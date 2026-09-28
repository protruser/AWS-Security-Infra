"""AI 패치 CI 스크립트 테스트. terraform-pr.yml 의 static job 에서 실행된다.

대시보드(protruser/AWS-security)의 backend/services/patch_authorization.py 가 만드는
승인 토큰 형식과, 대시보드 refresh_checks 가 읽는 manifest/plan 요약 형식이 계약이다.
형식을 바꾸면 양쪽을 같이 바꿔야 한다.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import terraform_patch_ci as ci  # noqa: E402
import verify_patch_authorization as infra_verify  # noqa: E402

PATCH_ID = "11111111-1111-1111-1111-111111111111"


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def dashboard_token(key, **overrides):
    """대시보드 patch_authorization.issue() 와 같은 형식."""
    claims = {"patch_id": PATCH_ID, "approval_hash": "h" * 64,
              "head_sha": "b" * 40, "base_sha": "a" * 40,
              "branch": f"ai-patch/{PATCH_ID}", "base_ref": "gyu",
              "pr_number": 7, "check_run_id": 50, "plan_sha256": "c" * 64,
              "plan_key": f"terraform-patches/{PATCH_ID}/{'b' * 40}/50-1.tfplan",
              "plan_version_id": "v1", "state": {"lineage": "l", "serial": 1},
              "exp": int(time.time()) + 900}
    claims.update(overrides)
    encoded = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    return f"{encoded}.{_b64(hmac.new(key, encoded.encode(), hashlib.sha256).digest())}"


class AuthorizationTest(unittest.TestCase):
    key = b"s" * 48

    def test_accepts_exact_dashboard_approval(self):
        claims = infra_verify.verify(dashboard_token(self.key), self.key)
        self.assertEqual((claims["base_ref"], claims["pr_number"]), ("gyu", 7))

    def test_rejects_tampered_expired_or_foreign_approval(self):
        token = dashboard_token(self.key)
        for bad, key in ((token + "x", self.key),
                         (token, b"t" * 48),
                         (dashboard_token(self.key, exp=int(time.time()) - 1), self.key),
                         (dashboard_token(self.key, base_ref="main"), self.key),
                         (dashboard_token(self.key, plan_key="other/x.tfplan"), self.key)):
            with self.subTest(token=bad[:20]), self.assertRaises(SystemExit):
                infra_verify.verify(bad, key)


class PlanSummaryTest(unittest.TestCase):
    def test_summary_omits_values_and_resource_keys(self):
        plan = {"resource_changes": [
            {"type": "aws_s3_bucket", "name": "x", "address": 'aws_s3_bucket.x["password-raw"]',
             "change": {"actions": ["update"], "before": {"password": "raw-secret"},
                        "after": {"password": "new-secret"}}},
            {"type": "aws_iam_role", "name": "r", "address": "aws_iam_role.r",
             "change": {"actions": ["delete", "create"]}},
            {"type": "aws_caller_identity", "name": "current", "address": "data.aws_caller_identity.current",
             "change": {"actions": ["read"], "after": {"account_id": "123456789012"}}}]}
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / "plan.json", Path(folder) / "summary.json"
            source.write_text(json.dumps(plan), encoding="utf-8")
            ci.plan_summary(source, target)
            output = target.read_text(encoding="utf-8")
        for secret in ("raw-secret", "password-raw", "123456789012"):
            self.assertNotIn(secret, output)
        data = json.loads(output)
        self.assertEqual(data["resources"]["update"], ["aws_s3_bucket"])
        self.assertEqual(data["resources"]["replace"], ["aws_iam_role"])
        self.assertEqual(data["labels"]["read"], ["aws_caller_identity.current"])


class ManifestTest(unittest.TestCase):
    def test_unrun_checks_stay_unrun(self):
        env = {"RUN_URL": "https://github.com/org/repo/actions/runs/5", "PATCH_ID": PATCH_ID,
               "HEAD_SHA": "a" * 40, "BASE_SHA": "b" * 40, "GITHUB_RUN_ID": "5",
               "CHECK_FMT": "success", "CHECK_VALIDATE": "skipped", "CHECK_PLAN": "failure",
               "CHECK_TFLINT": "failure", "CHECK_CHECKOV": "skipped"}
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, env, clear=True):
            target = Path(folder) / "manifest.json"
            ci.manifest(target)
            data = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual({k: v["status"] for k, v in data["results"].items()},
                         {"fmt": "PASS", "validate": "NOT_RUN", "plan": "FAIL",
                          "tflint": "FAIL", "checkov": "NOT_RUN"})
        self.assertEqual(data["run_id"], 5)


class CheckovNewTest(unittest.TestCase):
    def _write(self, folder, name, failures, as_list=False):
        report = {"check_type": "terraform", "results": {"failed_checks": [
            {"check_id": c, "file_path": f, "resource": r} for c, f, r in failures]}}
        path = Path(folder) / name
        path.write_text(json.dumps([report] if as_list else report), encoding="utf-8")
        return path

    def test_only_findings_added_by_patch_fail(self):
        existing = ("CKV_AWS_1", "/modules/a.tf", "aws_s3_bucket.x")
        added = ("CKV_AWS_2", "/modules/b.tf", "aws_kms_key.k")
        with tempfile.TemporaryDirectory() as folder:
            base = self._write(folder, "base.json", [existing])
            head = self._write(folder, "head.json", [existing, added], as_list=True)
            with self.assertRaises(SystemExit):
                ci.checkov_new(base, head)
            ci.checkov_new(head, base)  # 패치가 지적을 없앤 경우는 통과

    def test_clean_report_without_failed_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "clean.json"
            path.write_text(json.dumps({"check_type": "terraform", "summary": {"failed": 0}}), encoding="utf-8")
            ci.checkov_new(path, path)


class WorkflowTest(unittest.TestCase):
    root = Path(__file__).resolve().parents[1] / ".github" / "workflows"

    def test_validation_never_applies_and_deploy_verifies_first(self):
        plan = (self.root / "terraform-patch.yml").read_text(encoding="utf-8")
        deploy = (self.root / "terraform-patch-deploy.yml").read_text(encoding="utf-8")
        self.assertNotIn("terraform apply", plan)
        self.assertIn("environment: terraform-production", deploy)
        first = deploy.index("Verify server approval before loading patch code or AWS identity")
        self.assertLess(first, deploy.index("Check out exact approved patch commit"))
        self.assertLess(first, deploy.index("role-arn: ${{ vars.TF_APPLY_ROLE_ARN }}"))
        self.assertLess(deploy.index("Verify immutable plan and Terraform state"), deploy.index("terraform apply"))
        self.assertIn('"$MERGE_SHA"', deploy[deploy.index("name: Reconfirm state and apply exact approved saved plan"):])


if __name__ == "__main__":
    unittest.main()
