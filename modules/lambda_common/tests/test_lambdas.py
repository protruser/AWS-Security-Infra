"""AWS/DB 없이 돌아가는 변환·탐지 로직 테스트.

실행: python3 modules/lambda_common/tests/test_lambdas.py   (infra 폴더에서)
"""
import json
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path[:0] = [os.path.join(ROOT, "lambda_common"), os.path.join(ROOT, "lambda_b", "src")]

from common import mapping  # noqa: E402
import waf  # noqa: E402

CFG = {"login_paths": {"/login"}, "brute_threshold": 10, "dir_distinct_uris": 20, "critical_count": 20}


def finding(product, types, rtype="AwsEc2Instance", label="HIGH", **extra):
    f = {"Id": f"arn:aws:x/{product}/{types}", "ProductName": product, "Types": [types], "GeneratorId": "",
         "Title": "t", "Severity": {"Label": label}, "UpdatedAt": "2026-09-21T03:04:05.123Z",
         "Resources": [{"Type": rtype, "Id": "arn:aws:ec2:r:a:instance/i-1"}]}
    f.update(extra)
    return f


def rec(ip, uri="/", args="", method="GET", action="ALLOW", rules=(), ts=1000):
    return {"timestamp": ts, "action": action,
            "httpRequest": {"clientIp": ip, "uri": uri, "args": args, "httpMethod": method},
            "ruleGroupList": [{"ruleGroupId": r, "terminatingRule": None, "nonTerminatingMatchingRules": []} for r in rules]}


class MappingTest(unittest.TestCase):
    def test_portscan_extracts_ip_and_path(self):
        f = finding("GuardDuty", "TTPs/Discovery/Recon:EC2-Portscan",
                    Action={"PortProbeAction": {"PortProbeDetails": [{"RemoteIpDetails": {"IpAddressV4": "203.0.113.9"}}]}})
        e = mapping.finding_to_event(f)
        self.assertEqual(e["attacker_ip"], "203.0.113.9")
        self.assertEqual(e["attack_path"], ["k3s"])
        self.assertTrue(e["auto_remediation"])
        self.assertEqual(e["status"], "승인 대기")

    def test_credential_finding_keeps_username(self):
        f = finding("GuardDuty", "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration", "AwsIamAccessKey",
                    Resources=[{"Type": "AwsIamAccessKey", "Id": "AKIA1",
                                "Details": {"AwsIamAccessKey": {"UserName": "ex-employee", "AccessKeyId": "AKIA1"}}}])
        e = mapping.finding_to_event(f)
        self.assertEqual(json.loads(e["logs"])["extracted"]["userName"], "ex-employee")
        self.assertTrue(e["auto_remediation"])

    def test_inspector_and_analyzer(self):
        self.assertEqual(mapping.finding_to_event(finding("Inspector", "x", "AwsEcrContainerImage"))["highlight_assets"][0], "ecr")
        self.assertIn("s3Logs", mapping.finding_to_event(finding("IAM Access Analyzer", "x", "AwsS3Bucket"))["highlight_assets"])

    def test_skips_passed_and_archived(self):
        self.assertIsNone(mapping.finding_to_event(finding("Security Hub", "x", Compliance={"Status": "PASSED"})))
        self.assertIsNone(mapping.finding_to_event(finding("GuardDuty", "x", RecordState="ARCHIVED")))

    def test_id_is_stable_and_short(self):
        f = finding("GuardDuty", "x")
        self.assertEqual(mapping.finding_to_event(f)["id"], mapping.finding_to_event(f)["id"])
        self.assertLess(len(mapping.finding_to_event(f)["id"]), 255)


class WafTest(unittest.TestCase):
    def kinds(self, records, source="shop"):
        return {(e["title"].split(" (")[0], e["attacker_ip"], e["severity"]) for e in waf.detect(records, source, 0, CFG)}

    def test_sqli_xss_traversal(self):
        recs = [rec("1.1.1.1", "/api/products", "id=1' OR '1'='1"), rec("2.2.2.2", "/s", "q=<script>alert(1)</script>"),
                rec("3.3.3.3", "/download", "f=../../etc/passwd"), rec("4.4.4.4", "/", "q=hello")]
        got = {e["attacker_ip"] for e in waf.detect(recs, "shop", 0, CFG)}
        self.assertEqual(got, {"1.1.1.1", "2.2.2.2", "3.3.3.3"})

    def test_managed_rule_names_count(self):
        e = waf.detect([rec("5.5.5.5", "/x", "", rules=["AWSManagedRulesSQLiRuleSet"])], "shop", 0, CFG)
        self.assertEqual(e[0]["title"].split(" (")[0], "SQL Injection 시도 탐지")

    def test_brute_force_needs_threshold(self):
        few = [rec("6.6.6.6", "/login", method="POST") for _ in range(9)]
        many = [rec("6.6.6.6", "/login", method="POST") for _ in range(10)]
        self.assertEqual(waf.detect(few, "shop", 0, CFG), [])
        e = waf.detect(many, "admin", 0, CFG)[0]
        self.assertEqual(e["highlight_assets"][2], "adminWAF")

    def test_directory_scan_by_distinct_paths(self):
        e = waf.detect([rec("7.7.7.7", f"/p{i}") for i in range(20)], "shop", 0, CFG)
        self.assertEqual(len(e), 1)
        self.assertIn("디렉터리", e[0]["title"])

    def test_block_status(self):
        blocked = waf.detect([rec("8.8.8.8", "/", "id=1' or '1'='1", action="BLOCK")], "shop", 0, CFG)[0]
        self.assertEqual((blocked["status"], blocked["block_result"], blocked["auto_remediation"]), ("자동 완료", "성공", False))
        allowed = waf.detect([rec("8.8.8.8", "/", "id=1' or '1'='1")], "shop", 0, CFG)[0]
        self.assertEqual((allowed["status"], allowed["block_result"]), ("승인 대기", "실패"))

    def test_same_window_same_id(self):
        r = [rec("9.9.9.9", "/", "id=1' or '1'='1")]
        self.assertEqual(waf.detect(r, "shop", 300, CFG)[0]["id"], waf.detect(r, "shop", 300, CFG)[0]["id"])
        self.assertNotEqual(waf.detect(r, "shop", 300, CFG)[0]["id"], waf.detect(r, "shop", 600, CFG)[0]["id"])


if __name__ == "__main__":
    unittest.main()
