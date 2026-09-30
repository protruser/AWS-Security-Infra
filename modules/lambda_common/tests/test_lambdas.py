"""AWS/DB 없이 돌아가는 변환·탐지 로직 테스트.

실행: python3 modules/lambda_common/tests/test_lambdas.py   (infra 폴더에서)
"""
import datetime as dt
import json
import os
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path[:0] = [
    os.path.join(ROOT, "lambda_common"),
    os.path.join(ROOT, "lambda_b", "src"),
    os.path.join(ROOT, "lambda_c", "src"),
]

from common import mapping  # noqa: E402
import waf  # noqa: E402
import metrics as lambda_c_metrics  # noqa: E402

CFG = {"login_paths": {"/login"}, "brute_threshold": 10, "dir_distinct_uris": 20, "critical_count": 20}


def finding(product, types, rtype="AwsEc2Instance", label="HIGH", **extra):
    f = {"Id": f"arn:aws:x/{product}/{types}", "ProductName": product, "Types": [types], "GeneratorId": "",
         "Title": "t", "Severity": {"Label": label}, "UpdatedAt": "2026-09-21T03:04:05.123Z",
         "Resources": [{"Type": rtype, "Id": "arn:aws:ec2:r:a:instance/i-1"}]}
    f.update(extra)
    return f


GROUPS = ["AWS#AWSManagedRulesCommonRuleSet", "AWS#AWSManagedRulesSQLiRuleSet"]


def rec(ip, uri="/", args="", method="GET", action="ALLOW", matched=(), ts=1000):
    """WAF 로그 한 줄. 요청은 항상 두 규칙 그룹을 거치고, matched 에 준 규칙만 실제로 걸린 것으로 기록한다.

    SQLi_* 규칙은 SQLi 그룹에, 나머지는 Common 그룹에 걸린 것으로 둔다.
    """
    def group(gid, own):
        return {"ruleGroupId": gid, "terminatingRule": None,
                "nonTerminatingMatchingRules": [{"ruleId": m, "action": "COUNT"} for m in matched if own(m)]}
    return {"timestamp": ts, "action": action, "terminatingRuleId": "Default_Action",
            "httpRequest": {"clientIp": ip, "uri": uri, "args": args, "httpMethod": method},
            "ruleGroupList": [group(GROUPS[0], lambda m: not m.startswith("SQLi")),
                              group(GROUPS[1], lambda m: m.startswith("SQLi"))]}


class MappingTest(unittest.TestCase):
    def test_portscan_extracts_ip_and_path(self):
        f = finding("GuardDuty", "TTPs/Discovery/Recon:EC2-Portscan",
                    Action={"PortProbeAction": {"PortProbeDetails": [{"RemoteIpDetails": {"IpAddressV4": "203.0.113.9"}}]}})
        e = mapping.finding_to_event(f)
        self.assertEqual(e["attacker_ip"], "203.0.113.9")
        self.assertEqual(e["attack_path"], ["k3s"])
        self.assertEqual(e["scenario_type"], "port")
        self.assertTrue(e["auto_remediation"])
        self.assertEqual(e["status"], "승인 대기")

    def test_credential_finding_keeps_username(self):
        f = finding("GuardDuty", "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration", "AwsIamAccessKey",
                    Resources=[{"Type": "AwsIamAccessKey", "Id": "AKIA1",
                                "Details": {"AwsIamAccessKey": {"UserName": "ex-employee", "AccessKeyId": "AKIA1"}}}])
        e = mapping.finding_to_event(f)
        self.assertEqual(json.loads(e["logs"])["extracted"]["userName"], "ex-employee")
        self.assertTrue(e["auto_remediation"])
        self.assertIn("Access Key", e["recommendation"])

    def test_role_credential_finding_recommends_session_revoke(self):
        """역할·임시 자격증명은 비활성화할 Access Key 가 없다 → 수동 조치 + 세션 폐기 권고."""
        f = finding("GuardDuty", "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "AwsIamAccessKey",
                    Resources=[{"Type": "AwsIamAccessKey", "Id": "ASIA1",
                                "Details": {"AwsIamAccessKey": {"PrincipalId": "AROA1:i-1",
                                                                "PrincipalType": "AssumedRole"}}}])
        e = mapping.finding_to_event(f)
        self.assertEqual(e["scenario_type"], "cred")
        self.assertFalse(e["auto_remediation"])
        self.assertEqual(e["status"], "검토 필요")
        self.assertIn("세션 폐기", e["recommendation"])
        self.assertNotIn("Access Key 즉시 비활성화", e["recommendation"])

    def test_inspector_and_analyzer(self):
        self.assertEqual(mapping.finding_to_event(finding("Inspector", "x", "AwsEcrContainerImage"))["highlight_assets"][0], "ecr")
        self.assertIn("s3Logs", mapping.finding_to_event(finding("IAM Access Analyzer", "x", "AwsS3Bucket"))["highlight_assets"])

    def test_inspector_ecr_is_vuln_but_ec2_is_generic(self):
        """5번 시나리오(취약 컨테이너 이미지)는 ECR 이미지 취약점만 해당한다.
        EC2 패키지 취약점까지 vuln 으로 섞이면 화면 필터에서 시나리오 5로 잘못 집계된다."""
        ecr = mapping.finding_to_event(finding("Inspector", "x", "AwsEcrContainerImage"))
        ec2 = mapping.finding_to_event(finding("Inspector", "x", "AwsEc2Instance"))
        self.assertEqual(ecr["scenario_type"], "vuln")
        self.assertEqual(ec2["scenario_type"], "generic")

    def test_ecr_asset_shows_repo_and_tag_not_digest_hash(self):
        """ECR 리소스 Id는 항상 .../sha256:<해시>로 끝나서, 예전처럼 Id의 마지막
        경로만 쓰면 사람이 못 알아보는 해시만 남는다. Details에 저장소/태그가
        있으면 그걸 써야 한다."""
        f = finding("Inspector", "x", "AwsEcrContainerImage", Resources=[{
            "Type": "AwsEcrContainerImage",
            "Id": "arn:aws:ecr:ap-northeast-2:1:repository/wonny-sec-nginx/sha256:"
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Details": {"AwsEcrContainerImage": {
                "RepositoryName": "wonny-sec-nginx",
                "ImageTags": ["latest"],
                "ImageDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }},
        }])
        event = mapping.finding_to_event(f)
        self.assertEqual(event["asset"], "AwsEcrContainerImage wonny-sec-nginx:latest")
        self.assertNotIn("aaaaaaaa", event["asset"])

    def test_ecr_asset_falls_back_to_repo_name_without_any_tag(self):
        """태그가 없는 이미지(다이제스트로만 스캔된 경우)는 커밋 조회를 시도할 SHA
        자체가 없으니 저장소 이름만 보여준다 - 해시를 아예 노출하지 않는다."""
        f = finding("Inspector", "x", "AwsEcrContainerImage", Resources=[{
            "Type": "AwsEcrContainerImage",
            "Id": "arn:aws:ecr:ap-northeast-2:1:repository/wonny-sec-shop-app/sha256:"
                  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Details": {"AwsEcrContainerImage": {
                "RepositoryName": "wonny-sec-shop-app",
                "ImageDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            }},
        }])
        event = mapping.finding_to_event(f)
        self.assertEqual(event["asset"], "AwsEcrContainerImage wonny-sec-shop-app")
        self.assertNotIn("bbbbbbbb", event["asset"])

    def test_ecr_asset_shows_commit_subject_when_repo_and_sha_tag_known(self):
        """실제 저장소 이름 형식(wonny-sec/dashboard)과 git SHA 태그가 있으면
        GitHub에서 그 커밋의 제목을 가져와 보여준다 - 이게 이번에 추가한 핵심 동작."""
        f = finding("Inspector", "x", "AwsEcrContainerImage", Resources=[{
            "Type": "AwsEcrContainerImage",
            "Id": "arn:aws:ecr:ap-northeast-2:1:repository/wonny-sec/dashboard/sha256:"
                  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "Details": {"AwsEcrContainerImage": {
                "RepositoryName": "wonny-sec/dashboard",
                "ImageTags": ["7900353d726054f26b3156dda8901feb65fc1064"],
                "ImageDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            }},
        }])
        with patch.object(mapping, "_commit_subject", return_value="flood 시나리오 추가"):
            event = mapping.finding_to_event(f)
        self.assertEqual(event["asset"], "AwsEcrContainerImage wonny-sec/dashboard (flood 시나리오 추가)")

    def test_ecr_asset_falls_back_to_repo_name_when_commit_lookup_fails(self):
        """GitHub 조회가 실패해도(네트워크 문제, rate limit, 매핑에 없는 저장소 등)
        해시를 그대로 노출하지 않고 저장소 이름으로 안전하게 물러난다."""
        f = finding("Inspector", "x", "AwsEcrContainerImage", Resources=[{
            "Type": "AwsEcrContainerImage",
            "Id": "arn:aws:ecr:ap-northeast-2:1:repository/wonny-sec/dashboard/sha256:"
                  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "Details": {"AwsEcrContainerImage": {
                "RepositoryName": "wonny-sec/dashboard",
                "ImageTags": ["7900353d726054f26b3156dda8901feb65fc1064"],
            }},
        }])
        with patch.object(mapping, "_commit_subject", return_value=None):
            event = mapping.finding_to_event(f)
        self.assertEqual(event["asset"], "AwsEcrContainerImage wonny-sec/dashboard")
        self.assertNotIn("7900353d", event["asset"])

    def test_ecr_asset_keeps_short_named_tags_as_is(self):
        """'latest'처럼 원래 짧은 태그는 이미 사람이 읽을 수 있으니 자르지 않는다."""
        f = finding("Inspector", "x", "AwsEcrContainerImage", Resources=[{
            "Type": "AwsEcrContainerImage",
            "Id": "arn:aws:ecr:ap-northeast-2:1:repository/wonny-sec-nginx/sha256:"
                  "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "Details": {"AwsEcrContainerImage": {
                "RepositoryName": "wonny-sec-nginx",
                "ImageTags": ["v1.2.3"],
            }},
        }])
        event = mapping.finding_to_event(f)
        self.assertEqual(event["asset"], "AwsEcrContainerImage wonny-sec-nginx:v1.2.3")

    def test_seven_scenarios_filter_matches_project_list(self):
        """대시보드가 최종적으로 필터링할 7개 값과 우리가 실제로 만드는 값이 어긋나지 않는지 확인."""
        SEVEN = {"sqli", "dir", "brute", "cred", "vuln", "xss", "port"}
        port = mapping.finding_to_event(finding(
            "GuardDuty", "TTPs/Discovery/Recon:EC2-Portscan",
            Action={"PortProbeAction": {"PortProbeDetails": [{"RemoteIpDetails": {"IpAddressV4": "203.0.113.9"}}]}}))
        cred = mapping.finding_to_event(finding(
            "GuardDuty", "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"))
        vuln = mapping.finding_to_event(finding("Inspector", "x", "AwsEcrContainerImage"))
        self.assertTrue({port["scenario_type"], cred["scenario_type"], vuln["scenario_type"]} <= SEVEN)
        # s3/generic 은 7개 밖이라 화면 필터에서 일부러 빠져야 한다(오류 아님).
        s3 = mapping.finding_to_event(finding("IAM Access Analyzer", "x", "AwsS3Bucket"))
        self.assertNotIn(s3["scenario_type"], SEVEN)

    def test_skips_passed_and_archived(self):
        self.assertIsNone(mapping.finding_to_event(finding("Security Hub", "x", Compliance={"Status": "PASSED"})))
        self.assertIsNone(mapping.finding_to_event(finding("GuardDuty", "x", RecordState="ARCHIVED")))

    def test_id_is_stable_and_short(self):
        f = finding("GuardDuty", "x")
        self.assertEqual(mapping.finding_to_event(f)["id"], mapping.finding_to_event(f)["id"])
        self.assertLess(len(mapping.finding_to_event(f)["id"]), 255)

    def test_vuln_id_is_stable_across_image_rebuilds(self):
        """이미지를 새로 빌드(push)할 때마다 원본 finding Id는 이미지
        다이제스트를 포함해 달라진다 - 안 고친 채면 같은 CVE가 push할
        때마다 새 이벤트로 계속 쌓였다. 레포+CVE+패키지가 같으면 같은
        이벤트 id로 묶여야 한다."""
        def build(digest_suffix):
            return finding(
                "Inspector", "x", "AwsEcrContainerImage",
                Id=f"arn:aws:inspector2:r:1:finding/{digest_suffix}",
                Vulnerabilities=[{"Id": "CVE-2026-61081", "VulnerablePackages": [{"Name": "mariadb-libs"}]}],
                Resources=[{"Type": "AwsEcrContainerImage", "Id": "x", "Details": {"AwsEcrContainerImage": {
                    "RepositoryName": "wonny-sec/dashboard", "ImageDigest": f"sha256:{digest_suffix}"}}}],
            )
        first_build = mapping.finding_to_event(build("aaa111"))
        second_build = mapping.finding_to_event(build("bbb222"))
        self.assertEqual(first_build["scenario_type"], "vuln")
        self.assertEqual(first_build["id"], second_build["id"])

    def test_vuln_id_differs_for_different_cve(self):
        """다른 CVE는 당연히 서로 다른 이벤트로 남아야 한다."""
        def build(cve):
            return finding(
                "Inspector", "x", "AwsEcrContainerImage",
                Id=f"arn:aws:inspector2:r:1:finding/{cve}",
                Vulnerabilities=[{"Id": cve, "VulnerablePackages": [{"Name": "mariadb-libs"}]}],
                Resources=[{"Type": "AwsEcrContainerImage", "Id": "x", "Details": {"AwsEcrContainerImage": {
                    "RepositoryName": "wonny-sec/dashboard"}}}],
            )
        a = mapping.finding_to_event(build("CVE-2026-00001"))
        b = mapping.finding_to_event(build("CVE-2026-00002"))
        self.assertNotEqual(a["id"], b["id"])

    def test_cred_hints_catch_root_and_pentest_iam_usage(self):
        """Root 자격증명 사용, 침투테스트 도구의 IAM 자격증명 사용도 자격증명
        오남용이라 cred로 분류돼야 한다 - 실제 계정에서 관측된 GuardDuty
        finding type인데 예전 CRED_HINTS엔 없어서 generic으로 빠졌었다.
        타입 문자열은 실제 Security Hub finding에서 확인한 형식을 그대로
        쓴다(GuardDuty 자체 API가 주는 "Policy:IAMUser/RootCredentialUsage"와
        구분자가 다르다 - 슬래시가 아니라 하이픈, TTPs/ 접두사 붙음)."""
        root = mapping.finding_to_event(finding("GuardDuty", "TTPs/Policy:IAMUser-RootCredentialUsage"))
        pentest = mapping.finding_to_event(finding("GuardDuty", "TTPs/PenTest:IAMUser/KaliLinux"))
        self.assertEqual(root["scenario_type"], "cred")
        self.assertEqual(pentest["scenario_type"], "cred")


class WafTest(unittest.TestCase):
    def kinds(self, records, source="shop"):
        return {(e["title"].split(" (")[0], e["attacker_ip"], e["severity"]) for e in waf.detect(records, source, 0, CFG)}

    def test_sqli_xss_traversal(self):
        recs = [rec("1.1.1.1", "/api/products", "id=1' OR '1'='1"), rec("2.2.2.2", "/s", "q=<script>alert(1)</script>"),
                rec("3.3.3.3", "/download", "f=../../etc/passwd"), rec("4.4.4.4", "/", "q=hello")]
        got = {e["attacker_ip"] for e in waf.detect(recs, "shop", 0, CFG)}
        self.assertEqual(got, {"1.1.1.1", "2.2.2.2", "3.3.3.3"})

    def test_managed_rule_match_counts(self):
        e = waf.detect([rec("5.5.5.5", "/x", "", matched=["SQLi_BODY"])], "shop", 0, CFG)
        self.assertEqual(e[0]["title"].split(" (")[0], "SQL Injection 시도 탐지")
        self.assertEqual(e[0]["scenario_type"], "sqli")

    def test_admin_brute_force_scenario_type_stays_canonical(self):
        """scenario_type 은 화면 필터가 쓰는 7개 값 중 하나(brute)로 고정돼야 한다.
        관리자/쇼핑몰 구분(brute_admin)은 highlight_assets 조회에만 내부적으로 쓰이고
        DB에 저장되는 scenario_type 자체를 바꾸면 안 된다 (안 그러면 화면 필터에서 빠진다)."""
        many = [rec("6.6.6.6", "/login", method="POST") for _ in range(10)]
        admin_ev = waf.detect(many, "admin", 0, CFG)[0]
        shop_ev = waf.detect(many, "shop", 0, CFG)[0]
        self.assertEqual(admin_ev["scenario_type"], "brute")
        self.assertEqual(shop_ev["scenario_type"], "brute")
        # 맵 강조(자산 경로)는 여전히 관리자/쇼핑몰이 달라야 한다.
        self.assertIn("adminWAF", admin_ev["highlight_assets"])
        self.assertNotIn("adminWAF", shop_ev["highlight_assets"])

    def test_plain_request_is_not_an_attack(self):
        """규칙 그룹을 거쳐 갔을 뿐 걸리지 않은 평범한 요청은 탐지하면 안 된다. (실제 오탐 회귀 테스트)"""
        self.assertEqual(waf.detect([rec("16.5.0.236", "/")], "shop", 0, CFG), [])

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


class LambdaCTest(unittest.TestCase):
    # dashboard/security_db는 지표 수집 대상에서 제외됨 (k3s/shop_app/shop_db 3대만)
    INSTANCE_IDS = {"k3s": "i-k3s", "shop_app": "i-app", "shop_db": "i-sdb"}
    ALB_SERVERS = {"k3s": ("lb-shop", "tg-shop")}
    START = dt.datetime(2026, 9, 22, 3, 0, tzinfo=dt.timezone.utc)
    END = dt.datetime(2026, 9, 22, 3, 5, tzinfo=dt.timezone.utc)

    def test_build_queries_counts_and_dimensions(self):
        qs = lambda_c_metrics.build_queries(self.INSTANCE_IDS, self.ALB_SERVERS)
        # EC2 지표 3개 x 3대 + ALB 지표 6개 x 1대(k3s)
        self.assertEqual(len(qs), 3 * 3 + 6 * 1)
        ids = {q["Id"] for q in qs}
        self.assertIn("shop_db_cpu", ids)
        self.assertNotIn("shop_db_req", ids)  # ALB 뒤에 없는 서버는 요청 지표가 없다
        cpu_q = next(q for q in qs if q["Id"] == "k3s_cpu")
        self.assertEqual(cpu_q["MetricStat"]["Metric"]["Dimensions"], [{"Name": "InstanceId", "Value": "i-k3s"}])
        req_q = next(q for q in qs if q["Id"] == "k3s_req")
        self.assertEqual(
            req_q["MetricStat"]["Metric"]["Dimensions"],
            [{"Name": "LoadBalancer", "Value": "lb-shop"}, {"Name": "TargetGroup", "Value": "tg-shop"}],
        )

    def test_healthy_server_with_traffic(self):
        results = {
            "k3s_cpu": [42.5], "k3s_mem": [60.0], "k3s_status": [0.0],
            "k3s_req": [1200.0], "k3s_lat": [0.123], "k3s_5xx_t": [3.0], "k3s_5xx_e": [1.0],
            "k3s_healthy": [1.0], "k3s_unhealthy": [0.0],
        }
        row = lambda_c_metrics.build_rows(["k3s"], self.ALB_SERVERS, results, self.START, self.END)[0]
        self.assertEqual(row["status"], "healthy")
        self.assertEqual(row["cpu_percent"], 42.5)
        self.assertEqual(row["request_count"], 1200)
        self.assertEqual(row["avg_latency_ms"], 123.0)
        self.assertEqual(row["error_rate_percent"], round(4 / 1200 * 100, 2))

    def test_db_server_has_no_request_metrics(self):
        results = {"shop_db_cpu": [10.0], "shop_db_mem": [30.0], "shop_db_status": [0.0]}
        row = lambda_c_metrics.build_rows(["shop_db"], self.ALB_SERVERS, results, self.START, self.END)[0]
        self.assertEqual(row["status"], "healthy")
        self.assertIsNone(row["request_count"])
        self.assertIsNone(row["avg_latency_ms"])

    def test_status_check_failed_wins_over_everything(self):
        results = {"k3s_cpu": [5.0], "k3s_status": [1.0], "k3s_unhealthy": [0.0]}
        row = lambda_c_metrics.build_rows(["k3s"], self.ALB_SERVERS, results, self.START, self.END)[0]
        self.assertEqual(row["status"], "unhealthy")

    def test_unhealthy_target_without_status_check_is_degraded(self):
        results = {"k3s_cpu": [5.0], "k3s_status": [0.0], "k3s_unhealthy": [1.0]}
        row = lambda_c_metrics.build_rows(["k3s"], self.ALB_SERVERS, results, self.START, self.END)[0]
        self.assertEqual(row["status"], "degraded")

    def test_no_datapoints_is_unknown_not_unhealthy(self):
        """부팅 직후처럼 이 구간에 지표가 없으면 unknown 이지, 죽었다고 단정하지 않는다."""
        row = lambda_c_metrics.build_rows(["shop_app"], self.ALB_SERVERS, {}, self.START, self.END)[0]
        self.assertEqual(row["status"], "unknown")
        self.assertIsNone(row["cpu_percent"])

    def test_zero_requests_gives_zero_error_rate_not_division_error(self):
        results = {"k3s_cpu": [1.0], "k3s_req": [0.0]}
        row = lambda_c_metrics.build_rows(["k3s"], self.ALB_SERVERS, results, self.START, self.END)[0]
        self.assertEqual(row["request_count"], 0)
        self.assertEqual(row["error_rate_percent"], 0.0)


if __name__ == "__main__":
    unittest.main()
