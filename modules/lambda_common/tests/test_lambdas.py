"""AWS/DB 없이 돌아가는 변환·탐지 로직 테스트.

실행: python3 modules/lambda_common/tests/test_lambdas.py   (infra 폴더에서)
"""
import datetime as dt
import json
import os
import sys
import unittest

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

    def test_managed_rule_match_counts(self):
        e = waf.detect([rec("5.5.5.5", "/x", "", matched=["SQLi_BODY"])], "shop", 0, CFG)
        self.assertEqual(e[0]["title"].split(" (")[0], "SQL Injection 시도 탐지")
        self.assertEqual(e[0]["scenario_type"], "sqli")

    def test_admin_brute_force_gets_distinct_scenario_type(self):
        """관리자 로그인 무차별 대입은 일반 brute 와 다른 scenario_type(brute_admin)을 써야 한다."""
        many = [rec("6.6.6.6", "/login", method="POST") for _ in range(10)]
        self.assertEqual(waf.detect(many, "admin", 0, CFG)[0]["scenario_type"], "brute_admin")
        self.assertEqual(waf.detect(many, "shop", 0, CFG)[0]["scenario_type"], "brute")

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
    INSTANCE_IDS = {"k3s": "i-k3s", "dashboard": "i-dash", "shop_app": "i-app", "shop_db": "i-sdb", "security_db": "i-secdb"}
    ALB_SERVERS = {"k3s": ("lb-shop", "tg-shop"), "dashboard": ("lb-admin", "tg-admin")}
    START = dt.datetime(2026, 9, 22, 3, 0, tzinfo=dt.timezone.utc)
    END = dt.datetime(2026, 9, 22, 3, 5, tzinfo=dt.timezone.utc)

    def test_build_queries_counts_and_dimensions(self):
        qs = lambda_c_metrics.build_queries(self.INSTANCE_IDS, self.ALB_SERVERS)
        # EC2 지표 3개 x 5대 + ALB 지표 6개 x 2대(k3s, dashboard)
        self.assertEqual(len(qs), 3 * 5 + 6 * 2)
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
        results = {"dashboard_cpu": [5.0], "dashboard_status": [0.0], "dashboard_unhealthy": [1.0]}
        row = lambda_c_metrics.build_rows(["dashboard"], self.ALB_SERVERS, results, self.START, self.END)[0]
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
