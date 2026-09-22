"""CloudWatch 지표 쿼리 구성과, 응답을 service_metrics 행으로 바꾸는 순수 로직. (Lambda C)

boto3/DB 를 쓰지 않아 AWS 없이 단위 테스트할 수 있다.
"""
WINDOW = 300

DISPLAY_NAMES = {
    "k3s": "K3s / nginx",
    "shop_app": "Shop App",
    "shop_db": "Shop MySQL",
}


def build_queries(instance_ids, alb_servers):
    """instance_ids: {server: instance_id}. alb_servers: {server: (lb_arn_suffix, tg_arn_suffix)}."""
    queries = []
    for server, iid in instance_ids.items():
        queries += [
            _ec2_query(f"{server}_cpu", iid, "CPUUtilization", "Average"),
            _ec2_query(f"{server}_mem", iid, "mem_used_percent", "Average"),
            _ec2_query(f"{server}_status", iid, "StatusCheckFailed", "Maximum"),
        ]
    for server, (lb, tg) in alb_servers.items():
        queries += [
            _alb_query(f"{server}_req", "RequestCount", "Sum", lb, tg),
            _alb_query(f"{server}_lat", "TargetResponseTime", "Average", lb, tg),
            _alb_query(f"{server}_5xx_t", "HTTPCode_Target_5XX_Count", "Sum", lb, tg),
            _alb_query(f"{server}_5xx_e", "HTTPCode_ELB_5XX_Count", "Sum", lb),
            _alb_query(f"{server}_healthy", "HealthyHostCount", "Average", lb, tg),
            _alb_query(f"{server}_unhealthy", "UnHealthyHostCount", "Average", lb, tg),
        ]
    return queries


def _ec2_query(qid, instance_id, metric, stat):
    return {
        "Id": qid,
        "MetricStat": {
            "Metric": {
                "Namespace": "AWS/EC2" if metric != "mem_used_percent" else "CWAgent",
                "MetricName": metric,
                "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
            },
            "Period": WINDOW,
            "Stat": stat,
        },
        "ReturnData": True,
    }


def _alb_query(qid, metric, stat, lb, tg=None):
    dims = [{"Name": "LoadBalancer", "Value": lb}]
    if tg:
        dims.append({"Name": "TargetGroup", "Value": tg})
    return {
        "Id": qid,
        "MetricStat": {
            "Metric": {"Namespace": "AWS/ApplicationELB", "MetricName": metric, "Dimensions": dims},
            "Period": WINDOW,
            "Stat": stat,
        },
        "ReturnData": True,
    }


def _value(results, qid):
    """해당 구간에 값이 없으면(서버가 막 켜졌거나 트래픽이 0이면) None."""
    v = results.get(qid) or []
    return v[0] if v else None


def _derive_status(cpu, status_failed, unhealthy):
    if status_failed is not None and status_failed >= 1:
        return "unhealthy"
    if unhealthy:
        return "degraded"
    if cpu is None:
        # 이 구간에 지표 자체가 없음 (부팅 직후 등). 서버가 죽었다는 뜻은 아니다.
        return "unknown"
    return "healthy"


def build_rows(instance_ids, alb_servers, results, window_start, window_end):
    """instance_ids: server 목록(순회용, dict나 list 모두 가능).
    results: {query_id: [값,...]} (CloudWatch get_metric_data 응답을 Id 기준으로 모은 것)."""
    rows = []
    for server in instance_ids:
        cpu = _value(results, f"{server}_cpu")
        mem = _value(results, f"{server}_mem")
        status_failed = _value(results, f"{server}_status")

        req = lat = err_rate = healthy = unhealthy = None
        if server in alb_servers:
            req_count = _value(results, f"{server}_req") or 0
            errors = (_value(results, f"{server}_5xx_t") or 0) + (_value(results, f"{server}_5xx_e") or 0)
            req = int(req_count)
            lat_sec = _value(results, f"{server}_lat")
            lat = round(lat_sec * 1000, 2) if lat_sec is not None else None
            err_rate = round(errors / req_count * 100, 2) if req_count else 0.0
            h = _value(results, f"{server}_healthy")
            u = _value(results, f"{server}_unhealthy")
            healthy = int(h) if h is not None else None
            unhealthy = int(u) if u is not None else None

        rows.append(
            {
                "server": server,
                "display_name": DISPLAY_NAMES[server],
                "status": _derive_status(cpu, status_failed, unhealthy),
                "cpu_percent": round(cpu, 2) if cpu is not None else None,
                "memory_percent": round(mem, 2) if mem is not None else None,
                "request_count": req,
                "avg_latency_ms": lat,
                "error_rate_percent": err_rate,
                "healthy_targets": healthy,
                "unhealthy_targets": unhealthy,
                "window_start": window_start.strftime("%Y-%m-%d %H:%M:%S"),
                "window_end": window_end.strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    return rows
