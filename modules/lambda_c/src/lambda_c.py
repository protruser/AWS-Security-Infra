"""Lambda C: CloudWatch 지표 -> Security MySQL(service_metrics).

EventBridge 스케줄(5분)로 실행된다. 실제 쿼리 구성/응답 변환은 metrics.py(순수 로직)에 있고,
이 파일은 AWS 호출(CloudWatch 조회, DB 저장)만 담당한다.
"""
import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3
import metrics
from common import db

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, _context):
    instance_ids = json.loads(os.environ["INSTANCE_IDS"])
    alb_servers = {
        "k3s": (os.environ["SHOP_LB_ARN_SUFFIX"], os.environ["SHOP_TG_ARN_SUFFIX"]),
        "dashboard": (os.environ["ADMIN_LB_ARN_SUFFIX"], os.environ["ADMIN_TG_ARN_SUFFIX"]),
    }

    end = int(time.time()) // metrics.WINDOW * metrics.WINDOW
    start = end - metrics.WINDOW
    start_dt = datetime.fromtimestamp(start, timezone.utc)
    end_dt = datetime.fromtimestamp(end, timezone.utc)

    queries = metrics.build_queries(instance_ids, alb_servers)
    resp = boto3.client("cloudwatch").get_metric_data(
        MetricDataQueries=queries, StartTime=start_dt, EndTime=end_dt
    )
    results = {r["Id"]: r["Values"] for r in resp["MetricDataResults"]}

    rows = metrics.build_rows(instance_ids, alb_servers, results, start_dt, end_dt)
    stored = db.upsert_service_metrics(rows)
    logger.info("window=%s-%s stored=%d", start, end, stored)
    return {"window": [start, end], "stored": stored}
