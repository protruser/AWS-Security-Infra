"""Lambda B: WAF 로그 분석 -> 이상 징후를 security_events 에 저장.

EventBridge 스케줄(5분)로 실행된다. 직전 5분 구간(정각 기준)의 WAF 로그를 읽어
SQLi / XSS / 디렉터리 탐색 / 로그인 무차별 대입을 골라낸다.
같은 구간은 같은 id 로 저장되므로 재시도해도 중복되지 않는다.
"""
import json
import logging
import os
import time

import boto3
import waf
from common import db

logger = logging.getLogger()
logger.setLevel(logging.INFO)

WINDOW = 300
CFG = {
    "login_paths": set(os.environ.get("LOGIN_PATHS", "/login,/api/login,/api/auth/login").split(",")),
    "brute_threshold": int(os.environ.get("BRUTE_THRESHOLD", "10")),
    "dir_distinct_uris": int(os.environ.get("DIR_DISTINCT_URIS", "20")),
    "critical_count": int(os.environ.get("CRITICAL_COUNT", "20")),
}
MAX_EVENTS = int(os.environ.get("MAX_LOG_EVENTS", "20000"))
GROUPS = {"shop": os.environ.get("SHOP_WAF_LOG_GROUP", ""), "admin": os.environ.get("ADMIN_WAF_LOG_GROUP", "")}

logs = boto3.client("logs")


def _read(group, start_ms, end_ms):
    records, token = [], None
    while len(records) < MAX_EVENTS:
        kwargs = {"logGroupName": group, "startTime": start_ms, "endTime": end_ms}
        if token:
            kwargs["nextToken"] = token
        resp = logs.filter_log_events(**kwargs)
        for e in resp.get("events", []):
            try:
                rec = json.loads(e["message"])
                rec["timestamp"] = rec.get("timestamp") or e["timestamp"]
                records.append(rec)
            except (ValueError, KeyError):
                continue
        token = resp.get("nextToken")
        if not token:
            break
    return records


def lambda_handler(event, _context):
    end = int(time.time()) // WINDOW * WINDOW
    start = end - WINDOW
    events = []
    for source, group in GROUPS.items():
        if not group:
            continue
        records = _read(group, start * 1000, end * 1000 - 1)
        found = waf.detect(records, source, start, CFG)
        logger.info("%s: records=%d detected=%d", source, len(records), len(found))
        events.extend(found)
    stored = db.upsert_events(events)
    return {"window": [start, end], "stored": stored}
