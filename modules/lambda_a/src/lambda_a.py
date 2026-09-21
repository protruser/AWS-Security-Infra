"""Lambda A: Security Hub finding -> security_events.

EventBridge("Security Hub Findings - Imported") 이벤트를 받아 저장한다.
GuardDuty / Inspector / Access Analyzer / Security Hub 표준 점검 결과가 이 경로로 들어온다.
"""
import logging

from common import db, mapping

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, _context):
    findings = (event.get("detail") or {}).get("findings") or []
    events = [e for e in (mapping.finding_to_event(f) for f in findings) if e]
    stored = db.upsert_events(events)
    logger.info("findings=%d stored=%d", len(findings), stored)
    return {"received": len(findings), "stored": stored}
