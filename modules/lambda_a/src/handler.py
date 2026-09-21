"""Lambda A: Security Hub finding -> Security MySQL.

EventBridge("Security Hub Findings - Imported") 이벤트를 받아 findings 테이블에 upsert 한다.
GuardDuty / Inspector / Access Analyzer / Security Hub 표준 점검 결과가 모두 이 경로로 들어온다.
"""
import json
import logging
import os

import boto3
import pymysql

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECRET_ARN = os.environ["DB_SECRET_ARN"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  finding_id     VARCHAR(512) NOT NULL,
  source         VARCHAR(64)  NOT NULL,
  product_name   VARCHAR(128) NOT NULL,
  title          VARCHAR(512) NOT NULL,
  description    TEXT,
  severity       VARCHAR(16)  NOT NULL,
  severity_score DECIMAL(5,2) NULL,
  resource_type  VARCHAR(128) NULL,
  resource_id    VARCHAR(512) NULL,
  finding_types  VARCHAR(512) NULL,
  workflow_status VARCHAR(32) NULL,
  record_state   VARCHAR(32)  NULL,
  aws_account_id VARCHAR(16)  NULL,
  region         VARCHAR(32)  NULL,
  created_at     DATETIME     NULL,
  updated_at     DATETIME     NULL,
  ingested_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  raw            JSON         NOT NULL,
  PRIMARY KEY (finding_id(255)),
  KEY idx_severity_updated (severity, updated_at),
  KEY idx_source_updated (source, updated_at)
) CHARACTER SET utf8mb4
"""

UPSERT = """
INSERT INTO findings (
  finding_id, source, product_name, title, description, severity, severity_score,
  resource_type, resource_id, finding_types, workflow_status, record_state,
  aws_account_id, region, created_at, updated_at, raw
) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON DUPLICATE KEY UPDATE
  title=VALUES(title), description=VALUES(description), severity=VALUES(severity),
  severity_score=VALUES(severity_score), resource_type=VALUES(resource_type),
  resource_id=VALUES(resource_id), finding_types=VALUES(finding_types),
  workflow_status=VALUES(workflow_status), record_state=VALUES(record_state),
  updated_at=VALUES(updated_at), raw=VALUES(raw)
"""

_conn = None
_schema_ready = False


def _connect():
    secret = json.loads(
        boto3.client("secretsmanager").get_secret_value(SecretId=SECRET_ARN)["SecretString"]
    )
    return pymysql.connect(
        host=secret["host"],
        port=int(secret["port"]),
        user=secret["username"],
        password=secret["password"],
        database=secret["database"],
        charset="utf8mb4",
        connect_timeout=5,
        autocommit=True,
    )


def _get_conn():
    """웜 스타트에서는 연결을 재사용하고, 끊겼으면 다시 연결한다."""
    global _conn, _schema_ready
    if _conn is None:
        _conn = _connect()
        _schema_ready = False
    else:
        try:
            _conn.ping(reconnect=False)
        except pymysql.MySQLError:
            _conn = _connect()
            _schema_ready = False
    if not _schema_ready:
        with _conn.cursor() as cur:
            cur.execute(SCHEMA)
        _schema_ready = True
    return _conn


def _ts(value):
    """ASFF ISO8601(2026-09-21T03:04:05.123Z) -> MySQL DATETIME(UTC)."""
    if not value:
        return None
    return value.replace("T", " ").rstrip("Z").split(".")[0]


def _row(f):
    resource = (f.get("Resources") or [{}])[0]
    severity = f.get("Severity") or {}
    return (
        f["Id"],
        f.get("ProductName") or f.get("ProductArn", "").split("/")[-1],
        f.get("ProductName") or "unknown",
        (f.get("Title") or "")[:512],
        f.get("Description"),
        severity.get("Label") or "INFORMATIONAL",
        severity.get("Normalized"),
        resource.get("Type"),
        (resource.get("Id") or "")[:512] or None,
        ",".join(f.get("Types") or [])[:512] or None,
        (f.get("Workflow") or {}).get("Status"),
        f.get("RecordState"),
        f.get("AwsAccountId"),
        f.get("Region"),
        _ts(f.get("CreatedAt")),
        _ts(f.get("UpdatedAt")),
        json.dumps(f, ensure_ascii=False),
    )


def lambda_handler(event, _context):
    findings = (event.get("detail") or {}).get("findings") or []
    if not findings:
        logger.info("no findings in event: %s", event.get("detail-type"))
        return {"stored": 0}

    rows = [_row(f) for f in findings]
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.executemany(UPSERT, rows)
    logger.info("stored %d finding(s)", len(rows))
    return {"stored": len(rows)}
