"""Security MySQL 공통 접근 코드 (Lambda A / B / Remediation 이 함께 쓴다).

테이블 정의는 대시보드 백엔드의 backend/schema.sql 과 같아야 한다.
Lambda 가 먼저 실행돼도 동작하도록 첫 연결 때 CREATE TABLE IF NOT EXISTS 를 실행한다.
"""
import json
import os

import boto3
import pymysql

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS security_events (
        id                VARCHAR(255) PRIMARY KEY,
        service           VARCHAR(80) NOT NULL,
        severity          VARCHAR(20) NOT NULL,
        title             VARCHAR(255) NOT NULL,
        asset             VARCHAR(255) NULL,
        detected_at       DATETIME NOT NULL,
        status            VARCHAR(40) NOT NULL DEFAULT '검토 필요',
        recommendation    TEXT NULL,
        auto_remediation  BOOLEAN NOT NULL DEFAULT FALSE,
        highlight_assets  JSON NULL,
        attack_path       JSON NULL,
        attacker_ip       VARCHAR(45) NULL,
        request_url       TEXT NULL,
        rule_name         VARCHAR(255) NULL,
        blocked           BOOLEAN NULL,
        block_result      VARCHAR(20) NULL,
        logs              LONGTEXT NULL,
        created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                                          ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_security_events_detected_at (detected_at),
        INDEX idx_security_events_status (status),
        INDEX idx_security_events_severity (severity),
        INDEX idx_security_events_service (service)
    ) CHARACTER SET utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS remediation_history (
        id            BIGINT AUTO_INCREMENT PRIMARY KEY,
        event_id      VARCHAR(255) NOT NULL,
        action_type   VARCHAR(100) NULL,
        method        VARCHAR(20) NOT NULL DEFAULT '수동',
        approver      VARCHAR(100) NULL,
        status        VARCHAR(40) NULL,
        result        VARCHAR(100) NULL,
        result_detail TEXT NULL,
        requested_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        completed_at  DATETIME NULL,
        INDEX idx_remediation_event_id (event_id),
        INDEX idx_remediation_completed_at (completed_at),
        CONSTRAINT fk_remediation_event
          FOREIGN KEY (event_id) REFERENCES security_events(id)
          ON DELETE CASCADE
    ) CHARACTER SET utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS service_metrics (
        server           VARCHAR(40) PRIMARY KEY,
        display_name     VARCHAR(80) NOT NULL,
        status           VARCHAR(20) NOT NULL DEFAULT 'unknown',
        cpu_percent      DECIMAL(5,2) NULL,
        memory_percent   DECIMAL(5,2) NULL,
        request_count    INT NULL,
        avg_latency_ms   DECIMAL(8,2) NULL,
        error_rate_percent DECIMAL(5,2) NULL,
        healthy_targets  INT NULL,
        unhealthy_targets INT NULL,
        window_start     DATETIME NULL,
        window_end       DATETIME NULL,
        updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                                          ON UPDATE CURRENT_TIMESTAMP
    ) CHARACTER SET utf8mb4
    """,
]

UPSERT_EVENT = """
INSERT INTO security_events (
  id, service, severity, title, asset, detected_at, status, recommendation,
  auto_remediation, highlight_assets, attack_path, attacker_ip, request_url,
  rule_name, blocked, block_result, logs
) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON DUPLICATE KEY UPDATE
  severity=VALUES(severity), title=VALUES(title), asset=VALUES(asset),
  recommendation=VALUES(recommendation), auto_remediation=VALUES(auto_remediation),
  highlight_assets=VALUES(highlight_assets), attack_path=VALUES(attack_path),
  attacker_ip=VALUES(attacker_ip), request_url=VALUES(request_url),
  rule_name=VALUES(rule_name), logs=VALUES(logs),
  blocked=COALESCE(blocked, VALUES(blocked)),
  block_result=COALESCE(block_result, VALUES(block_result))
"""
# status 는 일부러 갱신하지 않는다. 승인/조치로 바뀐 상태를 다시 덮어쓰지 않기 위해서다.

_conn = None
_schema_ready = False


def _connect():
    secret = json.loads(
        boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["DB_SECRET_ARN"])[
            "SecretString"
        ]
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
        cursorclass=pymysql.cursors.DictCursor,
    )


def get_conn():
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
            for ddl in SCHEMA:
                cur.execute(ddl)
        _schema_ready = True
    return _conn


def upsert_events(events):
    """events: mapping/waf 모듈이 만든 dict 목록. id 가 같으면 갱신한다."""
    if not events:
        return 0
    rows = [
        (
            e["id"], e["service"], e["severity"], e["title"][:255], e.get("asset"),
            e["detected_at"], e.get("status", "검토 필요"), e.get("recommendation"),
            bool(e.get("auto_remediation")),
            json.dumps(e.get("highlight_assets") or []),
            json.dumps(e.get("attack_path") or []),
            e.get("attacker_ip"), e.get("request_url"), (e.get("rule_name") or "")[:255] or None,
            e.get("blocked"), e.get("block_result"),
            json.dumps(e.get("logs"), ensure_ascii=False, default=str)
            if not isinstance(e.get("logs"), str)
            else e.get("logs"),
        )
        for e in events
    ]
    with get_conn().cursor() as cur:
        cur.executemany(UPSERT_EVENT, rows)
    return len(rows)


UPSERT_METRIC = """
INSERT INTO service_metrics (
  server, display_name, status, cpu_percent, memory_percent, request_count,
  avg_latency_ms, error_rate_percent, healthy_targets, unhealthy_targets,
  window_start, window_end
) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON DUPLICATE KEY UPDATE
  display_name=VALUES(display_name), status=VALUES(status),
  cpu_percent=VALUES(cpu_percent), memory_percent=VALUES(memory_percent),
  request_count=VALUES(request_count), avg_latency_ms=VALUES(avg_latency_ms),
  error_rate_percent=VALUES(error_rate_percent),
  healthy_targets=VALUES(healthy_targets), unhealthy_targets=VALUES(unhealthy_targets),
  window_start=VALUES(window_start), window_end=VALUES(window_end)
"""


def upsert_service_metrics(rows):
    """rows: server(고정 키)당 최신 상태 1건. 표에는 서버 수만큼(5행)만 남는다(이력 아님)."""
    if not rows:
        return 0
    values = [
        (
            r["server"], r["display_name"], r.get("status", "unknown"),
            r.get("cpu_percent"), r.get("memory_percent"), r.get("request_count"),
            r.get("avg_latency_ms"), r.get("error_rate_percent"),
            r.get("healthy_targets"), r.get("unhealthy_targets"),
            r.get("window_start"), r.get("window_end"),
        )
        for r in rows
    ]
    with get_conn().cursor() as cur:
        cur.executemany(UPSERT_METRIC, values)
    return len(values)
