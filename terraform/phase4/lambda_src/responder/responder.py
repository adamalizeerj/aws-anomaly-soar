"""SOAR responder.

Triggered by SNS messages from the Phase 2 detector. For each anomaly:
  1. Validates the alert payload schema.
  2. Checks the principal against a break-glass exemption list. Exempt
     principals (root, admins, SOAR's own roles) are alerted and
     ticketed but NEVER auto-contained — preventing self-lockout.
  3. Starts a Step Functions execution for non-exempt principals.
  4. Emits an audit event to EventBridge.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone

import boto3

STATE_MACHINE_ARN = os.environ["STATE_MACHINE_ARN"]
AUDIT_BUS_NAME = os.environ["AUDIT_BUS_NAME"]
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Comma-separated substrings; if any appears in the principal ARN,
# the principal is exempt from automated containment.
EXEMPT_PRINCIPAL_PATTERNS = [
    p.strip()
    for p in os.environ.get(
        "EXEMPT_PRINCIPAL_PATTERNS",
        ":root,security-lab-admin,soar-,security-lab-activity,security-lab-detector,security-lab-responder",
    ).split(",")
    if p.strip()
]

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_sfn = boto3.client("stepfunctions")
_events = boto3.client("events")

EXECUTION_NAME_PATTERN = re.compile(r"[^A-Za-z0-9\-_]")


def _normalize_execution_name(raw: str) -> str:
    safe = EXECUTION_NAME_PATTERN.sub("-", raw)
    return safe[:80]


def _validate_alert(alert: dict) -> bool:
    required = {
        "principal_arn",
        "event_name",
        "aws_region",
        "source_ip",
        "source_ip_asn",
        "cloudtrail_event_id",
    }
    missing = required - set(alert.keys())
    if missing:
        logger.error("Alert missing required fields: %s", missing)
        return False
    return True


def _is_exempt(principal_arn: str) -> bool:
    return any(pat in principal_arn for pat in EXEMPT_PRINCIPAL_PATTERNS)


def _emit_audit(detail_type: str, detail: dict) -> None:
    try:
        _events.put_events(
            Entries=[
                {
                    "Source": "soar.responder",
                    "DetailType": detail_type,
                    "Detail": json.dumps(detail, default=str),
                    "EventBusName": AUDIT_BUS_NAME,
                }
            ]
        )
    except Exception:
        logger.exception("Failed to emit audit event")


def _start_playbook(alert: dict) -> str:
    event_id = alert.get("cloudtrail_event_id", "no-event-id")
    exec_name = _normalize_execution_name(f"anomaly-{event_id}")
    response = _sfn.start_execution(
        stateMachineArn=STATE_MACHINE_ARN,
        name=exec_name,
        input=json.dumps(alert, default=str),
    )
    return response["executionArn"]


def handler(event, context):
    records = event.get("Records", [])
    started = 0
    skipped = 0

    for record in records:
        try:
            sns_message = record["Sns"]["Message"]
            alert = json.loads(sns_message)
        except (KeyError, json.JSONDecodeError) as exc:
            logger.exception("Could not parse SNS record: %s", exc)
            skipped += 1
            continue

        if not _validate_alert(alert):
            skipped += 1
            _emit_audit(
                "alert.rejected",
                {"reason": "validation_failed", "alert": alert,
                 "at": datetime.now(timezone.utc).isoformat()},
            )
            continue

        principal = alert["principal_arn"]

        if _is_exempt(principal):
            skipped += 1
            logger.warning(
                "Principal %s is break-glass exempt; alerting but NOT containing.",
                principal,
            )
            _emit_audit(
                "playbook.skipped_exempt",
                {"principal_arn": principal,
                 "event_name": alert.get("event_name"),
                 "reason": "break_glass_exemption",
                 "at": datetime.now(timezone.utc).isoformat()},
            )
            continue

        try:
            execution_arn = _start_playbook(alert)
            started += 1
            logger.info("Started playbook: %s", execution_arn)
            _emit_audit(
                "playbook.started",
                {"execution_arn": execution_arn,
                 "principal_arn": principal,
                 "event_name": alert.get("event_name"),
                 "at": datetime.now(timezone.utc).isoformat()},
            )
        except _sfn.exceptions.ExecutionAlreadyExists:
            logger.info("Duplicate alert for event_id=%s",
                        alert.get("cloudtrail_event_id"))
            skipped += 1
        except Exception as exc:
            logger.exception("Failed to start playbook: %s", exc)
            skipped += 1
            _emit_audit(
                "playbook.start_failed",
                {"error": str(exc), "alert": alert,
                 "at": datetime.now(timezone.utc).isoformat()},
            )

    logger.info("Processed %d records: %d started, %d skipped",
                len(records), started, skipped)
    return {"started": started, "skipped": skipped}