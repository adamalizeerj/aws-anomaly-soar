"""SOAR responder.

Triggered by SNS messages from the Phase 2 detector. For each anomaly:

  1. Validates the alert payload schema.
  2. Decides whether to invoke the response playbook (Step Functions).
     Today: every well-formed alert triggers the playbook. Future:
     could filter by severity, principal age, event criticality.
  3. Starts a Step Functions execution, passing the alert as input.
  4. Emits an audit event to EventBridge.

Idempotency:
  Step Functions execution names include the CloudTrail event ID,
  so re-deliveries from SNS (which can happen) result in
  ExecutionAlreadyExists rather than duplicate playbook runs.
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

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_sfn = boto3.client("stepfunctions")
_events = boto3.client("events")

# Step Functions execution names must match this regex and be ≤80 chars
EXECUTION_NAME_PATTERN = re.compile(r"[^A-Za-z0-9\-_]")


def _normalize_execution_name(raw: str) -> str:
    """Convert an arbitrary string into a valid Step Functions execution name."""
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
    """SNS subscription handler."""
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
                {
                    "reason": "validation_failed",
                    "alert": alert,
                    "at": datetime.now(timezone.utc).isoformat(),
                },
            )
            continue

        try:
            execution_arn = _start_playbook(alert)
            started += 1
            logger.info("Started playbook: %s", execution_arn)
            _emit_audit(
                "playbook.started",
                {
                    "execution_arn": execution_arn,
                    "principal_arn": alert["principal_arn"],
                    "event_name": alert["event_name"],
                    "at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except _sfn.exceptions.ExecutionAlreadyExists:
            logger.info(
                "Duplicate alert; playbook already running for event_id=%s",
                alert.get("cloudtrail_event_id"),
            )
            skipped += 1
        except Exception as exc:
            logger.exception("Failed to start playbook: %s", exc)
            skipped += 1
            _emit_audit(
                "playbook.start_failed",
                {
                    "error": str(exc),
                    "alert": alert,
                    "at": datetime.now(timezone.utc).isoformat(),
                },
            )

    logger.info("Processed %d records: %d started, %d skipped", len(records), started, skipped)
    return {"started": started, "skipped": skipped}