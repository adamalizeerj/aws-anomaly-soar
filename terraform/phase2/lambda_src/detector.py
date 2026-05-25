"""Behavioral anomaly detector.

For each CloudTrail event, computes the tuple
  (principal_arn, eventName, awsRegion, source_ip_asn)
and checks whether this tuple has been seen before for this principal.

A never-seen tuple is anomalous IF the principal's age in days is >= the
warm-up window (default 7). New principals generate no anomalies
during warm-up — this is what builds the baseline.
"""

import base64
import gzip
import ipaddress
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import boto3
import pyasn

SEEN_TUPLES_TABLE = os.environ["SEEN_TUPLES_TABLE"]
PRINCIPAL_AGES_TABLE = os.environ["PRINCIPAL_AGES_TABLE"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
WARMUP_DAYS = int(os.environ.get("WARMUP_DAYS", "7"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

TUPLE_TTL_SECONDS = 90 * 24 * 60 * 60

NOISE_EVENT_NAMES = {
    "AssumeRole",
    "GetCallerIdentity",
    "Decrypt",
    "GenerateDataKey",
    "DescribeInstanceInformation",
}

SKIPPED_PRINCIPAL_TYPES = {"AWSService", "AWSAccount"}

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_session = boto3.Session()
_ddb = _session.resource("dynamodb")
_seen_table = _ddb.Table(SEEN_TUPLES_TABLE)
_ages_table = _ddb.Table(PRINCIPAL_AGES_TABLE)
_sns = _session.client("sns")

_asndb = pyasn.pyasn(os.path.join(os.path.dirname(__file__), "ipasn_db.dat"))


def _ip_to_asn(ip_str: str) -> str:
    if not ip_str:
        return "UNKNOWN"
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"NON_IP:{ip_str[:40]}"

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return "PRIVATE"

    if isinstance(ip_obj, ipaddress.IPv6Address):
        return "IPV6"

    asn, _prefix = _asndb.lookup(ip_str)
    return str(asn) if asn else "UNKNOWN"


def _extract_principal_arn(event: dict) -> Optional[str]:
    user_identity = event.get("userIdentity", {})
    user_type = user_identity.get("type")

    if user_type in SKIPPED_PRINCIPAL_TYPES:
        return None

    if user_type == "AssumedRole":
        return (
            user_identity.get("sessionContext", {})
            .get("sessionIssuer", {})
            .get("arn")
        )
    return user_identity.get("arn")


def _principal_age_days(principal_arn: str, now_epoch: int) -> int:
    resp = _ages_table.get_item(Key={"principal_arn": principal_arn})
    item = resp.get("Item")

    if item is None:
        _ages_table.put_item(
            Item={
                "principal_arn": principal_arn,
                "first_seen_at": now_epoch,
            }
        )
        return 0

    first_seen = int(item["first_seen_at"])
    return (now_epoch - first_seen) // 86400


def _tuple_key(principal: str, event_name: str, region: str, asn: str) -> str:
    return f"{principal}#{event_name}#{region}#{asn}"


def _seen_before(key: str) -> bool:
    resp = _seen_table.get_item(Key={"tuple_key": key})
    return "Item" in resp


def _record_seen(key: str, now_epoch: int) -> None:
    _seen_table.put_item(
        Item={
            "tuple_key": key,
            "last_seen_at": now_epoch,
            "expires_at": now_epoch + TUPLE_TTL_SECONDS,
        }
    )


def _publish_anomaly(event: dict, asn: str, principal_age: int) -> None:
    alert = {
        "alert_type": "behavioral_anomaly",
        "detection_rule": "novel_principal_tuple",
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "principal_arn": _extract_principal_arn(event),
        "principal_age_days": principal_age,
        "event_name": event.get("eventName"),
        "event_source": event.get("eventSource"),
        "aws_region": event.get("awsRegion"),
        "source_ip": event.get("sourceIPAddress"),
        "source_ip_asn": asn,
        "user_agent": event.get("userAgent"),
        "event_time": event.get("eventTime"),
        "request_parameters": event.get("requestParameters"),
        "cloudtrail_event_id": event.get("eventID"),
    }
    _sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[SECURITY] Anomalous {event.get('eventName')} by {alert['principal_arn']}",
        Message=json.dumps(alert, indent=2, default=str),
    )
    logger.warning("Published anomaly: %s", json.dumps(alert, default=str))


def _process_cloudtrail_event(event: dict, now_epoch: int) -> None:
    event_name = event.get("eventName")
    if event_name in NOISE_EVENT_NAMES:
        return

    principal_arn = _extract_principal_arn(event)
    if not principal_arn:
        return

    region = event.get("awsRegion", "unknown")
    source_ip = event.get("sourceIPAddress", "")
    asn = _ip_to_asn(source_ip)

    key = _tuple_key(principal_arn, event_name, region, asn)
    age_days = _principal_age_days(principal_arn, now_epoch)

    if not _seen_before(key):
        if age_days >= WARMUP_DAYS:
            _publish_anomaly(event, asn, age_days)
        else:
            logger.info(
                "Suppressed (warmup): principal=%s age_days=%d tuple=%s",
                principal_arn, age_days, key,
            )
        _record_seen(key, now_epoch)
    else:
        _record_seen(key, now_epoch)


def handler(event, context):
    payload = event.get("awslogs", {}).get("data")
    if not payload:
        logger.warning("No awslogs payload")
        return {"status": "no-op"}

    decoded = gzip.decompress(base64.b64decode(payload))
    parsed = json.loads(decoded)

    now_epoch = int(time.time())
    processed = 0
    errors = 0

    for log_event in parsed.get("logEvents", []):
        try:
            ct_event = json.loads(log_event["message"])
            _process_cloudtrail_event(ct_event, now_epoch)
            processed += 1
        except Exception as exc:
            errors += 1
            logger.exception("Failed to process log event: %s", exc)

    logger.info("Processed %d events, %d errors", processed, errors)
    return {"status": "ok", "processed": processed, "errors": errors}