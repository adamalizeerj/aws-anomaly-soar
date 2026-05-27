"""Snapshot the principal's recent CloudTrail activity to S3.

Queries CloudTrail for all events by this principal in the last 24 hours
and writes them as a JSON file in the evidence bucket. The state machine
passes the S3 URI downstream so Slack and the GitHub issue can link to it.

Input:
  Full anomaly alert payload
Output:
  {"evidence_uri": "s3://bucket/key", "event_count": N}
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "24"))

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_cloudtrail = boto3.client("cloudtrail")
_s3 = boto3.client("s3")


def handler(event, context):
    principal_arn = event.get("principal_arn")
    if not principal_arn:
        raise ValueError("Missing principal_arn in input")

    user_name = principal_arn.split("/")[-1]
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=LOOKBACK_HOURS)

    events = []
    paginator = _cloudtrail.get_paginator("lookup_events")
    page_iter = paginator.paginate(
        LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": user_name}],
        StartTime=start,
        EndTime=end,
        MaxResults=50,
    )

    for page in page_iter:
        for ct_event in page.get("Events", []):
            events.append({
                "EventId": ct_event.get("EventId"),
                "EventName": ct_event.get("EventName"),
                "EventTime": ct_event.get("EventTime").isoformat() if ct_event.get("EventTime") else None,
                "EventSource": ct_event.get("EventSource"),
                "Username": ct_event.get("Username"),
                "AwsRegion": ct_event.get("AwsRegion"),
                "CloudTrailEvent": json.loads(ct_event["CloudTrailEvent"]) if ct_event.get("CloudTrailEvent") else None,
            })
        if len(events) >= 200:
            break

    timestamp = end.strftime("%Y%m%dT%H%M%SZ")
    key = f"snapshots/{user_name}/{timestamp}-{event.get('cloudtrail_event_id', 'unknown')}.json"

    payload = {
        "snapshot_metadata": {
            "principal_arn": principal_arn,
            "trigger_event_id": event.get("cloudtrail_event_id"),
            "trigger_event_name": event.get("event_name"),
            "lookback_hours": LOOKBACK_HOURS,
            "snapshot_taken_at": end.isoformat(),
            "event_count": len(events),
        },
        "trigger_alert": event,
        "recent_events": events,
    }

    _s3.put_object(
        Bucket=EVIDENCE_BUCKET,
        Key=key,
        Body=json.dumps(payload, indent=2, default=str).encode("utf-8"),
        ContentType="application/json",
    )

    evidence_uri = f"s3://{EVIDENCE_BUCKET}/{key}"
    logger.info("Wrote %d events to %s", len(events), evidence_uri)

    return {
        "evidence_uri": evidence_uri,
        "evidence_key": key,
        "event_count": len(events),
    }