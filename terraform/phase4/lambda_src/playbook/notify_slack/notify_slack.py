"""Post a formatted alert to Slack via incoming webhook.

Two modes:
  1. approval_request=true: ask for analyst approval, include
     Approve/Reject link buttons that hit API Gateway.
  2. otherwise: final notification with containment status.
"""

import json
import logging
import os
from urllib.parse import urlencode

import boto3
import requests

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
SLACK_SECRET_ID = os.environ["SLACK_SECRET_ID"]
APPROVAL_API_BASE = os.environ.get("APPROVAL_API_BASE", "")

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_secrets = boto3.client("secretsmanager")


def _get_webhook_url() -> str:
    return _secrets.get_secret_value(SecretId=SLACK_SECRET_ID)["SecretString"]


def _approval_link(token: str, decision: str) -> str:
    qs = urlencode({"token": token, "decision": decision})
    return f"{APPROVAL_API_BASE}/approval?{qs}"


def _format_approval_request(event: dict) -> dict:
    alert = event.get("alert", {})
    token = event.get("token", "")
    approve_url = _approval_link(token, "approve")
    reject_url = _approval_link(token, "reject")

    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 Approval required: containment action"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "A behavioral anomaly was detected. "
                        "Approving will attach a `Deny *` policy to the principal."
                    ),
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Principal:*\n`{alert.get('principal_arn', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Action:*\n`{alert.get('event_name', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Region:*\n`{alert.get('aws_region', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Source ASN:*\n`{alert.get('source_ip_asn', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n`{alert.get('source_ip', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Principal age:*\n`{alert.get('principal_age_days', '?')} days`"},
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve containment"},
                        "url": approve_url,
                        "style": "danger",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Reject (no containment)"},
                        "url": reject_url,
                    },
                ],
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Detected at {alert.get('detected_at', 'unknown')} | Event ID: `{alert.get('cloudtrail_event_id', 'unknown')}`"}
                ],
            },
        ]
    }


def _format_final(event: dict) -> dict:
    alert = event.get("alert", {})
    contained = event.get("contained", False)
    evidence_uri = event.get("evidence_uri", "(none)")
    event_count = event.get("event_count", 0)

    status_emoji = "🛑" if contained else "⚠️"
    status_text = "CONTAINED (Deny policy applied)" if contained else "DETECTED (not contained — analyst rejected or timed out)"

    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{status_emoji} Security anomaly {status_text}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Principal:*\n`{alert.get('principal_arn', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Action:*\n`{alert.get('event_name', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Region:*\n`{alert.get('aws_region', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Source ASN:*\n`{alert.get('source_ip_asn', 'unknown')}`"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Evidence snapshot:* `{evidence_uri}` ({event_count} CloudTrail events from last 24h)",
                },
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Detected at {alert.get('detected_at', 'unknown')} | Event ID: `{alert.get('cloudtrail_event_id', 'unknown')}`"}
                ],
            },
        ]
    }


def handler(event, context):
    webhook = _get_webhook_url()

    if event.get("approval_request"):
        message = _format_approval_request(event)
    else:
        message = _format_final(event)

    logger.info("Posting to Slack (approval_request=%s): %s",
                bool(event.get("approval_request")), json.dumps(message)[:1500])

    response = requests.post(webhook, json=message, timeout=10)
    response.raise_for_status()

    logger.info("Slack notification sent: status=%s", response.status_code)
    return {"notified": True, "status_code": response.status_code}