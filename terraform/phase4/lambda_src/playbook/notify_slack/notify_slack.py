"""Post a formatted alert to Slack via incoming webhook.

Input:
  Full anomaly alert + evidence_uri + approval status
Output:
  {"notified": true/false, "channel": "..."}
"""

import json
import logging
import os

import boto3
import requests

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
SLACK_SECRET_ID = os.environ["SLACK_SECRET_ID"]

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_secrets = boto3.client("secretsmanager")


def _get_webhook_url() -> str:
    return _secrets.get_secret_value(SecretId=SLACK_SECRET_ID)["SecretString"]


def _format_message(event: dict) -> dict:
    alert = event.get("alert", {})
    contained = event.get("contained", False)
    evidence_uri = event.get("evidence_uri", "(none)")
    event_count = event.get("event_count", 0)

    status_emoji = "🛑" if contained else "⚠️"
    status_text = "CONTAINED (Deny policy applied)" if contained else "DETECTED (not contained)"

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
                    {"type": "mrkdwn", "text": f"*Source IP:*\n`{alert.get('source_ip', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Principal age:*\n`{alert.get('principal_age_days', '?')} days`"},
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
    message = _format_message(event)

    response = requests.post(webhook, json=message, timeout=10)
    response.raise_for_status()

    logger.info("Slack notification sent: status=%s", response.status_code)
    return {"notified": True, "status_code": response.status_code}