"""Open a GitHub issue documenting the incident.

Input:
  Full anomaly alert + evidence_uri + approval status + containment status
Output:
  {"issue_url": "...", "issue_number": N}
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
import requests

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
GITHUB_SECRET_ID = os.environ["GITHUB_SECRET_ID"]

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_secrets = boto3.client("secretsmanager")


def _get_github_config() -> dict:
    secret = _secrets.get_secret_value(SecretId=GITHUB_SECRET_ID)["SecretString"]
    return json.loads(secret)


def _build_issue_body(event: dict) -> tuple:
    alert = event.get("alert", {})
    contained = event.get("contained", False)
    evidence_uri = event.get("evidence_uri", "(none)")
    event_count = event.get("event_count", 0)
    approval = event.get("approval_decision", "unknown")

    severity = "high" if alert.get("event_name") in {
        "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
        "PutBucketPolicy", "DeleteTrail", "StopLogging",
    } else "medium"

    title = f"[SEC-{severity.upper()}] {alert.get('event_name')} by {alert.get('principal_arn')}"

    body = f"""## Security Incident — Auto-filed by SOAR

**Severity:** `{severity}`
**Status:** {'🛑 Contained' if contained else '⚠️ Detected, not contained'}
**Human approval decision:** `{approval}`

### Detection details

| Field | Value |
|---|---|
| Principal | `{alert.get('principal_arn', 'unknown')}` |
| Principal age | {alert.get('principal_age_days', '?')} days |
| Event name | `{alert.get('event_name', 'unknown')}` |
| Event source | `{alert.get('event_source', 'unknown')}` |
| Region | `{alert.get('aws_region', 'unknown')}` |
| Source IP | `{alert.get('source_ip', 'unknown')}` |
| Source IP ASN | `{alert.get('source_ip_asn', 'unknown')}` |
| Detected at | `{alert.get('detected_at', 'unknown')}` |
| CloudTrail event ID | `{alert.get('cloudtrail_event_id', 'unknown')}` |

### Evidence

- S3 snapshot: `{evidence_uri}`
- Events captured: {event_count} from the last 24h

### Request parameters (from the trigger event)

```json
{json.dumps(alert.get('request_parameters'), indent=2)}
```

### Triage checklist

- [ ] Verify the anomaly is not a false positive by reviewing the evidence snapshot
- [ ] If genuine, check for related events from the same principal in the last 7 days
- [ ] Investigate whether other principals exhibited similar behavior
- [ ] Determine root cause: credential compromise, insider, misconfigured automation
- [ ] If contained: review the Deny policy attached and decide on next step (rotate keys, terminate access, etc.)
- [ ] Document remediation actions in this issue before closing

---

*Filed at {datetime.now(timezone.utc).isoformat()} by the AWS SOAR pipeline.*
"""

    labels = ["security", "soar-auto-filed", f"severity-{severity}"]
    if contained:
        labels.append("contained")

    return title, body, labels


def handler(event, context):
    config = _get_github_config()
    repo = config["repo"]
    token = config["token"]

    title, body, labels = _build_issue_body(event)

    response = requests.post(
        f"https://api.github.com/repos/{repo}/issues",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json={"title": title, "body": body, "labels": labels},
        timeout=10,
    )
    response.raise_for_status()

    issue = response.json()
    logger.info("GitHub issue created: %s", issue["html_url"])

    return {
        "issue_url": issue["html_url"],
        "issue_number": issue["number"],
    }