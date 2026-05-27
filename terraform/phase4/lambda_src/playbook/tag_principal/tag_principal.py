"""Tag the offending IAM principal with quarantine=true.

This is an audit marker, NOT containment. Tags are passive metadata
visible in IAM, Config, and CloudTrail. They make it obvious to other
operators that this principal is under investigation.

Containment happens in the apply_deny step, after human approval.

Input (from state machine):
  Full anomaly alert payload
Output:
  {"tagged": true/false, "principal_arn": "..."}
"""

import json
import logging
import os

import boto3

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_iam = boto3.client("iam")


def handler(event, context):
    principal_arn = event.get("principal_arn")
    if not principal_arn:
        raise ValueError("Missing principal_arn in input")

    # Parse the ARN: arn:aws:iam::ACCT:user/PATH/USERNAME
    # We only tag IAMUser principals. Roles use TagRole, a different API.
    if ":user/" not in principal_arn:
        logger.info("Principal is not an IAM user; skipping tagging: %s", principal_arn)
        return {"tagged": False, "reason": "not_an_iam_user", "principal_arn": principal_arn}

    user_name = principal_arn.split(":user/")[-1].split("/")[-1]

    try:
        _iam.tag_user(
            UserName=user_name,
            Tags=[
                {"Key": "quarantine", "Value": "true"},
                {"Key": "quarantine_event_id", "Value": event.get("cloudtrail_event_id", "unknown")},
                {"Key": "quarantine_detected_at", "Value": event.get("detected_at", "unknown")},
            ],
        )
        logger.info("Tagged user %s with quarantine=true", user_name)
        return {"tagged": True, "principal_arn": principal_arn, "user_name": user_name}
    except _iam.exceptions.NoSuchEntityException:
        logger.warning("User %s no longer exists; cannot tag", user_name)
        return {"tagged": False, "reason": "user_not_found", "principal_arn": principal_arn}