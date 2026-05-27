"""Attach an inline Deny-* policy to contain the principal.

This is real containment — once applied, the user cannot perform
ANY action until the policy is removed. Reserved for cases where
a human analyst has explicitly approved containment via the
approval callback in the state machine.

Input:
  Full anomaly alert payload, plus approval decision
Output:
  {"contained": true/false, "policy_name": "..."}
"""

import json
import logging
import os

import boto3

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_iam = boto3.client("iam")

DENY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "QuarantineDenyAll",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }
    ]
}


def handler(event, context):
    principal_arn = event.get("principal_arn")
    if not principal_arn:
        raise ValueError("Missing principal_arn in input")

    if ":user/" not in principal_arn:
        logger.info("Principal is not an IAM user; cannot apply inline deny: %s", principal_arn)
        return {"contained": False, "reason": "not_an_iam_user"}

    user_name = principal_arn.split(":user/")[-1].split("/")[-1]
    policy_name = "SOAR-QuarantineDenyAll"

    try:
        _iam.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(DENY_POLICY),
        )
        logger.warning(
            "QUARANTINE APPLIED: user=%s policy=%s",
            user_name, policy_name,
        )
        return {
            "contained": True,
            "principal_arn": principal_arn,
            "user_name": user_name,
            "policy_name": policy_name,
        }
    except _iam.exceptions.NoSuchEntityException:
        logger.error("User %s no longer exists", user_name)
        return {"contained": False, "reason": "user_not_found"}