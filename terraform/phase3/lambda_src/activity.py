"""Generates realistic baseline traffic for the three test users.

Every invocation:
  1. Picks a random subset of test users (1-3)
  2. For each picked user, fetches their access key from Secrets Manager
  3. Builds a boto3 session as that user
  4. Makes 3-8 randomized read-only API calls

The events appear in CloudTrail under each test user's principal ARN,
which is what the detector baselines against.
"""

import json
import logging
import os
import random
from typing import List

import boto3

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
SECRET_PREFIX = os.environ["TEST_USER_SECRET_PREFIX"]
TEST_USER_NAMES = os.environ["TEST_USER_NAMES"].split(",")

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_secrets = boto3.client("secretsmanager")

# Each "activity" is a function that takes a boto3 session and makes
# 1 API call. Keep them simple, read-only, and varied.
def _act_list_buckets(session):
    s3 = session.client("s3")
    s3.list_buckets()

def _act_describe_instances(session):
    ec2 = session.client("ec2")
    ec2.describe_instances()

def _act_describe_volumes(session):
    ec2 = session.client("ec2")
    ec2.describe_volumes()

def _act_describe_security_groups(session):
    ec2 = session.client("ec2")
    ec2.describe_security_groups()

def _act_describe_vpcs(session):
    ec2 = session.client("ec2")
    ec2.describe_vpcs()

def _act_list_users(session):
    iam = session.client("iam")
    iam.list_users()

def _act_get_user(session):
    iam = session.client("iam")
    iam.get_user()

def _act_list_access_keys(session):
    iam = session.client("iam")
    iam.list_access_keys()

def _act_describe_alarms(session):
    cw = session.client("cloudwatch")
    cw.describe_alarms()

def _act_describe_log_groups(session):
    logs = session.client("logs")
    logs.describe_log_groups()

ACTIVITIES = [
    _act_list_buckets,
    _act_describe_instances,
    _act_describe_volumes,
    _act_describe_security_groups,
    _act_describe_vpcs,
    _act_list_users,
    _act_get_user,
    _act_list_access_keys,
    _act_describe_alarms,
    _act_describe_log_groups,
]


def _session_for_user(user_name: str) -> boto3.Session:
    secret_arn_or_name = f"{SECRET_PREFIX}{user_name}"
    resp = _secrets.get_secret_value(SecretId=secret_arn_or_name)
    creds = json.loads(resp["SecretString"])
    return boto3.Session(
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        region_name="us-east-1",
    )


def _generate_activity_for_user(user_name: str) -> int:
    session = _session_for_user(user_name)
    n_calls = random.randint(3, 8)
    chosen = random.sample(ACTIVITIES, n_calls)
    successes = 0
    for activity in chosen:
        try:
            activity(session)
            successes += 1
        except Exception as exc:
            logger.warning(
                "Activity %s for user %s failed: %s",
                activity.__name__, user_name, exc,
            )
    logger.info("User %s: %d/%d activities succeeded", user_name, successes, n_calls)
    return successes


def handler(event, context):
    # Pick a random subset of users to be active this run
    n_users = random.randint(1, len(TEST_USER_NAMES))
    picked = random.sample(TEST_USER_NAMES, n_users)
    logger.info("Generating activity for users: %s", picked)

    total = 0
    for user in picked:
        total += _generate_activity_for_user(user)

    return {"status": "ok", "users_active": len(picked), "total_calls": total}