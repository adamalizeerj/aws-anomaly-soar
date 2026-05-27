"""Handles approval/rejection from the API Gateway endpoint.

Receives a callback token and a decision (approve|reject), then
calls SendTaskSuccess or SendTaskFailure on Step Functions to
resume the paused state machine.
"""

import json
import logging
import os

import boto3

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_sfn = boto3.client("stepfunctions")


def handler(event, context):
    """Invoked by API Gateway with token+decision in the query string or body."""
    qs = event.get("queryStringParameters") or {}
    token = qs.get("token")
    decision = (qs.get("decision") or "").lower()

    if not token or decision not in {"approve", "reject"}:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Required: token and decision=approve|reject"}),
        }

    try:
        if decision == "approve":
            _sfn.send_task_success(
                taskToken=token,
                output=json.dumps({"approved": True, "decision": "approve"}),
            )
            message = "Approval recorded. Containment will proceed."
        else:
            _sfn.send_task_failure(
                taskToken=token,
                error="RejectedByOperator",
                cause="Human approver rejected containment.",
            )
            message = "Rejection recorded. State machine will not contain."

        logger.info("Decision recorded: %s", decision)
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/html"},
            "body": f"<html><body><h2>{message}</h2></body></html>",
        }
    except _sfn.exceptions.TaskTimedOut:
        return {
            "statusCode": 410,
            "body": json.dumps({"error": "Task token expired"}),
        }
    except _sfn.exceptions.TaskDoesNotExist:
        return {
            "statusCode": 404,
            "body": json.dumps({"error": "Task token not found"}),
        }