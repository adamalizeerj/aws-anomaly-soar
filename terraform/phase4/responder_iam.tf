data "aws_iam_policy_document" "responder_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "responder" {
  name               = "security-lab-responder"
  assume_role_policy = data.aws_iam_policy_document.responder_assume.json
}

data "aws_iam_policy_document" "responder" {
  statement {
    sid    = "WriteLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${var.region}:${var.account_id}:*"]
  }

  statement {
    sid    = "StartStateMachine"
    effect = "Allow"
    actions = [
      "states:StartExecution"
    ]
    # State machine doesn't exist yet (Phase 4C creates it). Reference by ARN.
    resources = [
      "arn:aws:states:${var.region}:${var.account_id}:stateMachine:${var.state_machine_name}"
    ]
  }

  statement {
    sid    = "PutAuditEvents"
    effect = "Allow"
    actions = [
      "events:PutEvents"
    ]
    resources = [aws_cloudwatch_event_bus.soar_audit.arn]
  }
}

resource "aws_iam_role_policy" "responder" {
  name   = "responder-permissions"
  role   = aws_iam_role.responder.id
  policy = data.aws_iam_policy_document.responder.json
}