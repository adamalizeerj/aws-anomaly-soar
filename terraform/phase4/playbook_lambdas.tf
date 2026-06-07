# ----- Common assume-role policy doc -----
data "aws_iam_policy_document" "playbook_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ----- tag_principal -----
data "archive_file" "tag_principal" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/playbook/tag_principal"
  output_path = "${path.module}/build/tag_principal.zip"
}

resource "aws_iam_role" "tag_principal" {
  name               = "soar-tag-principal"
  assume_role_policy = data.aws_iam_policy_document.playbook_assume.json
}

resource "aws_iam_role_policy" "tag_principal" {
  role = aws_iam_role.tag_principal.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:TagUser"]
        Resource = "arn:aws:iam::${var.account_id}:user/*"
      }
    ]
  })
}

resource "aws_lambda_function" "tag_principal" {
  function_name    = "soar-tag-principal"
  role             = aws_iam_role.tag_principal.arn
  handler          = "tag_principal.handler"
  runtime          = "python3.11"
  architectures    = ["arm64"]
  timeout          = 30
  filename         = data.archive_file.tag_principal.output_path
  source_code_hash = data.archive_file.tag_principal.output_base64sha256
  depends_on       = [aws_iam_role_policy.tag_principal]
}

# ----- apply_deny -----
data "archive_file" "apply_deny" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/playbook/apply_deny"
  output_path = "${path.module}/build/apply_deny.zip"
}

resource "aws_iam_role" "apply_deny" {
  name               = "soar-apply-deny"
  assume_role_policy = data.aws_iam_policy_document.playbook_assume.json
}

resource "aws_iam_role_policy" "apply_deny" {
  role = aws_iam_role.apply_deny.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PutUserPolicy"]
        Resource = "arn:aws:iam::${var.account_id}:user/*"
      }
    ]
  })
}

resource "aws_lambda_function" "apply_deny" {
  function_name    = "soar-apply-deny"
  role             = aws_iam_role.apply_deny.arn
  handler          = "apply_deny.handler"
  runtime          = "python3.11"
  architectures    = ["arm64"]
  timeout          = 30
  filename         = data.archive_file.apply_deny.output_path
  source_code_hash = data.archive_file.apply_deny.output_base64sha256
  depends_on       = [aws_iam_role_policy.apply_deny]
}

# ----- snapshot_evidence -----
data "archive_file" "snapshot_evidence" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/playbook/snapshot_evidence"
  output_path = "${path.module}/build/snapshot_evidence.zip"
}

resource "aws_iam_role" "snapshot_evidence" {
  name               = "soar-snapshot-evidence"
  assume_role_policy = data.aws_iam_policy_document.playbook_assume.json
}

resource "aws_iam_role_policy" "snapshot_evidence" {
  role = aws_iam_role.snapshot_evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.evidence.arn}/*"
      }
    ]
  })
}

resource "aws_lambda_function" "snapshot_evidence" {
  function_name    = "soar-snapshot-evidence"
  role             = aws_iam_role.snapshot_evidence.arn
  handler          = "snapshot_evidence.handler"
  runtime          = "python3.11"
  architectures    = ["arm64"]
  timeout          = 60
  memory_size      = 256
  filename         = data.archive_file.snapshot_evidence.output_path
  source_code_hash = data.archive_file.snapshot_evidence.output_base64sha256

  environment {
    variables = {
      EVIDENCE_BUCKET = aws_s3_bucket.evidence.id
      LOOKBACK_HOURS  = "24"
    }
  }

  depends_on = [aws_iam_role_policy.snapshot_evidence]
}

# ----- notify_slack -----
data "archive_file" "notify_slack" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/playbook/notify_slack"
  output_path = "${path.module}/build/notify_slack.zip"
}

resource "aws_iam_role" "notify_slack" {
  name               = "soar-notify-slack"
  assume_role_policy = data.aws_iam_policy_document.playbook_assume.json
}

resource "aws_iam_role_policy" "notify_slack" {
  role = aws_iam_role.notify_slack.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.slack_webhook.arn
      }
    ]
  })
}

resource "aws_lambda_function" "notify_slack" {
  function_name    = "soar-notify-slack"
  role             = aws_iam_role.notify_slack.arn
  handler          = "notify_slack.handler"
  runtime          = "python3.11"
  architectures    = ["arm64"]
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.notify_slack.output_path
  source_code_hash = data.archive_file.notify_slack.output_base64sha256

  environment {
    variables = {
      SLACK_SECRET_ID   = aws_secretsmanager_secret.slack_webhook.name
      APPROVAL_API_BASE = aws_apigatewayv2_api.approval.api_endpoint
    }
  }

  depends_on = [aws_iam_role_policy.notify_slack]
}

# ----- open_github_issue -----
data "archive_file" "open_github_issue" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/playbook/open_github_issue"
  output_path = "${path.module}/build/open_github_issue.zip"
}

resource "aws_iam_role" "open_github_issue" {
  name               = "soar-open-github-issue"
  assume_role_policy = data.aws_iam_policy_document.playbook_assume.json
}

resource "aws_iam_role_policy" "open_github_issue" {
  role = aws_iam_role.open_github_issue.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.github_token.arn
      }
    ]
  })
}

resource "aws_lambda_function" "open_github_issue" {
  function_name    = "soar-open-github-issue"
  role             = aws_iam_role.open_github_issue.arn
  handler          = "open_github_issue.handler"
  runtime          = "python3.11"
  architectures    = ["arm64"]
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.open_github_issue.output_path
  source_code_hash = data.archive_file.open_github_issue.output_base64sha256

  environment {
    variables = {
      GITHUB_SECRET_ID = aws_secretsmanager_secret.github_token.name
    }
  }

  depends_on = [aws_iam_role_policy.open_github_issue]
}

# ----- approval_callback -----
data "archive_file" "approval_callback" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/playbook/approval_callback"
  output_path = "${path.module}/build/approval_callback.zip"
}

resource "aws_iam_role" "approval_callback" {
  name               = "soar-approval-callback"
  assume_role_policy = data.aws_iam_policy_document.playbook_assume.json
}

resource "aws_iam_role_policy" "approval_callback" {
  role = aws_iam_role.approval_callback.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["states:SendTaskSuccess", "states:SendTaskFailure"]
        Resource = "arn:aws:states:${var.region}:${var.account_id}:stateMachine:${var.state_machine_name}"
      }
    ]
  })
}

resource "aws_lambda_function" "approval_callback" {
  function_name    = "soar-approval-callback"
  role             = aws_iam_role.approval_callback.arn
  handler          = "approval_callback.handler"
  runtime          = "python3.11"
  architectures    = ["arm64"]
  timeout          = 30
  filename         = data.archive_file.approval_callback.output_path
  source_code_hash = data.archive_file.approval_callback.output_base64sha256
  depends_on       = [aws_iam_role_policy.approval_callback]
}