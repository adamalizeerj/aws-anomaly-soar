data "archive_file" "activity" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src"
  output_path = "${path.module}/build/activity.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

data "aws_iam_policy_document" "activity_lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "activity_lambda" {
  name               = "security-lab-activity-lambda"
  assume_role_policy = data.aws_iam_policy_document.activity_lambda_assume.json
}

resource "aws_iam_role_policy" "activity_lambda" {
  name = "activity-lambda-perms"
  role = aws_iam_role.activity_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:*"
      },
      {
        Sid      = "ReadTestUserSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:security-lab/test-users/*"
      }
    ]
  })
}

resource "aws_lambda_function" "activity" {
  function_name    = "security-lab-activity-generator"
  role             = aws_iam_role.activity_lambda.arn
  handler          = "activity.handler"
  runtime          = "python3.11"
  architectures    = ["arm64"]
  timeout          = 120
  memory_size      = 256
  filename         = data.archive_file.activity.output_path
  source_code_hash = data.archive_file.activity.output_base64sha256

  environment {
    variables = {
      TEST_USER_SECRET_PREFIX = "security-lab/test-users/"
      TEST_USER_NAMES         = join(",", var.test_user_names)
      LOG_LEVEL               = "INFO"
    }
  }

  depends_on = [aws_iam_role_policy.activity_lambda]
}