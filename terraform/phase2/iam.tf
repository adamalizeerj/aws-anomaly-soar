data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "detector_lambda" {
  name               = "security-lab-detector-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "detector_lambda" {
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
    sid    = "ReadWriteDynamoDB"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem"
    ]
    resources = [
      aws_dynamodb_table.seen_tuples.arn,
      aws_dynamodb_table.principal_ages.arn
    ]
  }

  statement {
    sid     = "PublishAlerts"
    effect  = "Allow"
    actions = ["sns:Publish"]
    resources = [
      aws_sns_topic.anomaly_detections.arn
    ]
  }
}

resource "aws_iam_role_policy" "detector_lambda" {
  name   = "detector-lambda-permissions"
  role   = aws_iam_role.detector_lambda.id
  policy = data.aws_iam_policy_document.detector_lambda.json
}