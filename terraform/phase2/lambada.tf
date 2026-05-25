data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src"
  output_path = "${path.module}/build/detector.zip"
  excludes    = [".venv", "__pycache__", "*.pyc"]
}

resource "aws_lambda_function" "detector" {
  function_name    = "security-lab-detector"
  role             = aws_iam_role.detector_lambda.arn
  handler          = "detector.handler"
  runtime          = "python3.11"
  architectures    = ["arm64"]
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256

  environment {
    variables = {
      SEEN_TUPLES_TABLE    = aws_dynamodb_table.seen_tuples.name
      PRINCIPAL_AGES_TABLE = aws_dynamodb_table.principal_ages.name
      SNS_TOPIC_ARN        = aws_sns_topic.anomaly_detections.arn
      WARMUP_DAYS          = var.principal_age_warmup_days
      LOG_LEVEL            = "INFO"
    }
  }

  depends_on = [aws_iam_role_policy.detector_lambda]
}

resource "aws_lambda_permission" "allow_cwlogs" {
  statement_id  = "AllowCloudWatchLogsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "logs.${var.region}.amazonaws.com"
  source_arn    = "arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.cloudtrail_log_group_name}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "cloudtrail_to_detector" {
  name            = "cloudtrail-to-detector"
  log_group_name  = var.cloudtrail_log_group_name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.detector.arn

  depends_on = [aws_lambda_permission.allow_cwlogs]
}