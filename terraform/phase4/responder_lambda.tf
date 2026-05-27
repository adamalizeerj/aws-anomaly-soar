data "archive_file" "responder" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/responder"
  output_path = "${path.module}/build/responder.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

resource "aws_lambda_function" "responder" {
  function_name    = "security-lab-responder"
  role             = aws_iam_role.responder.arn
  handler          = "responder.handler"
  runtime          = "python3.11"
  architectures    = ["arm64"]
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.responder.output_path
  source_code_hash = data.archive_file.responder.output_base64sha256

  environment {
    variables = {
      STATE_MACHINE_ARN = "arn:aws:states:${var.region}:${var.account_id}:stateMachine:${var.state_machine_name}"
      AUDIT_BUS_NAME    = aws_cloudwatch_event_bus.soar_audit.name
      LOG_LEVEL         = "INFO"
    }
  }

  depends_on = [aws_iam_role_policy.responder]
}

resource "aws_lambda_permission" "sns_can_invoke" {
  statement_id  = "AllowSNSInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = var.sns_topic_arn_for_anomalies
}

resource "aws_sns_topic_subscription" "responder" {
  topic_arn = var.sns_topic_arn_for_anomalies
  protocol  = "lambda"
  endpoint  = aws_lambda_function.responder.arn

  depends_on = [aws_lambda_permission.sns_can_invoke]
}