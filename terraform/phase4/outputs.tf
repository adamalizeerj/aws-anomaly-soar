output "slack_webhook_secret_arn" {
  value = aws_secretsmanager_secret.slack_webhook.arn
}

output "github_token_secret_arn" {
  value = aws_secretsmanager_secret.github_token.arn
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.id
}

output "audit_bus_name" {
  value = aws_cloudwatch_event_bus.soar_audit.name
}

output "audit_log_group" {
  value = aws_cloudwatch_log_group.soar_audit.name
}

output "responder_lambda_log_group" {
  value = "/aws/lambda/${aws_lambda_function.responder.function_name}"
}