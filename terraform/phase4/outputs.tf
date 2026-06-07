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

output "state_machine_arn" {
  value = aws_sfn_state_machine.playbook.arn
}

output "state_machine_log_group" {
  value = aws_cloudwatch_log_group.state_machine.name
}

output "approval_callback_function_name" {
  value = aws_lambda_function.approval_callback.function_name
}

output "approval_api_url" {
  value       = "${aws_apigatewayv2_api.approval.api_endpoint}/approval"
  description = "Endpoint analysts hit to approve/reject. Append ?token=...&decision=approve|reject"
}

output "approval_api_access_log_group" {
  value = aws_cloudwatch_log_group.api_access.name
}