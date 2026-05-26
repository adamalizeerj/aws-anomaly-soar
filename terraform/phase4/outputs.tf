output "slack_webhook_secret_arn" {
  value = aws_secretsmanager_secret.slack_webhook.arn
}

output "github_token_secret_arn" {
  value = aws_secretsmanager_secret.github_token.arn
}