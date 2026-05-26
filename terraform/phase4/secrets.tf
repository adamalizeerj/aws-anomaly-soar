resource "aws_secretsmanager_secret" "slack_webhook" {
  name                    = "security-lab/slack-webhook-url"
  description             = "Incoming webhook URL for security alert notifications"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "slack_webhook" {
  secret_id     = aws_secretsmanager_secret.slack_webhook.id
  secret_string = var.slack_webhook_url
}

resource "aws_secretsmanager_secret" "github_token" {
  name                    = "security-lab/github-token"
  description             = "GitHub PAT for filing security incident issues"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "github_token" {
  secret_id = aws_secretsmanager_secret.github_token.id
  secret_string = jsonencode({
    token = var.github_token
    repo  = var.github_repo
  })
}