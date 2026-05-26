variable "region" {
  type    = string
  default = "us-east-1"
}

variable "account_id" {
  type = string
}

variable "slack_webhook_url" {
  description = "Slack (or Discord) incoming webhook URL"
  type        = string
  sensitive   = true
}

variable "github_token" {
  description = "GitHub PAT with issues:write on the target repo"
  type        = string
  sensitive   = true
}

variable "github_repo" {
  description = "Target GitHub repo in owner/repo form"
  type        = string
}

variable "sns_topic_arn_for_anomalies" {
  description = "ARN of the Phase 2 SNS topic that publishes anomalies"
  type        = string
}