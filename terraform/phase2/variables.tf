variable "region" {
  type    = string
  default = "us-east-1"
}

variable "account_id" {
  type = string
}

variable "alert_email" {
  description = "Email to receive detection alerts during development"
  type        = string
}

variable "cloudtrail_log_group_name" {
  description = "Phase 1 CloudWatch Logs group receiving CloudTrail events"
  type        = string
  default     = "/aws/cloudtrail/security-lab"
}

variable "principal_age_warmup_days" {
  description = "Principals younger than this generate no anomalies (warm-up grace period)"
  type        = number
  default     = 7
}