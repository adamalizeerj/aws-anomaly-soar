variable "region" {
  description = "Primary AWS region for the lab"
  type        = string
  default     = "us-east-1"
}

variable "account_id" {
  description = "AWS account ID (used for resource ARNs and bucket naming)"
  type        = string
}

variable "cloudtrail_retention_days" {
  description = "CloudWatch Logs retention for CloudTrail events"
  type        = number
  default     = 14
}