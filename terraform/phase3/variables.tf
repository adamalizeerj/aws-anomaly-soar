variable "region" {
  type    = string
  default = "us-east-1"
}

variable "account_id" {
  type = string
}

variable "test_user_names" {
  description = "Names of test IAM users to create for baseline traffic"
  type        = list(string)
  default     = ["lab-alice", "lab-bob", "lab-carol"]
}

variable "activity_schedule_expression" {
  description = "EventBridge schedule for the activity Lambda (every 30 min by default)"
  type        = string
  default     = "rate(30 minutes)"
}