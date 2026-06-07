# EventBridge Scheduler invokes the activity Lambda on a recurring schedule.
# Using the newer EventBridge Scheduler service (not classic Rules) — it's
# the AWS-recommended path for scheduled invocations as of late 2024.

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "security-lab-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  name = "invoke-activity-lambda"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.activity.arn
    }]
  })
}

resource "aws_scheduler_schedule" "activity" {
  name       = "security-lab-baseline-activity"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = var.activity_schedule_expression

  target {
    arn      = aws_lambda_function.activity.arn
    role_arn = aws_iam_role.scheduler.arn
  }
}