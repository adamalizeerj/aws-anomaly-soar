data "aws_iam_policy_document" "sfn_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "state_machine" {
  name               = "soar-state-machine"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
}

resource "aws_iam_role_policy" "state_machine" {
  role = aws_iam_role.state_machine.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          aws_lambda_function.tag_principal.arn,
          aws_lambda_function.apply_deny.arn,
          aws_lambda_function.snapshot_evidence.arn,
          aws_lambda_function.notify_slack.arn,
          aws_lambda_function.open_github_issue.arn,
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["events:PutEvents"]
        Resource = aws_cloudwatch_event_bus.soar_audit.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "state_machine" {
  name              = "/aws/vendedlogs/states/${var.state_machine_name}"
  retention_in_days = 30
}

resource "aws_sfn_state_machine" "playbook" {
  name     = var.state_machine_name
  role_arn = aws_iam_role.state_machine.arn
  type     = "STANDARD"

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.state_machine.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  definition = jsonencode({
    Comment = "SOAR incident response playbook"
    StartAt = "TagPrincipal"
    States = {
      TagPrincipal = {
        Type       = "Task"
        Resource   = aws_lambda_function.tag_principal.arn
        ResultPath = "$.tag_result"
        Next       = "RequestApproval"
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 2
        }]
      }

      RequestApproval = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke.waitForTaskToken"
        Parameters = {
          FunctionName = aws_lambda_function.notify_slack.arn
          Payload = {
            "alert.$"          = "$"
            "approval_request" = true
            "token.$"          = "$$.Task.Token"
            "evidence_uri"     = "(pending)"
            "event_count"      = 0
            "contained"        = false
          }
        }
        ResultPath = "$.approval"
        Next       = "ApprovedBranch"
        Catch = [{
          ErrorEquals = ["RejectedByOperator", "States.TaskFailed"]
          ResultPath  = "$.approval_error"
          Next        = "SnapshotEvidenceNoContain"
        }]
        TimeoutSeconds = 3600
      }

      ApprovedBranch = {
        Type       = "Pass"
        Result     = { "approval_decision" = "approved" }
        ResultPath = "$.approval_decision_wrapper"
        Next       = "ApplyDeny"
      }

      ApplyDeny = {
        Type       = "Task"
        Resource   = aws_lambda_function.apply_deny.arn
        ResultPath = "$.containment"
        Next       = "SnapshotEvidenceContained"
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 2
        }]
      }

      SnapshotEvidenceContained = {
        Type       = "Task"
        Resource   = aws_lambda_function.snapshot_evidence.arn
        ResultPath = "$.evidence"
        Next       = "NotifySlackFinalContained"
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 5
          MaxAttempts     = 2
          BackoffRate     = 2
        }]
      }

      SnapshotEvidenceNoContain = {
        Type       = "Task"
        Resource   = aws_lambda_function.snapshot_evidence.arn
        ResultPath = "$.evidence"
        Next       = "NotifySlackFinalNotContained"
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 5
          MaxAttempts     = 2
          BackoffRate     = 2
        }]
      }

      NotifySlackFinalContained = {
        Type     = "Task"
        Resource = aws_lambda_function.notify_slack.arn
        Parameters = {
          "alert.$"        = "$"
          "evidence_uri.$" = "$.evidence.evidence_uri"
          "event_count.$"  = "$.evidence.event_count"
          "contained"      = true
        }
        ResultPath = "$.slack_result"
        Next       = "OpenGitHubIssueContained"
      }

      NotifySlackFinalNotContained = {
        Type     = "Task"
        Resource = aws_lambda_function.notify_slack.arn
        Parameters = {
          "alert.$"        = "$"
          "evidence_uri.$" = "$.evidence.evidence_uri"
          "event_count.$"  = "$.evidence.event_count"
          "contained"      = false
        }
        ResultPath = "$.slack_result"
        Next       = "OpenGitHubIssueNotContained"
      }

      OpenGitHubIssueContained = {
        Type     = "Task"
        Resource = aws_lambda_function.open_github_issue.arn
        Parameters = {
          "alert.$"           = "$"
          "evidence_uri.$"    = "$.evidence.evidence_uri"
          "event_count.$"     = "$.evidence.event_count"
          "contained"         = true
          "approval_decision" = "approved"
        }
        ResultPath = "$.github_result"
        End        = true
      }

      OpenGitHubIssueNotContained = {
        Type     = "Task"
        Resource = aws_lambda_function.open_github_issue.arn
        Parameters = {
          "alert.$"           = "$"
          "evidence_uri.$"    = "$.evidence.evidence_uri"
          "event_count.$"     = "$.evidence.event_count"
          "contained"         = false
          "approval_decision" = "rejected"
        }
        ResultPath = "$.github_result"
        End        = true
      }
    }
  })
}