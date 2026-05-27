resource "aws_cloudwatch_event_bus" "soar_audit" {
  name = "soar-audit-trail"
}

# CloudWatch log group as the destination for the audit bus.
# Every state machine transition will write here, giving us a
# permanent, queryable timeline of what the SOAR system did.
resource "aws_cloudwatch_log_group" "soar_audit" {
  name              = "/aws/events/soar-audit-trail"
  retention_in_days = 30
}

resource "aws_cloudwatch_event_rule" "audit_capture_all" {
  name           = "capture-all-soar-events"
  description    = "Forward every event on the soar-audit-trail bus to CloudWatch Logs"
  event_bus_name = aws_cloudwatch_event_bus.soar_audit.name

  event_pattern = jsonencode({
    source = [{ prefix = "soar." }]
  })
}

resource "aws_cloudwatch_event_target" "audit_to_logs" {
  rule           = aws_cloudwatch_event_rule.audit_capture_all.name
  event_bus_name = aws_cloudwatch_event_bus.soar_audit.name
  target_id      = "audit-logs"
  arn            = aws_cloudwatch_log_group.soar_audit.arn
}

# EventBridge needs explicit permission to write to CloudWatch Logs.
# This resource grants that on the log group's resource policy.
data "aws_iam_policy_document" "events_to_logs" {
  statement {
    sid    = "EventBridgeToCWLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.soar_audit.arn}:*"]
  }
}

resource "aws_cloudwatch_log_resource_policy" "events_to_logs" {
  policy_name     = "EventBridgeToSOARAuditLogs"
  policy_document = data.aws_iam_policy_document.events_to_logs.json
}