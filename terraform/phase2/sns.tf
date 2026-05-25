resource "aws_sns_topic" "anomaly_detections" {
  name              = "anomaly-detections"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.anomaly_detections.arn
  protocol  = "email"
  endpoint  = var.alert_email
}