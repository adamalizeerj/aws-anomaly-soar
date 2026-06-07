output "cloudtrail_bucket" {
  value = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_log_group" {
  value = aws_cloudwatch_log_group.cloudtrail.name
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}

output "kms_key_arn" {
  value = aws_kms_key.logs.arn
}

output "config_bucket" {
  value = aws_s3_bucket.config.id
}