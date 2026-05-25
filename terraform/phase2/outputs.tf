output "lambda_function_name" {
  value = aws_lambda_function.detector.function_name
}

output "lambda_log_group" {
  value = "/aws/lambda/${aws_lambda_function.detector.function_name}"
}

output "sns_topic_arn" {
  value = aws_sns_topic.anomaly_detections.arn
}

output "seen_tuples_table" {
  value = aws_dynamodb_table.seen_tuples.name
}

output "principal_ages_table" {
  value = aws_dynamodb_table.principal_ages.name
}