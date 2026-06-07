output "test_user_names" {
  value = [for u in aws_iam_user.test : u.name]
}

output "test_user_secret_arns" {
  value     = { for k, s in aws_secretsmanager_secret.test_user_keys : k => s.arn }
  sensitive = true
}

output "activity_lambda_log_group" {
  value = "/aws/lambda/${aws_lambda_function.activity.function_name}"
}