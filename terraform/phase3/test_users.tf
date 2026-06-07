# Three test IAM users with their access keys stored in Secrets Manager
# so the activity Lambda can assume their identity to generate per-user
# baseline traffic.

resource "aws_iam_user" "test" {
  for_each = toset(var.test_user_names)
  name     = each.value
  path     = "/security-lab/"

  tags = {
    Purpose = "behavioral-baseline-test"
  }
}

# Limited read-only permissions for baseline activity.
# These users should *only* be able to do the read calls the
# activity script makes — anything else they do is unusual.
resource "aws_iam_user_policy" "test_baseline_perms" {
  for_each = aws_iam_user.test
  name     = "baseline-read-perms"
  user     = each.value.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "iam:ListUsers",
          "iam:GetUser",
          "iam:ListAccessKeys",
          "sts:GetCallerIdentity",
          "cloudwatch:DescribeAlarms",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      # CreateAccessKey on themselves — this is the privilege escalation
      # we'll simulate as the anomaly. Required so the API call succeeds
      # rather than failing with AccessDenied (we want the success to be
      # logged in CloudTrail).
      {
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey"
        ]
        Resource = "arn:aws:iam::${var.account_id}:user/security-lab/$${aws:username}"
      }
    ]
  })
}

resource "aws_iam_access_key" "test" {
  for_each = aws_iam_user.test
  user     = each.value.name
}

resource "aws_secretsmanager_secret" "test_user_keys" {
  for_each                = aws_iam_user.test
  name                    = "security-lab/test-users/${each.value.name}"
  recovery_window_in_days = 0 # lab; delete immediately on destroy
}

resource "aws_secretsmanager_secret_version" "test_user_keys" {
  for_each  = aws_iam_user.test
  secret_id = aws_secretsmanager_secret.test_user_keys[each.key].id
  secret_string = jsonencode({
    access_key_id     = aws_iam_access_key.test[each.key].id
    secret_access_key = aws_iam_access_key.test[each.key].secret
    user_name         = each.value.name
  })
}