resource "aws_dynamodb_table" "seen_tuples" {
  name         = "security-lab-seen-tuples"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tuple_key"

  attribute {
    name = "tuple_key"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false # lab; would be true in prod
  }
}

resource "aws_dynamodb_table" "principal_ages" {
  name         = "security-lab-principal-ages"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_arn"

  attribute {
    name = "principal_arn"
    type = "S"
  }
}