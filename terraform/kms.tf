# Layer 1 baseline: customer-managed KMS key for PHI at rest.
# Closes the key-custody part of GAP-01 (S3) and GAP-02 (DynamoDB).

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "phi" {
  description             = "Acme Health intake: CMK for PHI at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}

# GAP-01: SSE-KMS on the uploads bucket, under our CMK.
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# The Lambda must be allowed to use the key, or every read and write fails.
resource "aws_iam_role_policy" "lambda_kms" {
  name = "intake-kms-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey",
        "kms:CreateGrant"
      ]
      Resource = aws_kms_key.phi.arn
    }]
  })
}
