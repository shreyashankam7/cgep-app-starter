# Layer 1: evidence vault with S3 Object Lock, versioning, and our CMK.

resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.name_prefix}-evidence-${local.suffix}"
  object_lock_enabled = true
}

# Object Lock requires versioning.
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Every object gets a default lock, so the retention date is set automatically.
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

output "evidence_vault" {
  value = aws_s3_bucket.evidence.id
}
# Found by policy 4 (03.13.08): the vault itself must refuse non-TLS requests.
resource "aws_s3_bucket_policy" "evidence_tls" {
  bucket = aws_s3_bucket.evidence.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.evidence.arn,
        "${aws_s3_bucket.evidence.arn}/*"
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.evidence]
}
