# GAP-07: permissions written as policy documents so actions are checkable at plan time.

data "aws_iam_policy_document" "lambda_data" {
  statement {
    sid       = "IntakeTableWrite"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.intake.arn]
  }

  statement {
    sid       = "UploadsObjectWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.uploads.arn}/uploads/*"]
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  name   = "intake-data-access"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_data.json
}

data "aws_iam_policy_document" "lambda_kms" {
  statement {
    sid    = "UseIntakeKey"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
    ]
    resources = [aws_kms_key.phi.arn]
  }
}

resource "aws_iam_role_policy" "lambda_kms" {
  name   = "intake-kms-access"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_kms.json
}
