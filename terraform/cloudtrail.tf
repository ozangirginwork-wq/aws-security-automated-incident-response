# ---------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------
# Records AWS management API activity so EventBridge can
# receive "AWS API Call via CloudTrail" events.
#
# Logs are stored in a dedicated private S3 bucket.
# ---------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail" {
  bucket_prefix = "lab6-cloudtrail-"

  tags = {
    Name    = "lab6-cloudtrail-logs"
    Project = "Lab6"
  }
}

# Block all public access to the CloudTrail bucket.
resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Encrypt CloudTrail logs at rest using S3-managed encryption.
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Automatically remove old lab logs to minimize storage cost.
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "delete-old-cloudtrail-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }
  }
}

# CloudTrail requires permission to verify the bucket ACL
# and write log objects.
data "aws_iam_policy_document" "cloudtrail_bucket" {
  statement {
    sid = "AWSCloudTrailAclCheck"

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl"
    ]

    resources = [
      aws_s3_bucket.cloudtrail.arn
    ]
  }

  statement {
    sid = "AWSCloudTrailWrite"

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json
}

data "aws_caller_identity" "current" {}

resource "aws_cloudtrail" "lab6" {
  name                          = "lab6-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_logging                = true

  depends_on = [
    aws_s3_bucket_policy.cloudtrail
  ]

  tags = {
    Name    = "lab6-cloudtrail"
    Project = "Lab6"
  }
}