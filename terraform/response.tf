# Package the local Python incident-response code for Lambda.
data "archive_file" "response_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/lambda-response.zip"
}

# Lambda execution role.
resource "aws_iam_role" "response_lambda" {
  name = "lab6-incident-response-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# CloudWatch logging permissions.
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.response_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ---------------------------------------------------------
# Least-Privilege Incident Response Permissions
# ---------------------------------------------------------
# Write/remediation permission is restricted to the
# protected Lab 6 security group.
#
# DescribeSecurityGroups is read-only and is required so
# the verifier can independently confirm remediation.
# ---------------------------------------------------------

resource "aws_iam_role_policy" "remediation" {
  name = "lab6-security-group-remediation"
  role = aws_iam_role.response_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "RemediateProtectedSecurityGroup"
        Effect = "Allow"

        Action = [
          "ec2:RevokeSecurityGroupIngress"
        ]

        Resource = aws_security_group.protected.arn
      },
      {
        Sid    = "VerifySecurityGroupState"
        Effect = "Allow"

        Action = [
          "ec2:DescribeSecurityGroups"
        ]

        Resource = "*"
      }
    ]
  })
}

# ---------------------------------------------------------
# Incident Response Lambda
# ---------------------------------------------------------

resource "aws_lambda_function" "incident_response" {
  function_name = "lab6-incident-response"

  filename         = data.archive_file.response_lambda.output_path
  source_code_hash = data.archive_file.response_lambda.output_base64sha256

  role    = aws_iam_role.response_lambda.arn
  handler = "handler.lambda_handler"
  runtime = "python3.13"

  timeout     = 20
  memory_size = 128

  environment {
    variables = {
      ENABLE_LIVE_REMEDIATION     = "true"
      PROTECTED_SECURITY_GROUP_ID = aws_security_group.protected.id
    }
  }

  tags = {
    Project = "Lab6"
  }
}