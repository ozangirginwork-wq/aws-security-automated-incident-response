# ---------------------------------------------------------
# CloudWatch Logging
# ---------------------------------------------------------
# Explicitly manage the Lambda log group so retention is
# controlled rather than leaving logs indefinitely.
# ---------------------------------------------------------

resource "aws_cloudwatch_log_group" "incident_response" {
  name              = "/aws/lambda/${aws_lambda_function.incident_response.function_name}"
  retention_in_days = 365

  tags = {
    Project = "Lab6"
  }
}