# ---------------------------------------------------------
# EventBridge Detection Rule
# ---------------------------------------------------------
# Watches for security group ingress authorization events
# delivered through CloudTrail.
#
# The Python detector performs the deeper analysis to decide
# whether the change actually exposes SSH to 0.0.0.0/0.
# ---------------------------------------------------------

resource "aws_cloudwatch_event_rule" "security_group_change" {
  name        = "lab6-detect-security-group-change"
  description = "Detect security group ingress authorization events"

  event_pattern = jsonencode({
    source = [
      "aws.ec2"
    ]

    detail-type = [
      "AWS API Call via CloudTrail"
    ]

    detail = {
      eventSource = [
        "ec2.amazonaws.com"
      ]

      eventName = [
        "AuthorizeSecurityGroupIngress"
      ]
    }
  })

  tags = {
    Project = "Lab6"
  }
}

# ---------------------------------------------------------
# Send matching events to the incident-response Lambda
# ---------------------------------------------------------

resource "aws_cloudwatch_event_target" "incident_response" {
  rule = aws_cloudwatch_event_rule.security_group_change.name
  arn  = aws_lambda_function.incident_response.arn
}

# ---------------------------------------------------------
# Allow EventBridge to invoke Lambda
# ---------------------------------------------------------

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.incident_response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_group_change.arn
}