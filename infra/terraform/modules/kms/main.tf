# L11 §4 keys: the anchor key (ECC_SECG_P256K1, SIGN_VERIFY; L5 §3.3) and the symmetric envelope key
# (api per-org data keys, RDS storage). Only the anchor task role may kms:Sign the anchor key: the key
# policy gives account admins every management action except Sign, and denies Sign to any other principal.
# CloudTrail → EventBridge alerts on a Sign by anyone else and on any key-policy change.

variable "name" {
  type = string
}

variable "anchor_role_arn" {
  description = "The anchor ECS task role: the only principal allowed to sign."
  type        = string
}

variable "envelope_role_arns" {
  description = "Task roles that may Encrypt/Decrypt/GenerateDataKey with the envelope key (api)."
  type        = list(string)
  default     = []
}

variable "alert_topic_arn" {
  type = string
}

data "aws_caller_identity" "this" {}

locals {
  root = "arn:aws:iam::${data.aws_caller_identity.this.account_id}:root"
  admin_actions = [
    "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
    "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource",
    "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
  ]
}

resource "aws_kms_key" "anchor" {
  description              = "${var.name} RecorderAnchor signing key (L5 §3.3)"
  customer_master_key_spec = "ECC_SECG_P256K1"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AdminWithoutSign"
        Effect    = "Allow"
        Principal = { AWS = local.root }
        Action    = local.admin_actions
        Resource  = "*"
      },
      {
        Sid       = "AnchorSigns"
        Effect    = "Allow"
        Principal = { AWS = var.anchor_role_arn }
        Action    = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
        Resource  = "*"
      },
      {
        Sid       = "NobodyElseSigns"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "kms:Sign"
        Resource  = "*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = var.anchor_role_arn } }
      },
    ]
  })
}

resource "aws_kms_alias" "anchor" {
  name          = "alias/${var.name}-anchor"
  target_key_id = aws_kms_key.anchor.key_id
}

resource "aws_kms_key" "envelope" {
  description             = "${var.name} envelope key (per-org data keys, RDS storage)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid       = "Admin"
        Effect    = "Allow"
        Principal = { AWS = local.root }
        Action    = "kms:*"
        Resource  = "*"
      }],
      length(var.envelope_role_arns) == 0 ? [] : [{
        Sid       = "Services"
        Effect    = "Allow"
        Principal = { AWS = var.envelope_role_arns }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource  = "*"
      }],
    )
  })
}

resource "aws_kms_alias" "envelope" {
  name          = "alias/${var.name}-envelope"
  target_key_id = aws_kms_key.envelope.key_id
}

# Needs CloudTrail management events in the account (an org trail): KMS calls arrive as
# "AWS API Call via CloudTrail".
resource "aws_cloudwatch_event_rule" "foreign_sign" {
  name        = "${var.name}-anchor-key-foreign-sign"
  description = "kms:Sign on the anchor key by anything other than the anchor task role"
  event_pattern = jsonencode({
    source        = ["aws.kms"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["Sign"]
      resources = { ARN = [aws_kms_key.anchor.arn] }
      userIdentity = {
        sessionContext = { sessionIssuer = { arn = [{ "anything-but" = var.anchor_role_arn }] } }
      }
    }
  })
}

resource "aws_cloudwatch_event_rule" "policy_change" {
  name        = "${var.name}-anchor-key-policy-change"
  description = "Key policy, grant or state change on the anchor key"
  event_pattern = jsonencode({
    source        = ["aws.kms"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutKeyPolicy", "CreateGrant", "DisableKey", "ScheduleKeyDeletion"]
      resources = { ARN = [aws_kms_key.anchor.arn] }
    }
  })
}

resource "aws_cloudwatch_event_target" "alerts" {
  for_each = {
    sign   = aws_cloudwatch_event_rule.foreign_sign.name
    policy = aws_cloudwatch_event_rule.policy_change.name
  }
  rule = each.value
  arn  = var.alert_topic_arn
}

output "anchor_key_arn" {
  value = aws_kms_key.anchor.arn
}

output "anchor_key_id" {
  value = aws_kms_key.anchor.key_id
}

output "envelope_key_arn" {
  value = aws_kms_key.envelope.arn
}
