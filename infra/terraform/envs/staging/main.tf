# Staging (L11 §2, P3-12, P4): network, RDS, ECS cluster with the api, anchor and watcher services, KMS keys, ECR and
# empty Secrets Manager entries. Secret values are set out of band (never in tfstate). Plan and apply by
# hand from an operator's AWS session in the staging account; see ../../README.md.

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
  # bucket, key, region and dynamodb_table come from backend.hcl (see backend.hcl.example)
  backend "s3" {}
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "certificate_arn" {
  description = "ACM certificate for the API's HTTPS listener."
  type        = string
}

variable "anchor_image_tag" {
  type = string
}

variable "api_image_tag" {
  type = string
}

variable "watcher_image_tag" {
  type = string
}

variable "api_desired_count" {
  type    = number
  default = 2 # L11 §2: 2+ tasks behind the ALB (-var api_desired_count=1 for a cost-only staging)
}

variable "cpu_architecture" {
  description = "Must match the pushed images: X86_64 when built on an amd64 laptop (no buildx)."
  type        = string
  default     = "ARM64"
}

variable "siwe_domain" {
  description = "The dashboard host SIWE messages must name (e.g. app.staging.afr.dev)."
  type        = string
}

variable "dashboard_origin" {
  description = "https origin of the dashboard: the only CORS origin. null = same-origin only."
  type        = string
  default     = null
}

variable "alert_email" {
  type    = string
  default = null
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { project = "afr", env = "staging", managed_by = "terraform" }
  }
}

locals {
  name = "afr-staging"
}

data "aws_iam_policy_document" "alerts" {
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "cloudwatch.amazonaws.com"] # cloudwatch: the canary alarms
    }
  }
}

resource "aws_sns_topic" "alerts" {
  name = "${local.name}-alerts"
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == null ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

module "network" {
  source       = "../../modules/network"
  name         = local.name
  endpoint_azs = 1 # staging cost: one set of endpoint ENIs (L11 §2 prod keeps 3)
}

module "kms" {
  source             = "../../modules/kms"
  name               = local.name
  anchor_role_arn    = module.anchor.task_role_arn
  envelope_role_arns = [module.api.task_role_arn, module.watcher.task_role_arn, module.canary.task_role_arn] # watch keys
  alert_topic_arn    = aws_sns_topic.alerts.arn
}

module "rds" {
  source     = "../../modules/rds"
  name       = local.name
  vpc_id     = module.network.vpc_id
  subnet_ids = module.network.private_subnet_ids
  client_security_group_ids = [
    module.api.security_group_id,
    module.anchor.security_group_id,
    module.watcher.security_group_id,
    module.canary.security_group_id,
  ]
  kms_key_arn = module.kms.envelope_key_arn
  multi_az    = false # staging; prod is Multi-AZ (L11 §2)
  # staging runs in an AWS Free plan account: micro, 1-day backups, no Performance Insights
  instance_class        = "db.t4g.micro"
  allocated_storage_gb  = 20
  backup_retention_days = 1
  performance_insights  = false
}

resource "aws_ecr_repository" "this" {
  for_each             = toset(["api", "anchor", "watcher"])
  name                 = "afr/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

# Values are put with `aws secretsmanager put-secret-value` by an operator, never through Terraform.
resource "aws_secretsmanager_secret" "this" {
  for_each = toset([
    "anchor/pg-url",
    "anchor/rpc-url",
    "anchor/arkiv-access-key",
    "anchor/arkiv-writer-key",
    "api/pg-url",
    "watcher/pg-url",
    "watcher/rpc-url",
    "watcher/arkiv-access-key",
    "canary/wallet-key",
  ])
  name = "${local.name}/${each.key}"
}

resource "aws_ecs_cluster" "this" {
  name = local.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

module "anchor" {
  source           = "../../modules/ecs-service"
  name             = "${local.name}-anchor"
  cluster_arn      = aws_ecs_cluster.this.arn
  vpc_id           = module.network.vpc_id
  subnet_ids       = module.network.private_subnet_ids
  image            = "${aws_ecr_repository.this["anchor"].repository_url}:${var.anchor_image_tag}"
  desired_count    = 1
  cpu_architecture = var.cpu_architecture
  single_task      = true # leader-locked (L5 §3.2); a deploy must not overlap two signers
  environment = {
    AFR_ANCHOR_CHAIN_ID   = "84532"
    AFR_ANCHOR_KMS_KEY_ID = module.kms.anchor_key_id
    AWS_REGION            = var.region
  }
  secrets = {
    AFR_PG_URL           = aws_secretsmanager_secret.this["anchor/pg-url"].arn
    AFR_ANCHOR_RPC_URL   = aws_secretsmanager_secret.this["anchor/rpc-url"].arn
    ARKIV_ACCESS_KEY     = aws_secretsmanager_secret.this["anchor/arkiv-access-key"].arn
    AFR_ARKIV_WRITER_KEY = aws_secretsmanager_secret.this["anchor/arkiv-writer-key"].arn
  }
  task_policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
      Resource = module.kms.anchor_key_arn
    }]
  })
}

# L6 §7: follows Base Sepolia, matches intents, reconciles Arkiv batches. Leader-locked per chain; it only
# decrypts (watch keys under the org DEKs) and reads Arkiv with a throwaway writer key and a zero spend cap.
module "watcher" {
  source           = "../../modules/ecs-service"
  name             = "${local.name}-watcher"
  cluster_arn      = aws_ecs_cluster.this.arn
  vpc_id           = module.network.vpc_id
  subnet_ids       = module.network.private_subnet_ids
  image            = "${aws_ecr_repository.this["watcher"].repository_url}:${var.watcher_image_tag}"
  desired_count    = 1
  cpu_architecture = var.cpu_architecture
  single_task      = true
  environment = {
    AFR_WATCH_CHAIN_ID      = "84532"
    AFR_IDENTITY_CHAIN_ID   = "84532"
    AFR_KMS_ENVELOPE_KEY_ID = module.kms.envelope_key_arn
    AWS_REGION              = var.region
  }
  secrets = {
    AFR_PG_URL           = aws_secretsmanager_secret.this["watcher/pg-url"].arn
    AFR_WATCH_RPC_URL    = aws_secretsmanager_secret.this["watcher/rpc-url"].arn
    AFR_IDENTITY_RPC_URL = aws_secretsmanager_secret.this["watcher/rpc-url"].arn # same chain
    ARKIV_ACCESS_KEY     = aws_secretsmanager_secret.this["watcher/arkiv-access-key"].arn
  }
  task_policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:DescribeKey"]
      Resource = module.kms.envelope_key_arn
    }]
  })
}

resource "aws_security_group" "alb" {
  name_prefix = "${local.name}-alb-"
  description = "Public HTTPS to the API"
  vpc_id      = module.network.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [module.network.cidr]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb" "api" {
  name                       = "${local.name}-api"
  load_balancer_type         = "application"
  subnets                    = module.network.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "api" {
  name        = "${local.name}-api"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = module.network.vpc_id
  health_check {
    path    = "/healthz"
    matcher = "200"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.api.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

module "api" {
  source           = "../../modules/ecs-service"
  name             = "${local.name}-api"
  cluster_arn      = aws_ecs_cluster.this.arn
  vpc_id           = module.network.vpc_id
  subnet_ids       = module.network.private_subnet_ids
  image            = "${aws_ecr_repository.this["api"].repository_url}:${var.api_image_tag}"
  desired_count    = var.api_desired_count
  cpu              = 512
  memory           = 1024
  cpu_architecture = var.cpu_architecture
  # shortcut: no AFR_REDIS_URL yet, so each task rate-limits on its own (L8 §7); add ElastiCache with the cdn module
  environment = merge(
    {
      AFR_KMS_ENVELOPE_KEY_ID = module.kms.envelope_key_arn
      AFR_SIWE_DOMAIN         = var.siwe_domain
      AFR_DASHBOARD_DIR       = "/app/dashboard" # ADR-026: the api image carries the dashboard build
      AWS_REGION              = var.region
      PORT                    = "8080"
    },
    var.dashboard_origin == null ? {} : { AFR_DASHBOARD_ORIGIN = var.dashboard_origin },
  )
  secrets = {
    AFR_PG_URL = aws_secretsmanager_secret.this["api/pg-url"].arn
  }
  task_policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      Resource = module.kms.envelope_key_arn
    }]
  })
  alb = {
    container_port    = 8080
    target_group_arn  = aws_lb_target_group.api.arn
    security_group_id = aws_security_group.alb.id
  }
}

# P4-07 canary (L6 W9, L11 §5): the watcher image's canary entry point, one round an hour. It provisions its
# own agent (a fresh org DEK and watch key: kms:Encrypt/GenerateDataKey) and pages through the alerts topic
# on a failed round or no passed round for 2 h.
module "canary" {
  source           = "../../modules/ecs-service"
  name             = "${local.name}-canary"
  cluster_arn      = aws_ecs_cluster.this.arn
  vpc_id           = module.network.vpc_id
  subnet_ids       = module.network.private_subnet_ids
  image            = "${aws_ecr_repository.this["watcher"].repository_url}:${var.watcher_image_tag}"
  command          = ["node", "dist/canary-main.js"]
  desired_count    = 1
  cpu_architecture = var.cpu_architecture
  single_task      = true
  environment = {
    AFR_WATCH_CHAIN_ID      = "84532"
    AFR_KMS_ENVELOPE_KEY_ID = module.kms.envelope_key_arn
    AWS_REGION              = var.region
  }
  secrets = {
    AFR_PG_URL        = aws_secretsmanager_secret.this["watcher/pg-url"].arn
    AFR_WATCH_RPC_URL = aws_secretsmanager_secret.this["watcher/rpc-url"].arn
    AFR_CANARY_KEY    = aws_secretsmanager_secret.this["canary/wallet-key"].arn
  }
  task_policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      Resource = module.kms.envelope_key_arn
    }]
  })
}

resource "aws_cloudwatch_log_metric_filter" "canary" {
  for_each       = toset(["canary_ok", "canary_failed"])
  name           = "${local.name}-${each.key}"
  log_group_name = module.canary.log_group_name
  pattern        = "{ $.event = \"${each.key}\" }"
  metric_transformation {
    name          = each.key
    namespace     = "AFR/Staging"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "canary_failed" {
  alarm_name          = "${local.name}-canary-failed"
  alarm_description   = "A canary round failed (L11 §5): see the canary log's canary_failed code."
  namespace           = "AFR/Staging"
  metric_name         = "canary_failed"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "canary_missing" {
  alarm_name          = "${local.name}-canary-missing"
  alarm_description   = "No passed canary round for 2 h (L11 §5)."
  namespace           = "AFR/Staging"
  metric_name         = "canary_ok"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

output "anchor_key_id" {
  description = "The anchor's address is derived from this key's public key (README: allowlisting)."
  value       = module.kms.anchor_key_id
}

output "ecr" {
  value = { for k, r in aws_ecr_repository.this : k => r.repository_url }
}

output "rds_endpoint" {
  value = module.rds.endpoint
}

output "api_url" {
  value = "https://${aws_lb.api.dns_name}"
}
