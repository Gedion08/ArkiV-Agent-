# L11 §2 ecs-service: one Fargate service with its own task role (least privilege per service), an
# execution role that can read only the listed secrets, logs, and an optional ALB target.

variable "name" {
  type = string
}

variable "cluster_arn" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "image" {
  type = string
}

variable "cpu_architecture" {
  description = "ARM64 (Graviton, prod) or X86_64 (images built on an amd64 machine)."
  type        = string
  default     = "ARM64"
}

variable "cpu" {
  type    = number
  default = 256
}

variable "memory" {
  type    = number
  default = 512
}

variable "desired_count" {
  type    = number
  default = 1
}

variable "single_task" {
  description = "Never two tasks at once (a deploy stops the old one first). For leader-locked services."
  type        = bool
  default     = false
}

variable "environment" {
  type    = map(string)
  default = {}
}

variable "secrets" {
  description = "Env var name → Secrets Manager secret ARN."
  type        = map(string)
  default     = {}
}

variable "task_policy_json" {
  description = "Inline policy for the task role (what the service itself may call)."
  type        = string
}

variable "alb" {
  description = "Serve container_port behind this target group, reachable from the ALB's security group."
  type = object({
    container_port    = number
    target_group_arn  = string
    security_group_id = string
  })
  default = null
}

variable "log_retention_days" {
  type    = number
  default = 30
}

data "aws_region" "this" {}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/afr/${var.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  count = length(var.secrets) > 0 ? 1 : 0
  role  = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = distinct(values(var.secrets))
    }]
  })
}

resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "task" {
  role   = aws_iam_role.task.id
  policy = var.task_policy_json
}

resource "aws_security_group" "this" {
  name_prefix = "${var.name}-"
  description = "${var.name} tasks"
  vpc_id      = var.vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "from_alb" {
  count                        = var.alb == null ? 0 : 1
  security_group_id            = aws_security_group.this.id
  referenced_security_group_id = var.alb.security_group_id
  ip_protocol                  = "tcp"
  from_port                    = var.alb.container_port
  to_port                      = var.alb.container_port
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }
  container_definitions = jsonencode([{
    name                   = var.name
    image                  = var.image
    essential              = true
    user                   = "1000"
    readonlyRootFilesystem = true
    stopTimeout            = 60
    environment            = [for k, v in var.environment : { name = k, value = v }]
    secrets                = [for k, v in var.secrets : { name = k, valueFrom = v }]
    portMappings           = var.alb == null ? [] : [{ containerPort = var.alb.container_port }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = data.aws_region.this.name
        awslogs-stream-prefix = var.name
      }
    }
  }])
}

resource "aws_ecs_service" "this" {
  name                               = var.name
  cluster                            = var.cluster_arn
  task_definition                    = aws_ecs_task_definition.this.arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  deployment_minimum_healthy_percent = var.single_task ? 0 : 100
  deployment_maximum_percent         = var.single_task ? 100 : 200
  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.this.id]
    assign_public_ip = false
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  dynamic "load_balancer" {
    for_each = var.alb == null ? [] : [var.alb]
    content {
      target_group_arn = load_balancer.value.target_group_arn
      container_name   = var.name
      container_port   = load_balancer.value.container_port
    }
  }
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "security_group_id" {
  value = aws_security_group.this.id
}
