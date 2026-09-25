locals {
  dashboard_enabled = var.dashboard_port != null
}

check "dashboard_requires_allowed_cidrs" {
  assert {
    condition     = !local.dashboard_enabled || length(var.dashboard_allowed_cidrs) > 0
    error_message = "dashboard_allowed_cidrs must be set (non-empty) when dashboard_port is set — the dashboard has no authentication of its own, so it must not be reachable from an unrestricted CIDR."
  }
}

# --- ECS cluster -------------------------------------------------------

resource "aws_ecs_cluster" "this" {
  name = var.name
  tags = var.tags
}

# --- IAM: task execution role (pulls image, writes logs) ---------------

data "aws_iam_policy_document" "ecs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- Logging -------------------------------------------------------------

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = 14
  tags              = var.tags
}

# --- Task definition -----------------------------------------------------

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.container_cpu
  memory                   = var.container_memory
  execution_role_arn       = aws_iam_role.execution.arn

  container_definitions = jsonencode([
    {
      name  = "rampart"
      image = var.image
      portMappings = concat(
        [{ containerPort = var.proxy_port, protocol = "tcp" }],
        local.dashboard_enabled ? [{ containerPort = var.dashboard_port, protocol = "tcp" }] : []
      )
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.this.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "rampart"
        }
      }
    }
  ])

  tags = var.tags
}

data "aws_region" "current" {}

# --- Security groups -------------------------------------------------------

resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "Rampart ALB: public proxy port, restricted dashboard port"
  vpc_id      = var.vpc_id
  tags        = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_proxy_http" {
  security_group_id = aws_security_group.alb.id
  description       = "Public proxy traffic"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = var.certificate_arn != null ? 443 : 80
  to_port           = var.certificate_arn != null ? 443 : 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_proxy_http_redirect" {
  count              = var.certificate_arn != null ? 1 : 0
  security_group_id  = aws_security_group.alb.id
  description        = "HTTP, redirected to HTTPS"
  cidr_ipv4          = "0.0.0.0/0"
  from_port          = 80
  to_port             = 80
  ip_protocol        = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_dashboard" {
  for_each           = local.dashboard_enabled ? toset(var.dashboard_allowed_cidrs) : []
  security_group_id  = aws_security_group.alb.id
  description        = "Dashboard access - restricted CIDR only, no auth of its own"
  cidr_ipv4          = each.value
  from_port          = var.dashboard_port
  to_port            = var.dashboard_port
  ip_protocol        = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_all" {
  security_group_id = aws_security_group.alb.id
  cidr_ipv4          = "0.0.0.0/0"
  ip_protocol        = "-1"
}

resource "aws_security_group" "task" {
  name_prefix = "${var.name}-task-"
  description = "Rampart Fargate task: only reachable from the ALB"
  vpc_id      = var.vpc_id
  tags        = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "task_from_alb_proxy" {
  security_group_id           = aws_security_group.task.id
  description                 = "Proxy port, from ALB only"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                   = var.proxy_port
  to_port                     = var.proxy_port
  ip_protocol                 = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "task_from_alb_dashboard" {
  count                        = local.dashboard_enabled ? 1 : 0
  security_group_id           = aws_security_group.task.id
  description                 = "Dashboard port, from ALB only"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                   = var.dashboard_port
  to_port                     = var.dashboard_port
  ip_protocol                 = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "task_all" {
  # Needed to pull the container image from ECR and to reach `upstream`
  # (the app Rampart protects), which may be outside this security group.
  security_group_id = aws_security_group.task.id
  cidr_ipv4          = "0.0.0.0/0"
  ip_protocol        = "-1"
}

# --- Load balancer -----------------------------------------------------

resource "aws_lb" "this" {
  name               = var.name
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.alb.id]
  tags               = var.tags
}

resource "aws_lb_target_group" "proxy" {
  name        = "${var.name}-proxy"
  port        = var.proxy_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    # Rampart proxies "/" through to `upstream`; if this flaps, check
    # whether the protected app itself is healthy before assuming Rampart
    # is broken.
    matcher = "200-499"
  }

  tags = var.tags
}

resource "aws_lb_listener" "proxy_https" {
  count             = var.certificate_arn != null ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.proxy.arn
  }
}

resource "aws_lb_listener" "proxy_http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = var.certificate_arn != null ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = var.certificate_arn != null ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    target_group_arn = var.certificate_arn != null ? null : aws_lb_target_group.proxy.arn
  }
}

resource "aws_lb_target_group" "dashboard" {
  count       = local.dashboard_enabled ? 1 : 0
  name        = "${var.name}-dashboard"
  port        = var.dashboard_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path = "/"
  }

  tags = var.tags
}

resource "aws_lb_listener" "dashboard" {
  count             = local.dashboard_enabled ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = var.dashboard_port
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dashboard[0].arn
  }
}

# --- ECS service -----------------------------------------------------

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.proxy.arn
    container_name    = "rampart"
    container_port    = var.proxy_port
  }

  dynamic "load_balancer" {
    for_each = local.dashboard_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.dashboard[0].arn
      container_name    = "rampart"
      container_port    = var.dashboard_port
    }
  }

  depends_on = [aws_lb_listener.proxy_http]

  tags = var.tags
}
