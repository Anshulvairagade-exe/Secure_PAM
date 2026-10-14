# SecurePAM Keycloak on AWS (production identity for SecurePAM MFA).
#
#   users/backend --HTTPS--> ALB (ACM cert, TLS 1.2+) --HTTP (private, SG-restricted)--> EC2:8080 (Keycloak, start --optimized)
#                                                                                      \--> RDS PostgreSQL (private, encrypted)
#
# Exposure: the ALB is internal by default (var.public_alb). /admin/* (console + Admin REST) is forwarded
# ONLY for var.admin_cidr_blocks and the backend security groups (MFA sync uses /admin/realms/.../events);
# everyone else gets 403. /health and /metrics are never forwarded (the ALB health check reaches the
# target directly). No SSH: administration over SSM Session Manager.
#
# Secrets: the RDS master password is generated and stored by RDS in Secrets Manager
# (manage_master_user_password), so it never appears in Terraform state. The Keycloak bootstrap admin
# password and the audit-reader client secret are Secrets Manager shells whose VALUES are set by the
# operator / configure-realm.py, never by Terraform.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
    }
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

# --- Container registry ---

resource "aws_ecr_repository" "keycloak" {
  name                 = "${var.project}/keycloak"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
  }
}

# --- Secrets (shells only; values never in Terraform) ---

resource "aws_secretsmanager_secret" "bootstrap_admin" {
  name                    = "${var.project}/keycloak/bootstrap-admin"
  description             = "Keycloak master-realm bootstrap admin {\"username\",\"password\"}. Set by the operator before first boot."
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret" "audit_reader" {
  name                    = "${var.project}/keycloak/audit-reader-client-secret"
  description             = "securepam-audit-reader client secret for the SecurePAM backend MFA sync. Written by configure-realm.py."
  recovery_window_in_days = 30
}

# --- Networking ---

resource "aws_security_group" "alb" {
  name        = "${var.project}-kc-alb"
  description = "Keycloak ALB"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "keycloak" {
  name        = "${var.project}-kc"
  description = "Keycloak node: 8080 from the ALB only"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "db" {
  name        = "${var.project}-kc-db"
  description = "Keycloak PostgreSQL: 5432 from the Keycloak node only"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each          = toset(var.client_cidr_blocks)
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from users / SecurePAM frontend networks"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "alb_https_backend" {
  for_each                     = toset(var.backend_security_group_ids)
  security_group_id            = aws_security_group.alb.id
  description                  = "HTTPS from the SecurePAM backend (token validation + MFA sync)"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = each.value
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_redirect" {
  for_each          = toset(var.client_cidr_blocks)
  security_group_id = aws_security_group.alb.id
  description       = "HTTP, redirected to HTTPS"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "alb_to_kc" {
  security_group_id            = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.keycloak.id
}

resource "aws_vpc_security_group_ingress_rule" "kc_from_alb" {
  security_group_id            = aws_security_group.keycloak.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "kc_https" {
  security_group_id = aws_security_group.keycloak.id
  description       = "ECR, Secrets Manager, CloudWatch, SSM, package downloads"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "kc_to_db" {
  security_group_id            = aws_security_group.keycloak.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.db.id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_kc" {
  security_group_id            = aws_security_group.db.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.keycloak.id
}

# --- PostgreSQL (private, encrypted, backed up, RDS-managed master secret) ---

resource "aws_db_subnet_group" "kc" {
  name       = "${var.project}-kc"
  subnet_ids = var.private_subnet_ids
}

resource "aws_db_parameter_group" "kc" {
  name   = "${var.project}-kc-pg16"
  family = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "kc" {
  identifier                      = "${var.project}-kc"
  engine                          = "postgres"
  engine_version                  = var.postgres_version
  instance_class                  = var.db_instance_class
  allocated_storage               = var.db_storage_gb
  max_allocated_storage           = var.db_storage_gb * 4
  storage_type                    = "gp3"
  storage_encrypted               = true
  db_name                         = "keycloak"
  username                        = "keycloak"
  manage_master_user_password     = true
  db_subnet_group_name            = aws_db_subnet_group.kc.name
  vpc_security_group_ids          = [aws_security_group.db.id]
  parameter_group_name            = aws_db_parameter_group.kc.name
  publicly_accessible             = false
  multi_az                        = var.db_multi_az
  backup_retention_period         = var.db_backup_retention_days
  backup_window                   = "16:00-17:00"
  copy_tags_to_snapshot           = true
  deletion_protection             = true
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${var.project}-kc-final"
  auto_minor_version_upgrade      = true
  enabled_cloudwatch_logs_exports = ["postgresql"]
}

# --- IAM: node role ---

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "node" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "EcrPullKeycloakOnly"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [aws_ecr_repository.keycloak.arn]
  }
  statement {
    sid     = "ReadOnlyItsOwnSecrets"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_db_instance.kc.master_user_secret[0].secret_arn,
      aws_secretsmanager_secret.bootstrap_admin.arn,
    ]
  }
  statement {
    sid       = "ContainerLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.keycloak.arn}:*"]
  }
}

resource "aws_iam_role" "node" {
  name               = "${var.project}-kc-node"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy" "node" {
  name   = "${var.project}-kc-node"
  role   = aws_iam_role.node.id
  policy = data.aws_iam_policy_document.node.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "node" {
  name = "${var.project}-kc-node"
  role = aws_iam_role.node.name
}

# --- Keycloak node ---

resource "aws_cloudwatch_log_group" "keycloak" {
  name              = "/${var.project}/keycloak"
  retention_in_days = var.log_retention_days
}

resource "aws_instance" "keycloak" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = var.private_subnet_ids[0]
  vpc_security_group_ids      = [aws_security_group.keycloak.id]
  iam_instance_profile        = aws_iam_instance_profile.node.name
  associate_public_ip_address = false
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  root_block_device {
    encrypted   = true
    volume_size = 30
  }
  user_data = templatefile("${path.module}/user-data.sh", {
    aws_region       = var.aws_region
    image            = "${aws_ecr_repository.keycloak.repository_url}:${var.image_tag}"
    registry         = split("/", aws_ecr_repository.keycloak.repository_url)[0]
    db_host          = aws_db_instance.kc.address
    db_secret_arn    = aws_db_instance.kc.master_user_secret[0].secret_arn
    admin_secret_arn = aws_secretsmanager_secret.bootstrap_admin.arn
    hostname         = var.keycloak_hostname
    admin_hostname   = var.keycloak_admin_hostname
    log_group        = aws_cloudwatch_log_group.keycloak.name
  })
  user_data_replace_on_change = true
  tags                        = { Name = "${var.project}-keycloak" }
}

# --- ALB ---

resource "aws_lb" "kc" {
  name                       = "${var.project}-kc"
  internal                   = !var.public_alb
  load_balancer_type         = "application"
  subnets                    = var.public_alb ? var.public_subnet_ids : var.private_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}

resource "aws_lb_target_group" "kc" {
  name     = "${var.project}-kc"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  health_check {
    path                = "/health/ready"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
  stickiness {
    type    = "lb_cookie"
    enabled = true
  }
}

resource "aws_lb_target_group_attachment" "kc" {
  target_group_arn = aws_lb_target_group.kc.arn
  target_id        = aws_instance.keycloak.id
  port             = 8080
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.kc.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.kc.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.kc.arn
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

# Admin console + Admin REST only from admin networks (and the backend's NAT/egress CIDRs if the
# backend reaches the ALB from outside the VPC: add them to admin_cidr_blocks).
resource "aws_lb_listener_rule" "admin_allowed" {
  count        = length(var.admin_cidr_blocks) > 0 ? 1 : 0
  listener_arn = aws_lb_listener.https.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.kc.arn
  }
  condition {
    path_pattern {
      values = ["/admin/*"]
    }
  }
  condition {
    source_ip {
      values = var.admin_cidr_blocks
    }
  }
}

resource "aws_lb_listener_rule" "admin_denied" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 20
  action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Forbidden"
      status_code  = "403"
    }
  }
  condition {
    path_pattern {
      values = ["/admin/*", "/health*", "/metrics*"]
    }
  }
}

resource "aws_route53_record" "kc" {
  zone_id = var.route53_zone_id
  name    = var.keycloak_hostname
  type    = "A"
  alias {
    name                   = aws_lb.kc.dns_name
    zone_id                = aws_lb.kc.zone_id
    evaluate_target_health = true
  }
}

# --- Alarms ---

resource "aws_cloudwatch_metric_alarm" "kc_unhealthy" {
  alarm_name          = "${var.project}-keycloak-unhealthy"
  alarm_description   = "Keycloak target failed /health/ready."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  dimensions = {
    LoadBalancer = aws_lb.kc.arn_suffix
    TargetGroup  = aws_lb_target_group.kc.arn_suffix
  }
  alarm_actions = var.alarm_sns_topic_arn == "" ? [] : [var.alarm_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "kc_5xx" {
  alarm_name          = "${var.project}-keycloak-5xx"
  alarm_description   = "Keycloak returned 5xx responses."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { LoadBalancer = aws_lb.kc.arn_suffix }
  alarm_actions       = var.alarm_sns_topic_arn == "" ? [] : [var.alarm_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "db_storage" {
  alarm_name          = "${var.project}-keycloak-db-storage"
  alarm_description   = "Keycloak PostgreSQL free storage below 2 GiB."
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 2147483648
  comparison_operator = "LessThanThreshold"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.kc.identifier }
  alarm_actions       = var.alarm_sns_topic_arn == "" ? [] : [var.alarm_sns_topic_arn]
}
