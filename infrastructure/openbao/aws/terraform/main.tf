# SecurePAM OpenBao on AWS — single private node.
#
# Traffic:  backend --TLS--> NLB:443 (TCP passthrough) --> instance:8200 (TLS,
# Let's Encrypt DNS-01 cert for var.dns_name). No public ingress anywhere;
# administration is over AWS SSM Session Manager, never SSH.
#
# Identity: the instance role may ONLY use the seal key + manage the
# _acme-challenge TXT record + write logs. It cannot read the SecurePAM
# tokens (those live in Secrets Manager for the operator/backend to fetch).

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
    values = ["al2023-ami-2023.*-x86_64"] # excludes the minimal AMI variant
  }
}

# --- KMS seal key (auto-unseal; also encrypts nothing else) ---

resource "aws_kms_key" "seal" {
  description             = "${var.project} OpenBao auto-unseal key"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true
}

resource "aws_kms_alias" "seal" {
  name          = "alias/${var.project}-bao-seal"
  target_key_id = aws_kms_key.seal.key_id
}

# --- Secrets Manager shells (values are written by provision/provision.py,
# --- never by Terraform, so no secret material lands in state) ---

resource "aws_secretsmanager_secret" "app_token" {
  name                    = "${var.project}/openbao/app-token"
  description             = "SecurePAM backend OpenBao app token (securepam-app policy). Written by provision."
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret" "writer_token" {
  name                    = "${var.project}/openbao/writer-token"
  description             = "Credential-writer token (securepam-writer policy). Operator runbook only."
  recovery_window_in_days = 30
}

# --- IAM: instance role (least privilege) ---

data "aws_iam_policy_document" "instance" {
  statement {
    sid    = "KmsSealUse"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.seal.arn]
  }
  # DNS-01 must be answered from PUBLIC DNS (Let's Encrypt cannot see a
  # private hosted zone), and only the _acme-challenge TXT record may change.
  statement {
    sid       = "LetsEncryptDns01"
    effect    = "Allow"
    actions   = ["route53:ChangeResourceRecordSets"]
    resources = ["arn:aws:route53:::hostedzone/${var.acme_public_zone_id}"]
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "route53:ChangeResourceRecordSetsNormalizedRecordNames"
      values   = ["_acme-challenge.${lower(trimsuffix(var.dns_name, "."))}"]
    }
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "route53:ChangeResourceRecordSetsRecordTypes"
      values   = ["TXT"]
    }
  }
  statement {
    sid       = "LetsEncryptZonesRead"
    effect    = "Allow"
    actions   = ["route53:ListHostedZones", "route53:GetChange"]
    resources = ["*"]
  }
  statement {
    sid    = "CloudWatchAuditLog"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:*:log-group:/${var.project}/bao-audit:*"]
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.project}-bao-instance"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

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

resource "aws_iam_role_policy" "instance" {
  name   = "${var.project}-bao-instance"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.project}-bao-instance"
  role = aws_iam_role.instance.name
}

# --- Security groups: nothing public, no SSH ---
# Rules are separate resources: inline rules referencing each other's group
# (bao <-> nlb) form a dependency cycle Terraform cannot create.

resource "aws_security_group" "bao" {
  name        = "${var.project}-bao"
  description = "OpenBao instance: 8200 from the NLB only"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "nlb" {
  name        = "${var.project}-nlb"
  description = "Internal NLB: 443 from SecurePAM backends and admin nets only"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "bao_from_nlb" {
  security_group_id            = aws_security_group.bao.id
  description                  = "NLB passthrough to OpenBao TLS listener"
  ip_protocol                  = "tcp"
  from_port                    = 8200
  to_port                      = 8200
  referenced_security_group_id = aws_security_group.nlb.id
}

resource "aws_vpc_security_group_egress_rule" "bao_https" {
  security_group_id = aws_security_group.bao.id
  description       = "Package/plugin/image downloads, Let's Encrypt, KMS, Route53, CloudWatch, SSM"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "nlb_from_backends" {
  for_each                     = toset(var.allowed_backend_security_group_ids)
  security_group_id            = aws_security_group.nlb.id
  description                  = "SecurePAM backends"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = each.value
}

resource "aws_vpc_security_group_ingress_rule" "nlb_from_admin" {
  for_each          = toset(var.allowed_admin_cidr_blocks)
  security_group_id = aws_security_group.nlb.id
  description       = "Admin network"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_bao" {
  security_group_id            = aws_security_group.nlb.id
  description                  = "To the OpenBao instance"
  ip_protocol                  = "tcp"
  from_port                    = 8200
  to_port                      = 8200
  referenced_security_group_id = aws_security_group.bao.id
}

# --- Internal NLB: pure TCP passthrough so TLS terminates on OpenBao ---

resource "aws_lb" "bao" {
  name               = "${var.project}-bao"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.private_subnet_ids
  security_groups    = [aws_security_group.nlb.id]
}

resource "aws_lb_target_group" "bao" {
  name        = "${var.project}-bao"
  port        = 8200
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    protocol = "TCP"
    port     = "8200"
  }
}

resource "aws_lb_listener" "bao" {
  load_balancer_arn = aws_lb.bao.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.bao.arn
  }
}

resource "aws_route53_record" "bao" {
  zone_id = var.route53_zone_id
  name    = var.dns_name
  type    = "A"

  alias {
    name                   = aws_lb.bao.dns_name
    zone_id                = aws_lb.bao.zone_id
    evaluate_target_health = true
  }
}

# --- EC2: private, IMDSv2 only, encrypted EBS for Raft/TLS/audit ---

resource "aws_ebs_volume" "data" {
  availability_zone = data.aws_subnet.first.availability_zone
  size              = var.ebs_size_gb
  type              = "gp3"
  encrypted         = true

  tags = { Name = "${var.project}-bao-data", SecurePamBackup = "${var.project}-raft" }
}

data "aws_subnet" "first" {
  id = var.private_subnet_ids[0]
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.bao.id
}

resource "aws_instance" "bao" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = var.private_subnet_ids[0]
  vpc_security_group_ids      = [aws_security_group.bao.id]
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  associate_public_ip_address = false
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2 only
  }
  root_block_device {
    encrypted = true
  }

  user_data = templatefile("${path.module}/user-data.sh", {
    aws_region            = var.aws_region
    openbao_version       = var.openbao_version
    awskms_plugin_version = var.awskms_plugin_version
    awskms_plugin_sha256  = var.awskms_plugin_sha256
    kms_key_id            = aws_kms_key.seal.arn
    dns_name              = var.dns_name
    certbot_email         = var.certbot_email
    project               = var.project
    data_volume_id        = aws_ebs_volume.data.id
    # Server template travels inside user-data; secrets never do (the
    # template carries none). Rendered on-host via envsubst for IMDS values.
    bao_config_b64 = base64encode(file("${path.module}/../bao-config.hcl"))
  })

  tags = { Name = "${var.project}-bao-1" }
}

resource "aws_lb_target_group_attachment" "bao" {
  target_group_arn = aws_lb_target_group.bao.arn
  target_id        = aws_instance.bao.id
  port             = 8200
}

# --- Durable audit log group (explicit retention instead of the agent's implicit group) ---

resource "aws_cloudwatch_log_group" "audit" {
  name              = "/${var.project}/bao-audit"
  retention_in_days = var.audit_log_retention_days
}

# --- Backups: encrypted EBS snapshots of the Raft volume, no token on the host ---
# Crash-consistent snapshots of the volume holding Raft data. Before upgrades also take an
# application-consistent `bao operator raft snapshot save` as the administrator (see docs).

data "aws_iam_policy_document" "dlm_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["dlm.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "dlm" {
  name               = "${var.project}-dlm"
  assume_role_policy = data.aws_iam_policy_document.dlm_assume.json
}

resource "aws_iam_role_policy_attachment" "dlm" {
  role       = aws_iam_role.dlm.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

resource "aws_dlm_lifecycle_policy" "raft" {
  description        = "${var.project} OpenBao Raft volume snapshots"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]
    target_tags    = { SecurePamBackup = "${var.project}-raft" }

    schedule {
      name      = "daily"
      copy_tags = true
      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = [var.backup_time_utc]
      }
      retain_rule {
        count = var.backup_retain_count
      }
    }
  }
}

# --- Emergency root-token escrow (value pushed by provision --escrow-root-arn, never by Terraform) ---

resource "aws_secretsmanager_secret" "root_escrow" {
  name                    = "${var.project}/openbao/root-token-escrow"
  description             = "Emergency OpenBao root token (break-glass). Written by provision; restrict reads to the custodians' role."
  recovery_window_in_days = 30
}

# --- Monitoring ---

resource "aws_cloudwatch_metric_alarm" "nlb_unhealthy" {
  alarm_name          = "${var.project}-bao-unhealthy-target"
  alarm_description   = "OpenBao target behind the internal NLB failed its health check (sealed, down, or TLS listener gone)."
  namespace           = "AWS/NetworkELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  dimensions = {
    LoadBalancer = aws_lb.bao.arn_suffix
    TargetGroup  = aws_lb_target_group.bao.arn_suffix
  }
  alarm_actions = var.alarm_sns_topic_arn == "" ? [] : [var.alarm_sns_topic_arn]
  ok_actions    = var.alarm_sns_topic_arn == "" ? [] : [var.alarm_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "instance_status" {
  alarm_name          = "${var.project}-bao-status-check"
  alarm_description   = "EC2 status check failed on the OpenBao node."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  dimensions          = { InstanceId = aws_instance.bao.id }
  alarm_actions       = var.alarm_sns_topic_arn == "" ? [] : [var.alarm_sns_topic_arn]
}
