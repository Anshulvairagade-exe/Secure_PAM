# SecurePAM Keycloak (AWS) — inputs. No secret values belong here.

variable "project" {
  type    = string
  default = "securepam"
}
variable "aws_region" {
  type = string
}
variable "vpc_id" {
  type = string
}
variable "private_subnet_ids" {
  description = "Private subnets (2+ AZs) for the node, RDS and an internal ALB."
  type        = list(string)
}
variable "public_subnet_ids" {
  description = "Only used when public_alb = true."
  type        = list(string)
  default     = []
}
variable "public_alb" {
  description = "false (default): internal ALB reachable from the VPC/VPN only. true: internet-facing, /admin still restricted."
  type        = bool
  default     = false
}
variable "client_cidr_blocks" {
  description = "Networks whose users sign in (VPN / office / SecurePAM frontend users). Never 0.0.0.0/0 without review."
  type        = list(string)
}
variable "admin_cidr_blocks" {
  description = "Networks allowed to reach /admin/* (console + Admin REST, incl. the backend MFA sync egress)."
  type        = list(string)
  default     = []
}
variable "backend_security_group_ids" {
  description = "SecurePAM backend security groups allowed to reach the ALB on 443."
  type        = list(string)
  default     = []
}
variable "acm_certificate_arn" {
  description = "ACM certificate (DNS-validated) for keycloak_hostname."
  type        = string
}
variable "route53_zone_id" {
  type = string
}
variable "keycloak_hostname" {
  description = "Public/issuer hostname, e.g. auth.ops.example.com (tokens' iss = https://<this>/realms/securepam)."
  type        = string
}
variable "keycloak_admin_hostname" {
  description = "Optional separate hostname for the admin console (empty = same hostname, /admin restricted by CIDR)."
  type        = string
  default     = ""
}
variable "image_tag" {
  description = "Immutable tag pushed to the ECR repository (e.g. the git commit)."
  type        = string
}
variable "instance_type" {
  type    = string
  default = "t3.medium"
}
variable "postgres_version" {
  type    = string
  default = "16.4"
}
variable "db_instance_class" {
  type    = string
  default = "db.t4g.small"
}
variable "db_storage_gb" {
  type    = number
  default = 20
}
variable "db_multi_az" {
  type    = bool
  default = false
}
variable "db_backup_retention_days" {
  type    = number
  default = 14
  validation {
    condition     = var.db_backup_retention_days >= 7
    error_message = "Keep at least 7 days of automated backups."
  }
}
variable "log_retention_days" {
  type    = number
  default = 90
}
variable "alarm_sns_topic_arn" {
  type    = string
  default = ""
}
