# SecurePAM OpenBao (production, AWS) — input variables.
#
# No secrets belong here. Tokens, passwords and keys are minted at provision
# time by provision/provision.py and stored in AWS Secrets Manager plus 0600
# operator files OUTSIDE this repository.

variable "project" {
  description = "Name prefix for all resources."
  type        = string
  default     = "securepam-bao"
}

variable "aws_region" {
  description = "Region for OpenBao, KMS, ACM/Route53 and the backend that calls it."
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "Existing VPC. Must have private subnets with egress (NAT) for package/plugin downloads."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for the instance and the internal NLB (min 2 AZs for the NLB)."
  type        = list(string)
}

variable "route53_zone_id" {
  description = "Hosted zone (private is fine) holding the A record clients resolve for dns_name."
  type        = string
}

variable "acme_public_zone_id" {
  description = "PUBLIC hosted zone for the same domain, used ONLY for the _acme-challenge TXT record (Let's Encrypt cannot query a private zone). Split-horizon: the A record stays private."
  type        = string
}

variable "dns_name" {
  description = "DNS name clients verify, under a domain you own, e.g. bao.ops.example.com (A record -> internal NLB)."
  type        = string
  validation {
    condition     = !can(regex("\\.(internal|local|lan|localdomain|home|corp)\\.?$", lower(var.dns_name)))
    error_message = "Let's Encrypt cannot issue for a non-public TLD such as .internal/.local. Use a name under a registered domain (the A record can still be private)."
  }
}

variable "allowed_backend_security_group_ids" {
  description = "Security groups of the SecurePAM backend hosts allowed to reach TCP 443 on the NLB."
  type        = list(string)
}

variable "allowed_admin_cidr_blocks" {
  description = "Admin networks (VPN/bastion) allowed to reach TCP 443 on the NLB for bao CLI work."
  type        = list(string)
  default     = []
}

variable "instance_type" {
  description = "Single-node sizing. t3.small is ample for a handful of KV reads per session launch."
  type        = string
  default     = "t3.small"
}

variable "ebs_size_gb" {
  description = "Encrypted EBS volume holding Raft data, TLS material and the file audit log."
  type        = number
  default     = 30
}

variable "openbao_version" {
  description = "Pinned OpenBao image/binary version. Bump deliberately; see aws/README.md upgrades."
  type        = string
  default     = "2.7.1"
}

variable "awskms_plugin_version" {
  description = "Pinned openbao-plugins release providing openbao-plugin-kms-awskms. Confirm the release asset name used in user-data.sh against the release page before apply."
  type        = string
  default     = "2.7.1"
}

variable "awskms_plugin_sha256" {
  description = "SHA-256 of the plugin tarball from the release page. REQUIRED: copy from the pinned release checksums."
  type        = string
  sensitive   = true
}

variable "certbot_email" {
  description = "Let's Encrypt account email for DNS-01 issuance (expiry notices only)."
  type        = string
}

variable "kms_deletion_window_days" {
  description = "Waiting period before a destroyed seal key is gone. 7 minimum, 30 recommended."
  type        = number
  default     = 30
}

variable "audit_log_retention_days" {
  description = "CloudWatch retention for the OpenBao audit log."
  type        = number
  default     = 365
}

variable "backup_time_utc" {
  description = "Daily EBS snapshot time (HH:MM, UTC) of the Raft volume."
  type        = string
  default     = "17:00"
}

variable "backup_retain_count" {
  description = "Number of daily Raft-volume snapshots to keep."
  type        = number
  default     = 14
}

variable "alarm_sns_topic_arn" {
  description = "Optional SNS topic for health alarms (empty = alarms without notifications)."
  type        = string
  default     = ""
}
