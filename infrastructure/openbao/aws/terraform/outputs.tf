# SecurePAM OpenBao (production, AWS) — outputs.
# Nothing sensitive is output: token VALUES live only in Secrets Manager
# (written by provision) and in 0600 operator files.

output "bao_addr" {
  description = "OPENBAO_ADDR for the SecurePAM backend (TLS, verified with system CAs)."
  value       = "https://${var.dns_name}"
}

output "kms_seal_key_arn" {
  description = "KMS key backing auto-unseal."
  value       = aws_kms_key.seal.arn
}

output "app_token_secret_arn" {
  description = "Secrets Manager secret holding the backend app token (value set by provision)."
  value       = aws_secretsmanager_secret.app_token.arn
}

output "writer_token_secret_arn" {
  description = "Secrets Manager secret holding the credential-writer token (value set by provision)."
  value       = aws_secretsmanager_secret.writer_token.arn
}

output "instance_id" {
  description = "OpenBao EC2 instance (administer over SSM Session Manager; no SSH)."
  value       = aws_instance.bao.id
}

output "audit_log_group" {
  description = "CloudWatch log group receiving the OpenBao file audit device."
  value       = "/${var.project}/bao-audit"
}

output "instance_private_ip" {
  description = "Private address of the OpenBao listener (API + UI); target of the SSM port-forward."
  value       = aws_instance.bao.private_ip
}

output "root_escrow_secret_arn" {
  description = "Secrets Manager secret for the escrowed emergency root token (value set by provision)."
  value       = aws_secretsmanager_secret.root_escrow.arn
}

output "ui_port_forward_command" {
  description = "Open the OpenBao UI privately from a workstation (then browse https://<dns_name>:8200/ui with <dns_name> -> 127.0.0.1 in /etc/hosts)."
  value       = "aws ssm start-session --region ${var.aws_region} --target ${aws_instance.bao.id} --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters host=${aws_instance.bao.private_ip},portNumber=8200,localPortNumber=8200"
}
