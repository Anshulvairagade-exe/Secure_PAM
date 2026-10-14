output "ecr_repository_url" {
  value = aws_ecr_repository.keycloak.repository_url
}
output "issuer_url" {
  description = "KEYCLOAK_URL for the SecurePAM backend/frontend (issuer = <this>/realms/securepam)."
  value       = "https://${var.keycloak_hostname}"
}
output "bootstrap_admin_secret_arn" {
  value = aws_secretsmanager_secret.bootstrap_admin.arn
}
output "audit_reader_secret_arn" {
  description = "Grant the SecurePAM backend read access to this secret only."
  value       = aws_secretsmanager_secret.audit_reader.arn
}
output "db_master_secret_arn" {
  description = "RDS-managed master secret (rotated by RDS; the node refreshes it hourly)."
  value       = aws_db_instance.kc.master_user_secret[0].secret_arn
}
output "instance_id" {
  value = aws_instance.keycloak.id
}
output "admin_port_forward_command" {
  description = "Private admin access without opening /admin: forward the node's 8080 to your Mac, then browse http://localhost:8080/admin/."
  value       = "aws ssm start-session --region ${var.aws_region} --target ${aws_instance.keycloak.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=8080,localPortNumber=8080"
}
