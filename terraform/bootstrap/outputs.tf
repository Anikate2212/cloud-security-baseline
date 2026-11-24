output "state_bucket" {
  description = "Pass this to the main stack: terraform init -backend-config=\"bucket=<value>\""
  value       = aws_s3_bucket.tf_state.id
}
