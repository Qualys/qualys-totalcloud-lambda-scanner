output "scanner_lambda_arn" {
  description = "ARN of the Scanner Lambda function"
  value       = aws_lambda_function.scanner.arn
}

output "scanner_lambda_name" {
  description = "Name of the Scanner Lambda function"
  value       = aws_lambda_function.scanner.function_name
}

output "qscanner_layer_arn" {
  description = "ARN of the QScanner Lambda Layer"
  value       = aws_lambda_layer_version.qscanner.arn
}

output "qualys_secret_arn" {
  description = "ARN of the Qualys credentials secret"
  value       = aws_secretsmanager_secret.qualys_credentials.arn
}

output "scan_results_bucket_name" {
  description = "Name of the S3 bucket for scan results"
  value       = var.enable_s3_results ? aws_s3_bucket.scan_results[0].id : null
}

output "scan_results_bucket_arn" {
  description = "ARN of the S3 bucket for scan results"
  value       = var.enable_s3_results ? aws_s3_bucket.scan_results[0].arn : null
}

output "scan_notifications_topic_arn" {
  description = "ARN of the SNS topic for scan notifications"
  value       = var.enable_sns_notifications ? aws_sns_topic.scan_notifications[0].arn : null
}

output "scan_cache_table_name" {
  description = "Name of the DynamoDB scan cache table"
  value       = var.enable_scan_cache ? aws_dynamodb_table.scan_cache[0].name : null
}

output "scan_cache_table_arn" {
  description = "ARN of the DynamoDB scan cache table"
  value       = var.enable_scan_cache ? aws_dynamodb_table.scan_cache[0].arn : null
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  value       = aws_cloudtrail.main.name
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "cloudtrail_bucket_name" {
  description = "Name of the CloudTrail S3 bucket"
  value       = aws_s3_bucket.cloudtrail.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption"
  value       = aws_kms_key.scanner.arn
}

output "kms_key_id" {
  description = "ID of the KMS key used for encryption"
  value       = aws_kms_key.scanner.key_id
}

output "access_logs_bucket_name" {
  description = "Name of the S3 bucket for access logs"
  value       = var.enable_access_logging ? aws_s3_bucket.access_logs[0].id : null
}

output "access_logs_bucket_arn" {
  description = "ARN of the S3 bucket for access logs"
  value       = var.enable_access_logging ? aws_s3_bucket.access_logs[0].arn : null
}
