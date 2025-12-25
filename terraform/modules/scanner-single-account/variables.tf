variable "region" {
  description = "AWS region where the scanner will be deployed"
  type        = string
}

variable "stack_name" {
  description = "CloudFormation stack name. If empty, will be auto-generated"
  type        = string
  default     = ""
}

variable "qualys_secret_arn" {
  description = "ARN of existing Secrets Manager secret containing Qualys credentials (qualys_pod and qualys_access_token)"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.qualys_secret_arn))
    error_message = "Must be a valid Secrets Manager secret ARN"
  }
}

variable "qscanner_layer_arn" {
  description = "ARN of the QScanner Lambda Layer"
  type        = string
}

variable "lambda_code_bucket" {
  description = "S3 bucket containing Lambda function code"
  type        = string
}

variable "lambda_code_key" {
  description = "S3 key for Lambda function code ZIP"
  type        = string
}

variable "enable_s3_results" {
  description = "Create S3 bucket for storing scan results"
  type        = bool
  default     = true
}

variable "enable_sns_notifications" {
  description = "Create SNS topic for scan notifications"
  type        = bool
  default     = true
}

variable "scanner_memory_size" {
  description = "Memory size for Scanner Lambda in MB"
  type        = number
  default     = 2048

  validation {
    condition     = var.scanner_memory_size >= 512 && var.scanner_memory_size <= 10240
    error_message = "Scanner memory size must be between 512 and 10240 MB"
  }
}

variable "scanner_timeout" {
  description = "Timeout for Scanner Lambda in seconds"
  type        = number
  default     = 900

  validation {
    condition     = var.scanner_timeout >= 60 && var.scanner_timeout <= 900
    error_message = "Scanner timeout must be between 60 and 900 seconds"
  }
}

variable "scanner_ephemeral_storage" {
  description = "Ephemeral storage for Scanner Lambda in MB"
  type        = number
  default     = 2048

  validation {
    condition     = var.scanner_ephemeral_storage >= 512 && var.scanner_ephemeral_storage <= 10240
    error_message = "Scanner ephemeral storage must be between 512 and 10240 MB"
  }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
