variable "stack_name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "qualys-lambda-scanner"
}

variable "qualys_secret_arn" {
  description = "ARN of existing Secrets Manager secret containing Qualys credentials (qualys_pod and qualys_access_token)"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.qualys_secret_arn))
    error_message = "Must be a valid Secrets Manager secret ARN"
  }
}

variable "qscanner_layer_zip" {
  description = "Path to QScanner Lambda Layer ZIP file"
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

variable "enable_scan_cache" {
  description = "Enable DynamoDB scan cache to prevent duplicate scans"
  type        = bool
  default     = true
}

variable "cache_ttl_days" {
  description = "Number of days to cache scan results"
  type        = number
  default     = 30

  validation {
    condition     = var.cache_ttl_days >= 1 && var.cache_ttl_days <= 365
    error_message = "Cache TTL must be between 1 and 365 days"
  }
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

variable "scanner_reserved_concurrency" {
  description = "Reserved concurrent executions for Scanner Lambda. Prevents runaway invocations during mass Lambda deployments. Set to -1 to disable (not recommended for enterprise)."
  type        = number
  default     = 10

  validation {
    condition     = var.scanner_reserved_concurrency == -1 || (var.scanner_reserved_concurrency >= 1 && var.scanner_reserved_concurrency <= 100)
    error_message = "Scanner reserved concurrency must be -1 (disabled) or between 1 and 100"
  }
}

variable "enable_access_logging" {
  description = "Enable S3 access logging for audit compliance (CIS Benchmark 3.6)"
  type        = bool
  default     = true
}

variable "enable_tagging" {
  description = "Enable AWS Lambda resource tagging with scan results (set to false if customer policy forbids Lambda tags)"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
