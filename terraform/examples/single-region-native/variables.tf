variable "aws_region" {
  description = "AWS region to deploy the scanner"
  type        = string
  default     = "us-east-1"
}

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
  default     = "../../../build/qscanner-layer.zip"
}
