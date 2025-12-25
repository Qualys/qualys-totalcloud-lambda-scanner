terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

# Example: Deploy scanner in multiple regions using native Terraform module
#
# Prerequisites:
# 1. Create Qualys credentials secret in each region (or replicate from primary)
# 2. Build and upload QScanner layer ZIP to each region

variable "primary_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "qualys_secret_arn_map" {
  description = "Map of region to Qualys Secrets Manager secret ARN"
  type        = map(string)
  # Example:
  # {
  #   "us-east-1" = "arn:aws:secretsmanager:us-east-1:123456789012:secret:qualys-creds-abc123"
  #   "us-west-2" = "arn:aws:secretsmanager:us-west-2:123456789012:secret:qualys-creds-def456"
  # }
}

variable "qscanner_layer_zip_map" {
  description = "Map of region to QScanner layer ZIP path"
  type        = map(string)
  # Example:
  # {
  #   "us-east-1" = "../../../build/qscanner-layer.zip"
  #   "us-west-2" = "../../../build/qscanner-layer.zip"
  # }
}

# Configure providers for each region
provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us-west-2"
  region = "us-west-2"
}

# Deploy scanner in us-east-1
module "scanner_us_east_1" {
  source = "../../modules/scanner-native"
  count  = contains(keys(var.qualys_secret_arn_map), "us-east-1") ? 1 : 0

  providers = {
    aws = aws.us-east-1
  }

  stack_name        = "qualys-lambda-scanner"
  qualys_secret_arn = var.qualys_secret_arn_map["us-east-1"]
  qscanner_layer_zip = var.qscanner_layer_zip_map["us-east-1"]

  enable_s3_results        = true
  enable_sns_notifications = true
  enable_scan_cache        = true

  tags = {
    Environment = "production"
    Application = "qualys-lambda-scanner"
    Region      = "us-east-1"
  }
}

# Deploy scanner in us-west-2
module "scanner_us_west_2" {
  source = "../../modules/scanner-native"
  count  = contains(keys(var.qualys_secret_arn_map), "us-west-2") ? 1 : 0

  providers = {
    aws = aws.us-west-2
  }

  stack_name        = "qualys-lambda-scanner"
  qualys_secret_arn = var.qualys_secret_arn_map["us-west-2"]
  qscanner_layer_zip = var.qscanner_layer_zip_map["us-west-2"]

  enable_s3_results        = true
  enable_sns_notifications = true
  enable_scan_cache        = true

  tags = {
    Environment = "production"
    Application = "qualys-lambda-scanner"
    Region      = "us-west-2"
  }
}

# Outputs
output "scanner_deployments" {
  description = "Scanner Lambda ARNs by region"
  value = {
    us-east-1 = try(module.scanner_us_east_1[0].scanner_lambda_arn, null)
    us-west-2 = try(module.scanner_us_west_2[0].scanner_lambda_arn, null)
  }
}

output "scan_results_buckets" {
  description = "S3 buckets for scan results by region"
  value = {
    us-east-1 = try(module.scanner_us_east_1[0].scan_results_bucket_name, null)
    us-west-2 = try(module.scanner_us_west_2[0].scan_results_bucket_name, null)
  }
}
