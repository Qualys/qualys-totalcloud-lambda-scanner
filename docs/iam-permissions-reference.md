# IAM Permissions Reference

This document describes the IAM permissions required by the Qualys Lambda Scanner. This reference can be used for:
- Understanding the security posture of the scanner
- Auditing permissions for compliance
- Future integration with the Qualys CSPM connector role

## Scanner Lambda Role Permissions

The scanner Lambda function requires the following permissions to operate.

### Core Lambda Scanning

| Permission | Resource | Purpose |
|------------|----------|---------|
| `lambda:GetFunction` | `arn:aws:lambda:*:ACCOUNT_ID:function:*` | **CRITICAL** - Retrieve function code for vulnerability scanning |
| `lambda:GetFunctionConfiguration` | `arn:aws:lambda:*:ACCOUNT_ID:function:*` | Get function metadata (runtime, memory, etc.) |

### Lambda Tagging (Optional)

| Permission | Resource | Purpose |
|------------|----------|---------|
| `lambda:TagResource` | `arn:aws:lambda:*:ACCOUNT_ID:function:*` | Tag functions with scan status (`QualysScanTimestamp`, `QualysScanStatus`) |

**Condition**: Restricted to tags matching `QualysScan*` pattern.

### Container Image Scanning (ECR)

Required for scanning Lambda functions that use container images.

| Permission | Resource | Purpose |
|------------|----------|---------|
| `ecr:GetAuthorizationToken` | `*` | Authenticate to ECR (must be `*` per AWS requirements) |
| `ecr:BatchCheckLayerAvailability` | `arn:aws:ecr:*:ACCOUNT_ID:repository/*` | Check if image layers exist |
| `ecr:GetDownloadUrlForLayer` | `arn:aws:ecr:*:ACCOUNT_ID:repository/*` | Get pre-signed URLs for layer download |
| `ecr:BatchGetImage` | `arn:aws:ecr:*:ACCOUNT_ID:repository/*` | Retrieve image manifests |
| `ecr:DescribeImages` | `arn:aws:ecr:*:ACCOUNT_ID:repository/*` | Get image metadata |

### Credentials Management

| Permission | Resource | Purpose |
|------------|----------|---------|
| `secretsmanager:GetSecretValue` | Specific secret ARN | Retrieve Qualys API credentials |

### Encryption (KMS)

| Permission | Resource | Purpose |
|------------|----------|---------|
| `kms:Decrypt` | Specific KMS key ARN | Decrypt secrets and cached data |
| `kms:GenerateDataKey` | Specific KMS key ARN | Encrypt data for storage |

### Results Storage (S3)

| Permission | Resource | Purpose |
|------------|----------|---------|
| `s3:PutObject` | `arn:aws:s3:::BUCKET_NAME/*` | Store scan results JSON |

### Notifications (SNS)

| Permission | Resource | Purpose |
|------------|----------|---------|
| `sns:Publish` | Specific SNS topic ARN | Publish scan completion notifications |

### Scan Caching (DynamoDB)

| Permission | Resource | Purpose |
|------------|----------|---------|
| `dynamodb:GetItem` | Specific table ARN | Check if function was recently scanned |
| `dynamodb:PutItem` | Specific table ARN | Store scan cache entry |

### Dead Letter Queue (SQS)

| Permission | Resource | Purpose |
|------------|----------|---------|
| `sqs:SendMessage` | Specific queue ARN | Send failed invocations to DLQ |

### Logging (CloudWatch)

| Permission | Resource | Purpose |
|------------|----------|---------|
| `logs:CreateLogStream` | Log group ARN | Create log streams |
| `logs:PutLogEvents` | Log group ARN | Write log entries |

### Custom Metrics (CloudWatch)

| Permission | Resource | Purpose |
|------------|----------|---------|
| `cloudwatch:PutMetricData` | `*` (with namespace condition) | Publish scan metrics |

**Condition**: Restricted to `QualysLambdaScanner` namespace.

### Tracing (X-Ray)

| Permission | Resource | Purpose |
|------------|----------|---------|
| `xray:PutTraceSegments` | `*` | Send trace data |
| `xray:PutTelemetryRecords` | `*` | Send telemetry data |

### Cross-Account Scanning (Hub-Spoke Only)

| Permission | Resource | Purpose |
|------------|----------|---------|
| `sts:AssumeRole` | `arn:aws:iam::*:role/qualys-lambda-scanner-spoke-role` | Assume role in spoke accounts |

**Condition**: When using OrganizationId, restricted via `aws:ResourceOrgID` condition.

---

## Comparison with Qualys CSPM Connector Role

The standard Qualys CSPM connector role uses the AWS `SecurityAudit` managed policy. Here's what's included vs what the Lambda scanner needs:

### What SecurityAudit Provides

| Permission | Included | Notes |
|------------|----------|-------|
| `lambda:GetFunctionConfiguration` | Yes | Metadata only |
| `lambda:List*` | Yes | List functions, versions, aliases |
| `lambda:GetPolicy` | Yes | Function policies |
| `ecr:DescribeImages` | Yes | Image metadata |
| `ecr:DescribeRepositories` | Yes | Repository metadata |
| `ecr:GetRepositoryPolicy` | Yes | Repository policies |
| `ecr:ListImages` | Yes | List images |

### What SecurityAudit Does NOT Provide (Required for Scanning)

| Permission | Purpose | Why Not Included |
|------------|---------|------------------|
| `lambda:GetFunction` | Download function code | SecurityAudit is for config audit, not code access |
| `lambda:TagResource` | Tag with scan results | SecurityAudit is read-only |
| `ecr:GetAuthorizationToken` | Authenticate to ECR | Not needed for config audit |
| `ecr:BatchGetImage` | Pull container images | Would allow downloading image content |
| `ecr:GetDownloadUrlForLayer` | Download image layers | Would allow downloading image content |

### Permissions to Add for Future CSPM Integration

If the Qualys CSPM connector role is extended to support Lambda scanning, these permissions would need to be added:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LambdaCodeAccess",
      "Effect": "Allow",
      "Action": "lambda:GetFunction",
      "Resource": "arn:aws:lambda:*:*:function:*"
    },
    {
      "Sid": "LambdaTagging",
      "Effect": "Allow",
      "Action": "lambda:TagResource",
      "Resource": "arn:aws:lambda:*:*:function:*",
      "Condition": {
        "ForAllValues:StringLike": {
          "aws:TagKeys": ["QualysScan*"]
        }
      }
    },
    {
      "Sid": "ECRImagePull",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ECRRepositoryAccess",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ],
      "Resource": "arn:aws:ecr:*:*:repository/*"
    }
  ]
}
```

---

## Security Considerations

### Least Privilege

All permissions are scoped to specific resources where possible:
- Lambda permissions limited to account's functions
- ECR permissions limited to account's repositories
- S3/SNS/DynamoDB/SQS limited to specific resources created by the stack
- CloudWatch metrics restricted by namespace condition
- Lambda tagging restricted to `QualysScan*` tag pattern

### Permissions Requiring Resource: "*"

Some permissions require `Resource: "*"` per AWS requirements:
- `ecr:GetAuthorizationToken` - AWS requirement for ECR authentication
- `cloudwatch:PutMetricData` - Restricted via namespace condition
- `xray:*` - Required for X-Ray tracing

### Cross-Account Security

For hub-spoke deployments:
- External ID required for role assumption (prevents confused deputy)
- Organization ID condition restricts role assumption to org accounts
- Spoke trust policy provides additional access control

---

## Complete IAM Policy

See the CloudFormation templates for the complete IAM policy:
- Single account: `cloudformation/single-account-native.yaml` (ScannerLambdaRole resource)
- Centralized hub: `cloudformation/centralized-hub.yaml` (ScannerLambdaRole resource)
- Terraform: `terraform/modules/scanner-native/main.tf` (aws_iam_role_policy.scanner_lambda resource)
