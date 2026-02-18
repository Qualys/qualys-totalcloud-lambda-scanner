# Hub-Spoke Deployment with Org CloudTrail

This guide covers deploying the Qualys Lambda Scanner in a hub-spoke model using an existing organization CloudTrail (no new CloudTrails created in spoke accounts).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ Management Account (Org Root)                                       │
│ ┌─────────────────────────────────┐                                 │
│ │ Org CloudTrail (existing)       │                                 │
│ │           ↓                     │                                 │
│ │ org-cloudtrail-forwarder.yaml   │──────────┐                      │
│ │ (EventBridge rules)             │          │                      │
│ └─────────────────────────────────┘          │                      │
└──────────────────────────────────────────────│──────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Hub Account (Security/Tooling)                                      │
│ ┌─────────────────────────────────┐                                 │
│ │ centralized-hub.yaml            │                                 │
│ │ - Central EventBridge Bus    ←──│─── receives events              │
│ │ - Scanner Lambda                │                                 │
│ │ - Qualys credentials            │                                 │
│ │ - S3, DynamoDB, SNS, etc.       │                                 │
│ └─────────────────────────────────┘                                 │
│              │                                                      │
│              │ assumes spoke role to scan                           │
└──────────────│──────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ All Spoke Accounts (via StackSet)                                   │
│ ┌─────────────────────────────────┐                                 │
│ │ centralized-spoke-minimal.yaml  │                                 │
│ │ - IAM Role only                 │ ← hub assumes this to scan      │
│ │ - No CloudTrail                 │                                 │
│ └─────────────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Existing organization CloudTrail in management account
- AWS CLI configured with appropriate permissions
- Qualys subscription with TotalCloud
- Qualys Access Token

## Values to Track

| Value | Where it comes from | Used in |
|-------|---------------------|---------|
| `EXTERNAL_ID` | You generate it (Step 1) | Hub + Spoke StackSet |
| `HUB_ACCOUNT_ID` | Hub account's AWS account ID | Forwarder + Spoke StackSet |
| `ORG_ROOT` | `aws organizations list-roots` | Spoke StackSet |

## Deployment Steps

### Step 1: Deploy Hub (in Hub/Security Account)

Switch to hub account credentials first.

```bash
# Generate and SAVE the external ID (you'll need this for spokes)
export EXTERNAL_ID=$(openssl rand -hex 16)
echo "Save this EXTERNAL_ID: $EXTERNAL_ID"

# Set your Qualys token
export QUALYS_ACCESS_TOKEN="your-qualys-token"

# Deploy hub
make deploy-hub EXTERNAL_ID=$EXTERNAL_ID QUALYS_POD=US2 AWS_REGION=us-east-1
```

Note the hub account ID:
```bash
HUB_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Hub Account ID: $HUB_ACCOUNT_ID"
```

### Step 2: Deploy Org Forwarder (in Management Account)

Switch to management account credentials.

```bash
make deploy-org-forwarder \
  HUB_ACCOUNT_ID=<hub-account-id-from-step-1> \
  AWS_REGION=us-east-1
```

### Step 3: Deploy Minimal Spoke StackSet (from Management Account)

Still in management account.

```bash
# Get org root ID to deploy to entire org
ORG_ROOT=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
echo "Org Root: $ORG_ROOT"

# Deploy to all accounts in org, multiple regions
make deploy-spoke-minimal-stackset \
  ORG_UNIT_IDS=$ORG_ROOT \
  HUB_ACCOUNT_ID=<hub-account-id-from-step-1> \
  EXTERNAL_ID=<external-id-from-step-1> \
  REGIONS=us-east-1,us-west-2,ca-central-1
```

## Quick Reference

| Step | Account | Command |
|------|---------|---------|
| 1 | Hub | `make deploy-hub EXTERNAL_ID=xxx` |
| 2 | Management | `make deploy-org-forwarder HUB_ACCOUNT_ID=xxx` |
| 3 | Management | `make deploy-spoke-minimal-stackset ORG_UNIT_IDS=r-xxx HUB_ACCOUNT_ID=xxx EXTERNAL_ID=xxx` |

## Bulk Scanning

After deployment, run bulk scans from the hub account to scan all existing Lambda functions.

> **Note:** All commands below are AWS CloudShell compatible. They use `jq` for JSON filtering instead of JMESPath backticks which can cause issues in some shells.

### Scan All Accounts

```bash
# Get all account IDs in your org (CloudShell compatible)
ACCOUNT_IDS=$(aws organizations list-accounts --output json | jq -c '[.Accounts[] | select(.Status=="ACTIVE") | .Id]')

echo $ACCOUNT_IDS

# Create payload file
printf '{"account_ids": %s, "regions": ["us-east-1", "us-west-2", "ca-central-1"], "dry_run": false}' "$ACCOUNT_IDS" > /tmp/payload.json

# Invoke bulk scan async (avoids timeout)
aws lambda invoke \
  --function-name qualys-lambda-scanner-hub-bulk-scan \
  --invocation-type Event \
  --payload file:///tmp/payload.json \
  /tmp/output.json && echo "Bulk scan started in background"

# Watch progress
aws logs tail /aws/lambda/qualys-lambda-scanner-hub-bulk-scan --follow
```

### Dry Run First (Recommended)

See what would be scanned without actually scanning:

```bash
# Create dry run payload
printf '{"account_ids": %s, "regions": ["us-east-1", "us-west-2", "ca-central-1"], "dry_run": true}' "$ACCOUNT_IDS" > /tmp/payload.json

# Invoke async
aws lambda invoke \
  --function-name qualys-lambda-scanner-hub-bulk-scan \
  --invocation-type Event \
  --payload file:///tmp/payload.json \
  /tmp/output.json && echo "Dry run started"

# Watch logs for results
aws logs tail /aws/lambda/qualys-lambda-scanner-hub-bulk-scan --follow
```

### Scan Single Account

```bash
# Create payload for single account (replace with real account ID)
echo '{"account_ids": ["123456789012"], "regions": ["us-east-1"], "dry_run": false}' > /tmp/payload.json

# Invoke async
aws lambda invoke \
  --function-name qualys-lambda-scanner-hub-bulk-scan \
  --invocation-type Event \
  --payload file:///tmp/payload.json \
  /tmp/output.json && echo "Scan started"

# Watch logs
aws logs tail /aws/lambda/qualys-lambda-scanner-hub-bulk-scan --follow
```

### Quick One-Liner (All Accounts, All Regions)

CloudShell compatible - uses async invocation to avoid timeout:

```bash
# Step 1: Get account IDs
ACCOUNTS=$(aws organizations list-accounts --output json | jq -c '[.Accounts[] | select(.Status=="ACTIVE") | .Id]')

# Step 2: Invoke with the variable
aws lambda invoke \
  --function-name qualys-lambda-scanner-hub-bulk-scan \
  --invocation-type Event \
  --payload "{\"account_ids\": $ACCOUNTS, \"regions\": [\"us-east-1\",\"us-west-2\",\"ca-central-1\"]}" \
  --cli-binary-format raw-in-base64-out \
  /tmp/output.json && echo "Bulk scan started"
```

Or use a file to avoid all escaping issues:

```bash
# Step 1: Get accounts and build payload file
aws organizations list-accounts --output json | jq '{account_ids: [.Accounts[] | select(.Status=="ACTIVE") | .Id], regions: ["us-east-1","us-west-2","ca-central-1"]}' > /tmp/payload.json

# Step 2: Verify
cat /tmp/payload.json

# Step 3: Invoke
aws lambda invoke \
  --function-name qualys-lambda-scanner-hub-bulk-scan \
  --invocation-type Event \
  --payload file:///tmp/payload.json \
  /tmp/output.json && echo "Bulk scan started"
```

Then watch the logs:

```bash
aws logs tail /aws/lambda/qualys-lambda-scanner-hub-bulk-scan --follow
```

### Watch Progress

```bash
# Tail scanner logs
aws logs tail /aws/lambda/qualys-lambda-scanner-hub-scanner --follow

# Tail bulk scan logs
aws logs tail /aws/lambda/qualys-lambda-scanner-hub-bulk-scan --follow
```

## Bulk Scan Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `account_ids` | list | Account IDs to scan (default: hub account only) |
| `regions` | list | Regions to scan (default: `BulkScanDefaultRegions` or current region) |
| `dry_run` | bool | List functions without scanning |
| `exclude_patterns` | list | Additional function name patterns to skip |

## Event Flow

1. Lambda function created/updated in any spoke account
2. Org CloudTrail captures the event (management account)
3. EventBridge rule forwards event to hub's central bus
4. Hub's scanner Lambda receives the event
5. Scanner assumes spoke role in target account
6. Scanner downloads and scans the Lambda code
7. Results stored in S3, DynamoDB cache updated, SNS notification sent

## Troubleshooting

### Bulk Scan CLI Timeout

**Symptom:** `ReadTimeoutError` when invoking the bulk scan Lambda from the CLI.

**Cause:** The default `aws lambda invoke` uses synchronous (`RequestResponse`) invocation. The bulk scan Lambda can run for up to 15 minutes, but the CLI has a 60-second read timeout.

**Fix:** Always use `--invocation-type Event` for async invocation. Monitor progress via CloudWatch Logs instead.

### QScanner Cross-Account Failures (exit code 10, "no resource-based policy")

**Symptom:** QScanner fails with exit code 10 and errors like "no resource-based policy allows the lambda:GetFunction action" when scanning functions in spoke accounts.

**Cause:** The scanner Lambda assumes the spoke role and uses those credentials for the Python boto3 client. However, QScanner runs as a subprocess and inherits the Lambda's own execution role credentials from the environment, not the assumed spoke credentials. QScanner then attempts cross-account GetFunction calls with the wrong identity.

**Fix (applied in commit `6597bb5`):** The assumed spoke role credentials are now passed to the QScanner subprocess via `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` environment variables. This ensures QScanner operates with the spoke role's permissions.

**Verification:** After deploying the fix, scanner logs should show:
```
Passing assumed role credentials to QScanner for <function-name>
QScanner completed: function=<function-name> exit_code=0
```

### Cross-Region Scan Failures ("not reachable in this region")

**Symptom:** Scans fail for Lambda functions in regions other than the hub's region (e.g., hub is in us-east-1 but functions exist in us-west-2).

**Cause:** The scanner Lambda client and QScanner subprocess were not being configured with the target function's region. Both defaulted to the hub's own region.

**Fix (applied in commit `20359fe`):** The region is now extracted from the function ARN and passed to both the boto3 Lambda client and the QScanner `AWS_REGION` environment variable.

### Debugging Scan Failures

Check scanner logs with filtering:

```bash
# All errors
aws logs tail /aws/lambda/qualys-lambda-scanner-hub-scanner --since 1h \
  --filter-pattern "ERROR"

# Specific account
aws logs tail /aws/lambda/qualys-lambda-scanner-hub-scanner --since 1h \
  --filter-pattern "123456789012"

# Assume role issues
aws logs tail /aws/lambda/qualys-lambda-scanner-hub-scanner --since 1h \
  --filter-pattern "Failed to assume"

# Successful scans
aws logs tail /aws/lambda/qualys-lambda-scanner-hub-scanner --since 1h \
  --filter-pattern "Scan completed"
```

### Validating Cross-Account Role Setup

Before running bulk scans, verify the spoke role can be assumed from the hub account:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::SPOKE_ACCOUNT_ID:role/qualys-lambda-scanner-spoke-role \
  --role-session-name TestSession \
  --external-id YOUR_EXTERNAL_ID \
  --query 'AssumedRoleUser.Arn' --output text
```

Check that both the scanner and bulk scan Lambdas have the correct environment variables:

```bash
aws lambda get-function-configuration \
  --function-name qualys-lambda-scanner-hub-scanner \
  --query 'Environment.Variables.{ROLE: CROSS_ACCOUNT_ROLE_NAME, EXT_ID: SCANNER_EXTERNAL_ID}' \
  --output table
```

Verify the spoke role's trust policy references the correct hub account ID and external ID:

```bash
# Run in a spoke account
aws iam get-role \
  --role-name qualys-lambda-scanner-spoke-role \
  --query 'Role.AssumeRolePolicyDocument'
```

### Redeploying Code Fixes

After pulling code updates, redeploy the scanner Lambda:

```bash
git pull
make package
aws lambda update-function-code \
  --function-name qualys-lambda-scanner-hub-scanner \
  --zip-file fileb://build/scanner-function.zip
```

To also update the bulk scan Lambda:

```bash
aws lambda update-function-code \
  --function-name qualys-lambda-scanner-hub-bulk-scan \
  --zip-file fileb://build/bulk-scan.zip
```

## Cleanup

```bash
# Delete spoke StackSet (from management account)
aws cloudformation delete-stack-instances \
  --stack-set-name qualys-lambda-scanner-spoke-minimal-stackset \
  --deployment-targets OrganizationalUnitIds=r-xxxx \
  --regions us-east-1 us-west-2 ca-central-1 \
  --no-retain-stacks

# Wait for instances to delete, then:
aws cloudformation delete-stack-set \
  --stack-set-name qualys-lambda-scanner-spoke-minimal-stackset

# Delete org forwarder (from management account)
make delete-org-forwarder

# Delete hub (from hub account)
make delete-hub
make clean-all-hub
```
