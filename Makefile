.PHONY: help layer package deploy deploy-multi-region clean deploy-stackset deploy-hub deploy-spoke \
       delete delete-hub delete-stackset delete-spoke-stackset \
       delete-bucket delete-buckets delete-artifacts-bucket delete-secret delete-layers \
       delete-dynamodb delete-dlq delete-sns delete-log-groups delete-alarms delete-eventbridge-rules delete-kms-key \
       clean-all clean-all-hub clean-all-stackset clean-dry-run clean-all-resources

# Variables
AWS_REGION ?= us-east-1
STACK_NAME ?= qualys-lambda-scanner
QUALYS_POD ?= US2
LAYER_NAME ?= qscanner
S3_BUCKET ?= $(STACK_NAME)-artifacts-$(shell aws sts get-caller-identity --query Account --output text)
QUALYS_ACCESS_TOKEN ?= $(shell echo $$QUALYS_ACCESS_TOKEN)

# Tagging variable (optional - defaults to true)
TAG ?= true

# Cross-account security
EXTERNAL_ID ?= $(shell openssl rand -hex 16)

# StackSet/Organization variables
ORG_ID ?= $(shell aws organizations describe-organization --query 'Organization.Id' --output text 2>/dev/null)
ORG_UNIT_IDS ?=
ADMIN_ACCOUNT_ID ?= $(shell aws sts get-caller-identity --query Account --output text)

help:
	@echo "Qualys Lambda Scanner - Makefile"
	@echo ""
	@echo "=== Single Account Deployment ==="
	@echo "  deploy               - Deploy scanner to single region"
	@echo "  deploy-multi-region  - Deploy scanner to multiple regions"
	@echo "  update-function      - Update Lambda function code only"
	@echo "  delete               - Delete single-account CloudFormation stack"
	@echo ""
	@echo "=== Multi-Account StackSet Deployment ==="
	@echo "  deploy-stackset      - Deploy StackSet to organization OUs"
	@echo "  delete-stackset      - Delete StackSet from organization"
	@echo ""
	@echo "=== Centralized Hub-Spoke Deployment ==="
	@echo "  deploy-hub           - Deploy hub scanner in security account"
	@echo "  deploy-spoke-stackset - Deploy spoke template via StackSet"
	@echo "  delete-hub           - Delete hub stack"
	@echo "  delete-spoke-stackset - Delete spoke StackSet"
	@echo ""
	@echo "=== Build ==="
	@echo "  layer                - Build QScanner Lambda Layer"
	@echo "  package              - Package Lambda function code"
	@echo ""
	@echo "=== Cleanup (IMPORTANT) ==="
	@echo "  clean                - Clean local build artifacts only"
	@echo "  clean-dry-run        - Show what AWS resources would be deleted"
	@echo "  clean-all            - FULL cleanup: stack, buckets, secret, layers (single-account)"
	@echo "  clean-all-hub        - FULL cleanup for hub-spoke deployment"
	@echo "  clean-all-stackset   - FULL cleanup for StackSet deployment"
	@echo ""
	@echo "=== Individual Resource Cleanup ==="
	@echo "  delete-buckets       - Delete all S3 buckets for this stack"
	@echo "  delete-secret        - Delete Secrets Manager secret"
	@echo "  delete-layers        - Delete all Lambda layer versions"
	@echo "  delete-bucket        - Delete specific bucket (BUCKET_NAME=xxx)"
	@echo "  delete-artifacts-bucket - Delete cross-account artifacts bucket"
	@echo "  delete-dynamodb      - Delete DynamoDB scan cache table"
	@echo "  delete-dlq           - Delete SQS Dead Letter Queue"
	@echo "  delete-sns           - Delete SNS notification topic"
	@echo "  delete-log-groups    - Delete CloudWatch Log Groups"
	@echo "  delete-alarms        - Delete CloudWatch Alarms"
	@echo "  delete-eventbridge-rules - Delete EventBridge Rules"
	@echo "  delete-kms-key       - Schedule KMS key for deletion"
	@echo ""
	@echo "Variables:"
	@echo "  AWS_REGION           - AWS region (default: us-east-1)"
	@echo "  STACK_NAME           - CloudFormation stack name (default: qualys-lambda-scanner)"
	@echo "  QUALYS_POD           - Qualys POD (default: US2)"
	@echo "  QUALYS_ACCESS_TOKEN  - Qualys access token (required, or set env var)"
	@echo "  ORG_UNIT_IDS         - Comma-separated OU IDs for StackSet deployment"
	@echo "  TAG                  - Enable Lambda resource tagging (true/false, default: true)"
	@echo "  LAYER_NAME           - Lambda layer name (default: qscanner)"
	@echo ""
	@echo "Examples:"
	@echo "  make deploy QUALYS_POD=US2 AWS_REGION=us-east-1"
	@echo "  make deploy TAG=false  # Disable Lambda tagging"
	@echo "  make deploy-hub"
	@echo "  make deploy-stackset ORG_UNIT_IDS=ou-xxxx"
	@echo ""
	@echo "Cleanup Examples:"
	@echo "  make clean-dry-run                    # Preview what will be deleted"
	@echo "  make clean-all                        # Full cleanup (single-account)"
	@echo "  make clean-all-hub ORG_UNIT_IDS=ou-xxxx  # Full hub-spoke cleanup"
	@echo "  make delete-bucket BUCKET_NAME=my-bucket # Delete specific bucket"

# =============================================================================
# Build Targets
# =============================================================================

# Build Lambda Layer with QScanner binary
layer:
	@echo "Building QScanner Lambda Layer..."
	@if [ ! -f scanner-lambda/qscanner.gz ]; then \
		echo "ERROR: qscanner.gz not found in scanner-lambda/"; \
		echo "Please download QScanner and place it in scanner-lambda/qscanner.gz"; \
		exit 1; \
	fi
	@mkdir -p build/layer/bin
	@gunzip -c scanner-lambda/qscanner.gz > build/layer/bin/qscanner
	@chmod +x build/layer/bin/qscanner
	@cd build/layer && zip -r ../qscanner-layer.zip .
	@echo "Layer created: build/qscanner-layer.zip"
	@du -h build/qscanner-layer.zip

# Package Lambda function code
package:
	@echo "Packaging Lambda function code..."
	@mkdir -p build/function build/bulk-scan
	@cp scanner-lambda/lambda_function.py build/function/
	@cp scanner-lambda/bulk_scan.py build/bulk-scan/
	@cd build/function && zip -r ../scanner-function.zip .
	@cd build/bulk-scan && zip -r ../bulk-scan.zip .
	@echo "Function packages created: build/scanner-function.zip, build/bulk-scan.zip"

# Publish Lambda Layer to AWS
publish-layer: layer
	@echo "Publishing Lambda Layer to AWS..."
	@aws lambda publish-layer-version \
		--layer-name $(LAYER_NAME) \
		--description "Qualys QScanner binary" \
		--zip-file fileb://build/qscanner-layer.zip \
		--compatible-runtimes python3.11 python3.12 \
		--region $(AWS_REGION) \
		--query 'LayerVersionArn' \
		--output text > build/layer-arn.txt
	@echo "Layer published: $$(cat build/layer-arn.txt)"

# Create S3 bucket for Lambda artifacts
create-bucket:
	@echo "Creating S3 bucket for artifacts..."
	@aws s3 mb s3://$(S3_BUCKET) --region $(AWS_REGION) 2>/dev/null || true

# Upload Lambda function code to S3
upload-function: package create-bucket
	@echo "Uploading Lambda function code to S3..."
	@aws s3 cp build/scanner-function.zip s3://$(S3_BUCKET)/scanner-function.zip
	@aws s3 cp build/bulk-scan.zip s3://$(S3_BUCKET)/bulk-scan.zip
	@echo "Function code uploaded to s3://$(S3_BUCKET)/"

# Create Secrets Manager secret
create-secret:
	@echo "Creating Secrets Manager secret..."
	@if [ -z "$(QUALYS_ACCESS_TOKEN)" ]; then \
		echo "ERROR: QUALYS_ACCESS_TOKEN environment variable not set"; \
		exit 1; \
	fi
	@mkdir -p build
	@SECRET_JSON='{"qualys_pod":"$(QUALYS_POD)","qualys_access_token":"$(QUALYS_ACCESS_TOKEN)"}'; \
	SECRET_ARN=$$(aws secretsmanager create-secret \
		--name "$(STACK_NAME)-qualys-credentials" \
		--description "Qualys credentials for Lambda scanner" \
		--secret-string "$$SECRET_JSON" \
		--region $(AWS_REGION) \
		--query ARN \
		--output text 2>/dev/null || \
		aws secretsmanager describe-secret \
		--secret-id "$(STACK_NAME)-qualys-credentials" \
		--region $(AWS_REGION) \
		--query ARN \
		--output text); \
	echo $$SECRET_ARN > build/secret-arn.txt
	@echo "Secret ARN: $$(cat build/secret-arn.txt)"

# =============================================================================
# Single Account Deployment
# =============================================================================

# Deploy to single account/region
deploy: publish-layer upload-function create-secret
	@echo "Deploying CloudFormation stack..."
	@aws cloudformation deploy \
		--template-file cloudformation/single-account-native.yaml \
		--stack-name $(STACK_NAME) \
		--parameter-overrides \
			QualysPod=$(QUALYS_POD) \
			QualysSecretArn=$$(cat build/secret-arn.txt) \
			QScannerLayerArn=$$(cat build/layer-arn.txt) \
			LambdaCodeBucket=$(S3_BUCKET) \
			LambdaCodeKey=scanner-function.zip \
			BulkScanCodeKey=bulk-scan.zip \
			EnableTagging=$(TAG) \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION)
	@echo "Deployment complete!"
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--query 'Stacks[0].Outputs' \
		--region $(AWS_REGION)

# Update Lambda function code only
update-function: upload-function
	@echo "Updating Lambda function code..."
	@aws lambda update-function-code \
		--function-name $(STACK_NAME)-scanner \
		--s3-bucket $(S3_BUCKET) \
		--s3-key scanner-function.zip \
		--region $(AWS_REGION)
	@echo "Function code updated"

# Deploy to multiple regions
deploy-multi-region:
	@echo "Deploying to multiple regions..."
	@for region in us-east-1 us-west-2 eu-west-1; do \
		echo "Deploying to $$region..."; \
		$(MAKE) deploy AWS_REGION=$$region STACK_NAME=$(STACK_NAME)-$$region; \
	done

# Delete single-account stack
delete:
	@echo "Deleting CloudFormation stack..."
	@aws cloudformation delete-stack \
		--stack-name $(STACK_NAME) \
		--region $(AWS_REGION)
	@echo "Waiting for stack deletion..."
	@aws cloudformation wait stack-delete-complete \
		--stack-name $(STACK_NAME) \
		--region $(AWS_REGION)
	@echo "Stack deleted"

# =============================================================================
# Multi-Account StackSet Deployment
# =============================================================================

# Create S3 bucket with org-wide read access for artifact distribution
create-artifacts-bucket:
	@echo "Creating artifacts bucket for cross-account distribution..."
	@mkdir -p build
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	BUCKET_NAME=qualys-scanner-artifacts-$$ACCOUNT_ID; \
	aws s3 mb s3://$$BUCKET_NAME --region $(AWS_REGION) 2>/dev/null || true; \
	if [ -n "$(ORG_ID)" ] && [ "$(ORG_ID)" != "None" ]; then \
		echo "Applying org-wide bucket policy for $(ORG_ID)..."; \
		aws s3api put-bucket-policy --bucket $$BUCKET_NAME --policy '{"Version":"2012-10-17","Statement":[{"Sid":"AllowOrgAccess","Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::'$$BUCKET_NAME'/*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"$(ORG_ID)"}}}]}'; \
	else \
		echo "No ORG_ID provided - skipping org-wide bucket policy (single account mode)"; \
	fi; \
	echo $$BUCKET_NAME > build/artifacts-bucket.txt
	@echo "Artifacts bucket: $$(cat build/artifacts-bucket.txt)"

# Upload Lambda artifacts to S3 for cross-account access
upload-artifacts: layer package create-artifacts-bucket
	@echo "Uploading artifacts to S3..."
	@BUCKET=$$(cat build/artifacts-bucket.txt); \
	aws s3 cp build/qscanner-layer.zip s3://$$BUCKET/qualys-lambda-scanner/qscanner-layer.zip; \
	aws s3 cp build/scanner-function.zip s3://$$BUCKET/qualys-lambda-scanner/lambda-code.zip; \
	aws s3 cp build/bulk-scan.zip s3://$$BUCKET/qualys-lambda-scanner/bulk-scan.zip
	@echo "Artifacts uploaded to s3://$$BUCKET/qualys-lambda-scanner/"

# Deploy StackSet to organization (each account gets own scanner)
deploy-stackset: upload-artifacts
	@echo "Deploying StackSet to organization..."
	@if [ -z "$(QUALYS_ACCESS_TOKEN)" ]; then \
		echo "ERROR: QUALYS_ACCESS_TOKEN environment variable not set"; \
		exit 1; \
	fi
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "ERROR: ORG_UNIT_IDS not set."; \
		echo "Usage: make deploy-stackset ORG_UNIT_IDS=ou-xxxx-xxxxxxxx"; \
		exit 1; \
	fi
	@BUCKET=$$(cat build/artifacts-bucket.txt); \
	aws cloudformation create-stack-set \
		--stack-set-name $(STACK_NAME)-stackset \
		--template-body file://cloudformation/stackset.yaml \
		--parameters \
			ParameterKey=QualysPod,ParameterValue=$(QUALYS_POD) \
			ParameterKey=QualysAccessToken,ParameterValue=$(QUALYS_ACCESS_TOKEN) \
			ParameterKey=ArtifactsBucket,ParameterValue=$$BUCKET \
			ParameterKey=EnableTagging,ParameterValue=$(TAG) \
		--capabilities CAPABILITY_NAMED_IAM \
		--permission-model SERVICE_MANAGED \
		--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
		--region $(AWS_REGION) 2>/dev/null || \
		aws cloudformation update-stack-set \
			--stack-set-name $(STACK_NAME)-stackset \
			--template-body file://cloudformation/stackset.yaml \
			--parameters \
				ParameterKey=QualysPod,ParameterValue=$(QUALYS_POD) \
				ParameterKey=QualysAccessToken,ParameterValue=$(QUALYS_ACCESS_TOKEN) \
				ParameterKey=ArtifactsBucket,ParameterValue=$$BUCKET \
				ParameterKey=EnableTagging,ParameterValue=$(TAG) \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION)
	@echo "Creating stack instances in OUs: $(ORG_UNIT_IDS)..."
	@aws cloudformation create-stack-instances \
		--stack-set-name $(STACK_NAME)-stackset \
		--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
		--regions $(AWS_REGION) \
		--operation-preferences FailureTolerancePercentage=10,MaxConcurrentPercentage=25 \
		--region $(AWS_REGION)
	@echo ""
	@echo "StackSet deployment initiated!"
	@echo "Monitor: aws cloudformation list-stack-instances --stack-set-name $(STACK_NAME)-stackset --region $(AWS_REGION)"

# Delete StackSet
delete-stackset:
	@echo "Deleting StackSet instances..."
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "ERROR: ORG_UNIT_IDS required to delete instances"; \
		exit 1; \
	fi
	@aws cloudformation delete-stack-instances \
		--stack-set-name $(STACK_NAME)-stackset \
		--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
		--regions $(AWS_REGION) \
		--no-retain-stacks \
		--region $(AWS_REGION) || true
	@echo "Waiting for instances to be deleted (60s)..."
	@sleep 60
	@aws cloudformation delete-stack-set \
		--stack-set-name $(STACK_NAME)-stackset \
		--region $(AWS_REGION)
	@echo "StackSet deleted"

# =============================================================================
# Centralized Hub-Spoke Deployment
# =============================================================================

# Deploy hub scanner in security/central account
deploy-hub: upload-artifacts
	@echo "Deploying centralized hub scanner..."
	@if [ -z "$(QUALYS_ACCESS_TOKEN)" ]; then \
		echo "ERROR: QUALYS_ACCESS_TOKEN environment variable not set"; \
		exit 1; \
	fi
	@BUCKET=$$(cat build/artifacts-bucket.txt); \
	aws cloudformation deploy \
		--template-file cloudformation/centralized-hub.yaml \
		--stack-name $(STACK_NAME)-hub \
		--parameter-overrides \
			QualysPod=$(QUALYS_POD) \
			QualysAccessToken=$(QUALYS_ACCESS_TOKEN) \
			ArtifactsBucket=$$BUCKET \
			OrganizationId=$(ORG_ID) \
			ScannerExternalId=$(EXTERNAL_ID) \
			EnableTagging=$(TAG) \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION)
	@echo ""
	@echo "Hub deployment complete!"
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-hub \
		--query 'Stacks[0].Outputs' \
		--region $(AWS_REGION) \
		--output table
	@# Save outputs for spoke deployment
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-hub \
		--query "Stacks[0].Outputs[?OutputKey=='CentralEventBusArn'].OutputValue" \
		--output text \
		--region $(AWS_REGION) > build/central-bus-arn.txt
	@echo ""
	@echo "Next: make deploy-spoke-stackset ORG_UNIT_IDS=ou-xxxx-xxxxxxxx"

# Deploy spoke template via StackSet to member accounts
deploy-spoke-stackset:
	@echo "Deploying spoke StackSet to member accounts..."
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "ERROR: ORG_UNIT_IDS required"; \
		exit 1; \
	fi
	@if [ ! -f build/central-bus-arn.txt ]; then \
		echo "ERROR: Deploy hub first: make deploy-hub"; \
		exit 1; \
	fi
	@SECURITY_ACCT=$$(aws sts get-caller-identity --query Account --output text); \
	CENTRAL_BUS_ARN=$$(cat build/central-bus-arn.txt); \
	CENTRAL_BUS_NAME=$$(echo $$CENTRAL_BUS_ARN | awk -F'/' '{print $$NF}'); \
	aws cloudformation create-stack-set \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--template-body file://cloudformation/centralized-spoke.yaml \
		--parameters \
			ParameterKey=SecurityAccountId,ParameterValue=$$SECURITY_ACCT \
			ParameterKey=CentralEventBusName,ParameterValue=$$CENTRAL_BUS_NAME \
			ParameterKey=CentralEventBusArn,ParameterValue=$$CENTRAL_BUS_ARN \
		--capabilities CAPABILITY_NAMED_IAM \
		--permission-model SERVICE_MANAGED \
		--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
		--region $(AWS_REGION) 2>/dev/null || \
		aws cloudformation update-stack-set \
			--stack-set-name $(STACK_NAME)-spoke-stackset \
			--template-body file://cloudformation/centralized-spoke.yaml \
			--parameters \
				ParameterKey=SecurityAccountId,ParameterValue=$$SECURITY_ACCT \
				ParameterKey=CentralEventBusName,ParameterValue=$$CENTRAL_BUS_NAME \
				ParameterKey=CentralEventBusArn,ParameterValue=$$CENTRAL_BUS_ARN \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION)
	@echo "Creating spoke instances in OUs: $(ORG_UNIT_IDS)..."
	@aws cloudformation create-stack-instances \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
		--regions $(AWS_REGION) \
		--operation-preferences FailureTolerancePercentage=10,MaxConcurrentPercentage=25 \
		--region $(AWS_REGION)
	@echo ""
	@echo "Spoke StackSet deployment initiated!"

# Delete spoke StackSet
delete-spoke-stackset:
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "ERROR: ORG_UNIT_IDS required"; \
		exit 1; \
	fi
	@aws cloudformation delete-stack-instances \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
		--regions $(AWS_REGION) \
		--no-retain-stacks \
		--region $(AWS_REGION) || true
	@sleep 60
	@aws cloudformation delete-stack-set \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--region $(AWS_REGION)
	@echo "Spoke StackSet deleted"

# Delete hub
delete-hub:
	@aws cloudformation delete-stack \
		--stack-name $(STACK_NAME)-hub \
		--region $(AWS_REGION)
	@aws cloudformation wait stack-delete-complete \
		--stack-name $(STACK_NAME)-hub \
		--region $(AWS_REGION)
	@echo "Hub deleted"

# =============================================================================
# Cleanup & Utilities
# =============================================================================

# Clean local build artifacts only
clean:
	@rm -rf build/
	@echo "Build artifacts cleaned"

# Delete S3 bucket contents and bucket (handles versioned objects)
# Usage: make delete-bucket BUCKET_NAME=my-bucket
delete-bucket:
	@if [ -z "$(BUCKET_NAME)" ]; then \
		echo "ERROR: BUCKET_NAME required"; \
		echo "Usage: make delete-bucket BUCKET_NAME=my-bucket"; \
		exit 1; \
	fi
	@echo "Emptying bucket $(BUCKET_NAME)..."
	@aws s3api list-object-versions --bucket $(BUCKET_NAME) --query 'Versions[].{Key:Key,VersionId:VersionId}' --output json 2>/dev/null | \
		jq -c 'select(. != null) | .[] | select(. != null)' | \
		while read obj; do \
			key=$$(echo $$obj | jq -r '.Key'); \
			vid=$$(echo $$obj | jq -r '.VersionId'); \
			aws s3api delete-object --bucket $(BUCKET_NAME) --key "$$key" --version-id "$$vid" 2>/dev/null || true; \
		done
	@aws s3api list-object-versions --bucket $(BUCKET_NAME) --query 'DeleteMarkers[].{Key:Key,VersionId:VersionId}' --output json 2>/dev/null | \
		jq -c 'select(. != null) | .[] | select(. != null)' | \
		while read obj; do \
			key=$$(echo $$obj | jq -r '.Key'); \
			vid=$$(echo $$obj | jq -r '.VersionId'); \
			aws s3api delete-object --bucket $(BUCKET_NAME) --key "$$key" --version-id "$$vid" 2>/dev/null || true; \
		done
	@aws s3 rb s3://$(BUCKET_NAME) --force 2>/dev/null || true
	@echo "Bucket $(BUCKET_NAME) deleted"

# Delete all S3 buckets created by this stack
delete-buckets:
	@echo "Deleting S3 buckets for stack $(STACK_NAME)..."
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	for bucket_suffix in "artifacts" "scan-results" "cloudtrail"; do \
		BUCKET="$(STACK_NAME)-$$bucket_suffix-$$ACCOUNT_ID"; \
		if aws s3api head-bucket --bucket "$$BUCKET" 2>/dev/null; then \
			echo "Deleting bucket: $$BUCKET"; \
			$(MAKE) delete-bucket BUCKET_NAME=$$BUCKET; \
		else \
			echo "Bucket $$BUCKET does not exist, skipping"; \
		fi; \
	done
	@echo "All buckets cleaned up"

# Delete DynamoDB scan cache table
delete-dynamodb:
	@echo "Deleting DynamoDB scan cache table..."
	@aws dynamodb delete-table \
		--table-name "$(STACK_NAME)-scan-cache" \
		--region $(AWS_REGION) 2>/dev/null && \
		echo "Table $(STACK_NAME)-scan-cache deleted" || \
		echo "Table $(STACK_NAME)-scan-cache not found or already deleted"

# Delete SQS Dead Letter Queue
delete-dlq:
	@echo "Deleting SQS Dead Letter Queue..."
	@QUEUE_URL=$$(aws sqs get-queue-url \
		--queue-name "$(STACK_NAME)-scanner-dlq" \
		--region $(AWS_REGION) \
		--query 'QueueUrl' --output text 2>/dev/null); \
	if [ -n "$$QUEUE_URL" ] && [ "$$QUEUE_URL" != "None" ]; then \
		aws sqs delete-queue --queue-url "$$QUEUE_URL" --region $(AWS_REGION); \
		echo "Queue $(STACK_NAME)-scanner-dlq deleted"; \
	else \
		echo "Queue $(STACK_NAME)-scanner-dlq not found or already deleted"; \
	fi

# Delete SNS topic
delete-sns:
	@echo "Deleting SNS topic..."
	@TOPIC_ARN=$$(aws sns list-topics --region $(AWS_REGION) --query "Topics[?contains(TopicArn, '$(STACK_NAME)-scan-notifications')].TopicArn" --output text 2>/dev/null); \
	if [ -n "$$TOPIC_ARN" ] && [ "$$TOPIC_ARN" != "None" ]; then \
		aws sns delete-topic --topic-arn "$$TOPIC_ARN" --region $(AWS_REGION); \
		echo "Topic deleted: $$TOPIC_ARN"; \
	else \
		echo "SNS topic $(STACK_NAME)-scan-notifications not found or already deleted"; \
	fi

# Delete CloudWatch Log Groups
delete-log-groups:
	@echo "Deleting CloudWatch Log Groups..."
	@for log_group in "/aws/lambda/$(STACK_NAME)-scanner" "/aws/lambda/$(STACK_NAME)-bulk-scan" "/aws/cloudtrail/$(STACK_NAME)"; do \
		if aws logs describe-log-groups --log-group-name-prefix "$$log_group" --region $(AWS_REGION) --query 'logGroups[0].logGroupName' --output text 2>/dev/null | grep -q "$$log_group"; then \
			aws logs delete-log-group --log-group-name "$$log_group" --region $(AWS_REGION) 2>/dev/null && \
			echo "Deleted log group: $$log_group" || true; \
		else \
			echo "Log group $$log_group not found, skipping"; \
		fi; \
	done

# Delete CloudWatch Alarms
delete-alarms:
	@echo "Deleting CloudWatch Alarms..."
	@ALARMS=$$(aws cloudwatch describe-alarms \
		--alarm-name-prefix "$(STACK_NAME)-" \
		--region $(AWS_REGION) \
		--query 'MetricAlarms[].AlarmName' \
		--output text 2>/dev/null); \
	if [ -n "$$ALARMS" ]; then \
		for alarm in $$ALARMS; do \
			echo "Deleting alarm: $$alarm"; \
			aws cloudwatch delete-alarms --alarm-names "$$alarm" --region $(AWS_REGION); \
		done; \
	else \
		echo "No alarms found with prefix $(STACK_NAME)-"; \
	fi

# Delete EventBridge Rules
delete-eventbridge-rules:
	@echo "Deleting EventBridge Rules..."
	@for rule in "$(STACK_NAME)-lambda-create" "$(STACK_NAME)-lambda-update-code" "$(STACK_NAME)-lambda-update-config" "$(STACK_NAME)-bulk-scan-schedule"; do \
		if aws events describe-rule --name "$$rule" --region $(AWS_REGION) 2>/dev/null; then \
			echo "Removing targets from rule: $$rule"; \
			TARGETS=$$(aws events list-targets-by-rule --rule "$$rule" --region $(AWS_REGION) --query 'Targets[].Id' --output text 2>/dev/null); \
			if [ -n "$$TARGETS" ]; then \
				aws events remove-targets --rule "$$rule" --ids $$TARGETS --region $(AWS_REGION) 2>/dev/null || true; \
			fi; \
			echo "Deleting rule: $$rule"; \
			aws events delete-rule --name "$$rule" --region $(AWS_REGION) 2>/dev/null || true; \
		fi; \
	done

# Schedule KMS key for deletion (30-day minimum wait period)
delete-kms-key:
	@echo "Scheduling KMS key for deletion..."
	@KEY_ID=$$(aws kms list-aliases --region $(AWS_REGION) \
		--query "Aliases[?AliasName=='alias/$(STACK_NAME)-scanner'].TargetKeyId" \
		--output text 2>/dev/null); \
	if [ -n "$$KEY_ID" ] && [ "$$KEY_ID" != "None" ]; then \
		echo "Deleting alias alias/$(STACK_NAME)-scanner..."; \
		aws kms delete-alias --alias-name "alias/$(STACK_NAME)-scanner" --region $(AWS_REGION) 2>/dev/null || true; \
		echo "Scheduling key $$KEY_ID for deletion (30-day wait)..."; \
		aws kms schedule-key-deletion --key-id "$$KEY_ID" --pending-window-in-days 7 --region $(AWS_REGION) 2>/dev/null && \
			echo "KMS key scheduled for deletion in 7 days" || \
			echo "Could not schedule key deletion (may already be scheduled or deleted)"; \
	else \
		echo "KMS key alias/$(STACK_NAME)-scanner not found"; \
	fi

# Delete artifacts bucket (for StackSet/Hub deployments)
delete-artifacts-bucket:
	@echo "Deleting artifacts bucket..."
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	BUCKET="qualys-scanner-artifacts-$$ACCOUNT_ID"; \
	if aws s3api head-bucket --bucket "$$BUCKET" 2>/dev/null; then \
		$(MAKE) delete-bucket BUCKET_NAME=$$BUCKET; \
	else \
		echo "Bucket $$BUCKET does not exist"; \
	fi

# Delete Secrets Manager secret
delete-secret:
	@echo "Deleting Secrets Manager secret..."
	@aws secretsmanager delete-secret \
		--secret-id "$(STACK_NAME)-qualys-credentials" \
		--force-delete-without-recovery \
		--region $(AWS_REGION) 2>/dev/null && \
		echo "Secret $(STACK_NAME)-qualys-credentials deleted" || \
		echo "Secret $(STACK_NAME)-qualys-credentials not found or already deleted"

# Delete all Lambda layer versions
delete-layers:
	@echo "Deleting Lambda layer versions for $(LAYER_NAME)..."
	@VERSIONS=$$(aws lambda list-layer-versions \
		--layer-name $(LAYER_NAME) \
		--region $(AWS_REGION) \
		--query 'LayerVersions[].Version' \
		--output text 2>/dev/null); \
	if [ -n "$$VERSIONS" ]; then \
		for v in $$VERSIONS; do \
			echo "Deleting $(LAYER_NAME) version $$v..."; \
			aws lambda delete-layer-version \
				--layer-name $(LAYER_NAME) \
				--version-number $$v \
				--region $(AWS_REGION); \
		done; \
		echo "All layer versions deleted"; \
	else \
		echo "No layer versions found for $(LAYER_NAME)"; \
	fi

# Complete cleanup for single-account deployment
# This deletes: stack, buckets, secret, layers, and local build artifacts
# Also cleans up resources that may have been created before the stack (secret, layer)
# or that may persist after stack deletion (log groups, orphaned resources)
clean-all:
	@echo "=========================================="
	@echo "COMPLETE CLEANUP - Single Account"
	@echo "Stack: $(STACK_NAME)"
	@echo "Region: $(AWS_REGION)"
	@echo "Layer: $(LAYER_NAME)"
	@echo "=========================================="
	@echo ""
	@echo "Step 1/10: Deleting CloudFormation stack..."
	-@$(MAKE) delete 2>/dev/null || echo "Stack already deleted or does not exist"
	@echo ""
	@echo "Step 2/10: Deleting S3 buckets..."
	-@$(MAKE) delete-buckets 2>/dev/null || true
	@echo ""
	@echo "Step 3/10: Deleting Secrets Manager secret (created before stack)..."
	-@$(MAKE) delete-secret 2>/dev/null || true
	@echo ""
	@echo "Step 4/10: Deleting Lambda layers (created before stack)..."
	-@$(MAKE) delete-layers 2>/dev/null || true
	@echo ""
	@echo "Step 5/10: Deleting DynamoDB table (if orphaned)..."
	-@$(MAKE) delete-dynamodb 2>/dev/null || true
	@echo ""
	@echo "Step 6/10: Deleting SQS Dead Letter Queue (if orphaned)..."
	-@$(MAKE) delete-dlq 2>/dev/null || true
	@echo ""
	@echo "Step 7/10: Deleting SNS topic (if orphaned)..."
	-@$(MAKE) delete-sns 2>/dev/null || true
	@echo ""
	@echo "Step 8/10: Deleting CloudWatch Log Groups..."
	-@$(MAKE) delete-log-groups 2>/dev/null || true
	@echo ""
	@echo "Step 9/10: Deleting CloudWatch Alarms (if orphaned)..."
	-@$(MAKE) delete-alarms 2>/dev/null || true
	@echo ""
	@echo "Step 10/10: Cleaning local build artifacts..."
	@$(MAKE) clean
	@echo ""
	@echo "=========================================="
	@echo "CLEANUP COMPLETE"
	@echo "=========================================="
	@echo ""
	@echo "Note: KMS keys created by the stack are scheduled for deletion automatically"
	@echo "      (30-day wait period enforced by AWS)."
	@echo ""
	@echo "To manually schedule KMS key deletion:"
	@echo "  make delete-kms-key"
	@echo ""
	@echo "To verify all resources are cleaned up:"
	@echo "  make clean-dry-run"

# Complete cleanup for hub-spoke deployment
# Hub creates: stack, artifacts bucket, secret (in stack), layer (in stack), EventBus
# Note: Hub stack creates secret internally, but we also delete standalone secret if created separately
clean-all-hub:
	@echo "=========================================="
	@echo "COMPLETE CLEANUP - Hub-Spoke Deployment"
	@echo "Stack: $(STACK_NAME)-hub"
	@echo "Region: $(AWS_REGION)"
	@echo "Layer: $(LAYER_NAME)"
	@echo "=========================================="
	@echo ""
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "WARNING: ORG_UNIT_IDS not set - spoke StackSet cleanup will be skipped"; \
		echo "To clean spokes: make clean-all-hub ORG_UNIT_IDS=ou-xxxx"; \
	else \
		echo "Step 1/12: Deleting spoke StackSet..."; \
		$(MAKE) delete-spoke-stackset 2>/dev/null || echo "Spoke StackSet not found"; \
	fi
	@echo ""
	@echo "Step 2/12: Deleting hub stack..."
	-@$(MAKE) delete-hub 2>/dev/null || echo "Hub stack already deleted"
	@echo ""
	@echo "Step 3/12: Deleting artifacts bucket..."
	-@$(MAKE) delete-artifacts-bucket 2>/dev/null || true
	@echo ""
	@echo "Step 4/12: Deleting Secrets Manager secret (hub)..."
	-@aws secretsmanager delete-secret \
		--secret-id "$(STACK_NAME)-hub-qualys-credentials" \
		--force-delete-without-recovery \
		--region $(AWS_REGION) 2>/dev/null || echo "Secret $(STACK_NAME)-hub-qualys-credentials not found"
	@echo ""
	@echo "Step 5/12: Deleting Lambda layers ($(LAYER_NAME))..."
	-@$(MAKE) delete-layers 2>/dev/null || true
	@echo ""
	@echo "Step 6/12: Deleting DynamoDB table (if orphaned)..."
	-@aws dynamodb delete-table \
		--table-name "$(STACK_NAME)-hub-scan-cache" \
		--region $(AWS_REGION) 2>/dev/null || true
	@echo ""
	@echo "Step 7/12: Deleting SQS Dead Letter Queue (if orphaned)..."
	-@QUEUE_URL=$$(aws sqs get-queue-url \
		--queue-name "$(STACK_NAME)-hub-scanner-dlq" \
		--region $(AWS_REGION) \
		--query 'QueueUrl' --output text 2>/dev/null); \
	if [ -n "$$QUEUE_URL" ] && [ "$$QUEUE_URL" != "None" ]; then \
		aws sqs delete-queue --queue-url "$$QUEUE_URL" --region $(AWS_REGION); \
	fi
	@echo ""
	@echo "Step 8/12: Deleting SNS topic (if orphaned)..."
	-@TOPIC_ARN=$$(aws sns list-topics --region $(AWS_REGION) --query "Topics[?contains(TopicArn, '$(STACK_NAME)-hub-scan-notifications')].TopicArn" --output text 2>/dev/null); \
	if [ -n "$$TOPIC_ARN" ] && [ "$$TOPIC_ARN" != "None" ]; then \
		aws sns delete-topic --topic-arn "$$TOPIC_ARN" --region $(AWS_REGION); \
	fi
	@echo ""
	@echo "Step 9/12: Deleting CloudWatch Log Groups..."
	-@for log_group in "/aws/lambda/$(STACK_NAME)-hub-scanner" "/aws/lambda/$(STACK_NAME)-hub-bulk-scan"; do \
		aws logs delete-log-group --log-group-name "$$log_group" --region $(AWS_REGION) 2>/dev/null || true; \
	done
	@echo ""
	@echo "Step 10/12: Deleting CloudWatch Alarms (if orphaned)..."
	-@ALARMS=$$(aws cloudwatch describe-alarms \
		--alarm-name-prefix "$(STACK_NAME)-hub-" \
		--region $(AWS_REGION) \
		--query 'MetricAlarms[].AlarmName' \
		--output text 2>/dev/null); \
	if [ -n "$$ALARMS" ]; then \
		for alarm in $$ALARMS; do \
			aws cloudwatch delete-alarms --alarm-names "$$alarm" --region $(AWS_REGION); \
		done; \
	fi
	@echo ""
	@echo "Step 11/12: Deleting Central EventBridge Bus (if orphaned)..."
	-@aws events delete-event-bus \
		--name "$(STACK_NAME)-hub-central-bus" \
		--region $(AWS_REGION) 2>/dev/null || true
	@echo ""
	@echo "Step 12/12: Cleaning local build artifacts..."
	@$(MAKE) clean
	@echo ""
	@echo "=========================================="
	@echo "HUB-SPOKE CLEANUP COMPLETE"
	@echo "=========================================="
	@echo ""
	@echo "Note: KMS keys are scheduled for deletion automatically (30-day wait)"
	@echo ""
	@echo "To verify all resources are cleaned up:"
	@echo "  make clean-dry-run"

# Complete cleanup for StackSet deployment
# StackSet creates: stackset, artifacts bucket, layer (uploaded, not published)
# Member accounts get: stack with secret, layer, DynamoDB, SQS, SNS, etc. (all in stack)
clean-all-stackset:
	@echo "=========================================="
	@echo "COMPLETE CLEANUP - StackSet Deployment"
	@echo "StackSet: $(STACK_NAME)-stackset"
	@echo "Region: $(AWS_REGION)"
	@echo "Layer: $(LAYER_NAME)"
	@echo "=========================================="
	@echo ""
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "ERROR: ORG_UNIT_IDS required for StackSet cleanup"; \
		echo "Usage: make clean-all-stackset ORG_UNIT_IDS=ou-xxxx"; \
		exit 1; \
	fi
	@echo "Step 1/5: Deleting StackSet (this deletes all member account stacks)..."
	-@$(MAKE) delete-stackset 2>/dev/null || echo "StackSet not found"
	@echo ""
	@echo "Step 2/5: Deleting artifacts bucket..."
	-@$(MAKE) delete-artifacts-bucket 2>/dev/null || true
	@echo ""
	@echo "Step 3/5: Deleting Lambda layers ($(LAYER_NAME))..."
	-@$(MAKE) delete-layers 2>/dev/null || true
	@echo ""
	@echo "Step 4/5: Deleting scan-results bucket (admin account, if created)..."
	-@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	BUCKET="qualys-lambda-scan-results-$$ACCOUNT_ID"; \
	if aws s3api head-bucket --bucket "$$BUCKET" 2>/dev/null; then \
		$(MAKE) delete-bucket BUCKET_NAME=$$BUCKET; \
	fi
	@echo ""
	@echo "Step 5/5: Cleaning local build artifacts..."
	@$(MAKE) clean
	@echo ""
	@echo "=========================================="
	@echo "STACKSET CLEANUP COMPLETE"
	@echo "=========================================="
	@echo ""
	@echo "Note: Member account resources are deleted via StackSet deletion."
	@echo "      KMS keys in member accounts have 30-day deletion wait period."
	@echo ""
	@echo "If any member account resources remain orphaned, use these commands in each account:"
	@echo "  - Secret: aws secretsmanager delete-secret --secret-id qualys-lambda-scanner-credentials --force-delete-without-recovery"
	@echo "  - Log Groups: aws logs delete-log-group --log-group-name /aws/lambda/qualys-lambda-scanner"

# Show what would be cleaned up (dry run)
clean-dry-run:
	@echo "=========================================="
	@echo "DRY RUN - Resources that would be deleted"
	@echo "=========================================="
	@echo ""
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	echo "Account ID: $$ACCOUNT_ID"; \
	echo "Region: $(AWS_REGION)"; \
	echo "Stack Name: $(STACK_NAME)"; \
	echo "Layer Name: $(LAYER_NAME)"; \
	echo ""
	@echo "=== CloudFormation Stacks ==="
	@aws cloudformation describe-stacks --stack-name $(STACK_NAME) --region $(AWS_REGION) \
		--query 'Stacks[0].StackName' --output text 2>/dev/null && \
		echo "  [FOUND] $(STACK_NAME)" || echo "  [NOT FOUND] $(STACK_NAME)"
	@aws cloudformation describe-stacks --stack-name $(STACK_NAME)-hub --region $(AWS_REGION) \
		--query 'Stacks[0].StackName' --output text 2>/dev/null && \
		echo "  [FOUND] $(STACK_NAME)-hub" || echo "  [NOT FOUND] $(STACK_NAME)-hub"
	@echo ""
	@echo "=== S3 Buckets ==="
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	for bucket in "$(STACK_NAME)-artifacts-$$ACCOUNT_ID" "$(STACK_NAME)-scan-results-$$ACCOUNT_ID" "$(STACK_NAME)-cloudtrail-$$ACCOUNT_ID" "qualys-scanner-artifacts-$$ACCOUNT_ID" "$(STACK_NAME)-hub-scan-results-$$ACCOUNT_ID" "qualys-lambda-scan-results-$$ACCOUNT_ID"; do \
		if aws s3api head-bucket --bucket "$$bucket" 2>/dev/null; then \
			OBJECTS=$$(aws s3 ls s3://$$bucket --recursive --summarize 2>/dev/null | grep "Total Objects" | awk '{print $$3}' || echo "?"); \
			echo "  [FOUND] $$bucket ($$OBJECTS objects)"; \
		fi; \
	done
	@echo ""
	@echo "=== Secrets Manager Secrets ==="
	@for secret in "$(STACK_NAME)-qualys-credentials" "$(STACK_NAME)-hub-qualys-credentials" "qualys-lambda-scanner-credentials"; do \
		if aws secretsmanager describe-secret --secret-id "$$secret" --region $(AWS_REGION) 2>/dev/null >/dev/null; then \
			echo "  [FOUND] $$secret"; \
		fi; \
	done
	@echo ""
	@echo "=== Lambda Layers ==="
	@VERSIONS=$$(aws lambda list-layer-versions --layer-name $(LAYER_NAME) --region $(AWS_REGION) \
		--query 'LayerVersions[].Version' --output text 2>/dev/null); \
	if [ -n "$$VERSIONS" ]; then \
		echo "  [FOUND] $(LAYER_NAME): versions $$VERSIONS"; \
	else \
		echo "  [NOT FOUND] $(LAYER_NAME)"; \
	fi
	@echo ""
	@echo "=== DynamoDB Tables ==="
	@for table in "$(STACK_NAME)-scan-cache" "$(STACK_NAME)-hub-scan-cache" "qualys-lambda-scanner-cache"; do \
		if aws dynamodb describe-table --table-name "$$table" --region $(AWS_REGION) 2>/dev/null >/dev/null; then \
			echo "  [FOUND] $$table"; \
		fi; \
	done
	@echo ""
	@echo "=== SQS Queues ==="
	@for queue in "$(STACK_NAME)-scanner-dlq" "$(STACK_NAME)-hub-scanner-dlq" "qualys-lambda-scanner-dlq"; do \
		if aws sqs get-queue-url --queue-name "$$queue" --region $(AWS_REGION) 2>/dev/null >/dev/null; then \
			echo "  [FOUND] $$queue"; \
		fi; \
	done
	@echo ""
	@echo "=== SNS Topics ==="
	@TOPICS=$$(aws sns list-topics --region $(AWS_REGION) --query "Topics[?contains(TopicArn, 'scan-notifications')].TopicArn" --output text 2>/dev/null); \
	if [ -n "$$TOPICS" ]; then \
		for topic in $$TOPICS; do \
			echo "  [FOUND] $$topic"; \
		done; \
	fi
	@echo ""
	@echo "=== CloudWatch Log Groups ==="
	@for prefix in "/aws/lambda/$(STACK_NAME)" "/aws/cloudtrail/$(STACK_NAME)" "/aws/lambda/qualys-lambda-scanner" "/aws/lambda/qualys-lambda-bulk-scan"; do \
		GROUPS=$$(aws logs describe-log-groups --log-group-name-prefix "$$prefix" --region $(AWS_REGION) \
			--query 'logGroups[].logGroupName' --output text 2>/dev/null); \
		if [ -n "$$GROUPS" ]; then \
			for group in $$GROUPS; do \
				echo "  [FOUND] $$group"; \
			done; \
		fi; \
	done
	@echo ""
	@echo "=== CloudWatch Alarms ==="
	@ALARMS=$$(aws cloudwatch describe-alarms --alarm-name-prefix "$(STACK_NAME)-" --region $(AWS_REGION) \
		--query 'MetricAlarms[].AlarmName' --output text 2>/dev/null); \
	if [ -n "$$ALARMS" ]; then \
		for alarm in $$ALARMS; do \
			echo "  [FOUND] $$alarm"; \
		done; \
	else \
		echo "  [NOT FOUND] No alarms with prefix $(STACK_NAME)-"; \
	fi
	@ALARMS2=$$(aws cloudwatch describe-alarms --alarm-name-prefix "qualys-lambda-scanner-" --region $(AWS_REGION) \
		--query 'MetricAlarms[].AlarmName' --output text 2>/dev/null); \
	if [ -n "$$ALARMS2" ]; then \
		for alarm in $$ALARMS2; do \
			echo "  [FOUND] $$alarm"; \
		done; \
	fi
	@echo ""
	@echo "=== EventBridge Rules ==="
	@for rule in "$(STACK_NAME)-lambda-create" "$(STACK_NAME)-lambda-update-code" "$(STACK_NAME)-lambda-update-config" "$(STACK_NAME)-bulk-scan-schedule" "qualys-lambda-scanner-create" "qualys-lambda-scanner-update-code" "qualys-lambda-scanner-update-config"; do \
		if aws events describe-rule --name "$$rule" --region $(AWS_REGION) 2>/dev/null >/dev/null; then \
			echo "  [FOUND] $$rule"; \
		fi; \
	done
	@echo ""
	@echo "=== EventBridge Event Buses ==="
	@for bus in "$(STACK_NAME)-central-bus" "$(STACK_NAME)-hub-central-bus"; do \
		if aws events describe-event-bus --name "$$bus" --region $(AWS_REGION) 2>/dev/null >/dev/null; then \
			echo "  [FOUND] $$bus"; \
		fi; \
	done
	@echo ""
	@echo "=== KMS Keys ==="
	@KEY_ID=$$(aws kms list-aliases --region $(AWS_REGION) \
		--query "Aliases[?AliasName=='alias/$(STACK_NAME)-scanner'].TargetKeyId" \
		--output text 2>/dev/null); \
	if [ -n "$$KEY_ID" ] && [ "$$KEY_ID" != "None" ]; then \
		STATE=$$(aws kms describe-key --key-id "$$KEY_ID" --region $(AWS_REGION) --query 'KeyMetadata.KeyState' --output text 2>/dev/null); \
		echo "  [FOUND] alias/$(STACK_NAME)-scanner (Key: $$KEY_ID, State: $$STATE)"; \
	fi
	@KEY_ID2=$$(aws kms list-aliases --region $(AWS_REGION) \
		--query "Aliases[?AliasName=='alias/qualys-lambda-scanner'].TargetKeyId" \
		--output text 2>/dev/null); \
	if [ -n "$$KEY_ID2" ] && [ "$$KEY_ID2" != "None" ]; then \
		STATE=$$(aws kms describe-key --key-id "$$KEY_ID2" --region $(AWS_REGION) --query 'KeyMetadata.KeyState' --output text 2>/dev/null); \
		echo "  [FOUND] alias/qualys-lambda-scanner (Key: $$KEY_ID2, State: $$STATE)"; \
	fi
	@echo ""
	@echo "=== StackSets ==="
	@aws cloudformation describe-stack-set --stack-set-name $(STACK_NAME)-stackset \
		--region $(AWS_REGION) --query 'StackSet.StackSetName' --output text 2>/dev/null && \
		echo "  [FOUND] $(STACK_NAME)-stackset" || true
	@aws cloudformation describe-stack-set --stack-set-name $(STACK_NAME)-spoke-stackset \
		--region $(AWS_REGION) --query 'StackSet.StackSetName' --output text 2>/dev/null && \
		echo "  [FOUND] $(STACK_NAME)-spoke-stackset" || true
	@echo ""
	@echo "=== Local Build Artifacts ==="
	@if [ -d build ]; then \
		echo "  [FOUND] build/ directory:"; \
		ls -la build/ 2>/dev/null | head -10 || true; \
	else \
		echo "  [NOT FOUND] build/ directory"; \
	fi
	@echo ""
	@echo "=========================================="
	@echo ""
	@echo "To perform cleanup, run one of:"
	@echo "  make clean-all                              # Single account deployment"
	@echo "  make clean-all-hub ORG_UNIT_IDS=ou-xxx      # Hub-spoke deployment"
	@echo "  make clean-all-stackset ORG_UNIT_IDS=ou-xxx # StackSet deployment"
