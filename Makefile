.PHONY: help layer package deploy deploy-multi-region clean deploy-stackset deploy-hub deploy-spoke

# Variables
AWS_REGION ?= us-east-1
STACK_NAME ?= qscanner
QUALYS_POD ?= US2
LAYER_NAME ?= qscanner
S3_BUCKET ?= $(STACK_NAME)-artifacts-$(shell aws sts get-caller-identity --query Account --output text)
QUALYS_ACCESS_TOKEN ?= $(shell echo $$QUALYS_ACCESS_TOKEN)

# StackSet/Organization variables
ORG_ID ?= $(shell aws organizations describe-organization --query 'Organization.Id' --output text 2>/dev/null)
ORG_UNIT_IDS ?=
ADMIN_ACCOUNT_ID ?= $(shell aws sts get-caller-identity --query Account --output text)
ECR_REPO_NAME ?= qualys-lambda-scanner
SECURITY_ACCOUNT_ID ?= $(ADMIN_ACCOUNT_ID)
CENTRAL_EVENT_BUS_ARN ?=

help:
	@echo "Qualys Lambda Scanner - Makefile"
	@echo ""
	@echo "=== Single Account Deployment ==="
	@echo "  layer                 - Build QScanner Lambda Layer"
	@echo "  package              - Package Lambda function code"
	@echo "  deploy               - Deploy scanner to single region"
	@echo "  deploy-multi-region  - Deploy scanner to multiple regions"
	@echo ""
	@echo "=== Multi-Account StackSet Deployment ==="
	@echo "  build-image          - Build container image for scanner"
	@echo "  push-image           - Push container image to ECR"
	@echo "  deploy-stackset      - Deploy StackSet to organization"
	@echo "  delete-stackset      - Delete StackSet from organization"
	@echo ""
	@echo "=== Centralized Hub-Spoke Deployment ==="
	@echo "  deploy-hub           - Deploy hub scanner in security account"
	@echo "  deploy-spoke-stackset - Deploy spoke template via StackSet to member accounts"
	@echo ""
	@echo "=== Utilities ==="
	@echo "  clean                - Clean build artifacts"
	@echo "  delete               - Delete single-account stack"
	@echo ""
	@echo "Variables:"
	@echo "  AWS_REGION           - AWS region (default: us-east-1)"
	@echo "  STACK_NAME           - CloudFormation stack name (default: qscanner)"
	@echo "  QUALYS_POD           - Qualys POD (default: US2)"
	@echo "  QUALYS_ACCESS_TOKEN  - Qualys access token (required)"
	@echo "  ORG_ID               - AWS Organization ID (auto-detected)"
	@echo "  ORG_UNIT_IDS         - Comma-separated OU IDs for StackSet deployment"
	@echo "  SECURITY_ACCOUNT_ID  - Account ID for centralized hub (default: current account)"

# Build Lambda Layer with QScanner binary
layer:
	@echo "Building QScanner Lambda Layer..."
	@if [ ! -f scanner-lambda/qscanner.gz ]; then \
		echo "ERROR: qscanner.gz not found in scanner-lambda/"; \
		echo "Please download QScanner and place it in scanner-lambda/qscanner.gz"; \
		exit 1; \
	fi
	@echo "Decompressing qscanner.gz to build/layer/bin/..."
	@mkdir -p build/layer/bin
	@gunzip -c scanner-lambda/qscanner.gz > build/layer/bin/qscanner
	@chmod +x build/layer/bin/qscanner
	@cd build/layer && zip -r ../qscanner-layer.zip .
	@echo "Layer created: build/qscanner-layer.zip"
	@du -h build/qscanner-layer.zip

# Package Lambda function code
package:
	@echo "Packaging Lambda function code..."
	@mkdir -p build/function
	@cp scanner-lambda/lambda_function.py build/function/
	@cd build/function && zip -r ../scanner-function.zip .
	@echo "Function package created: build/scanner-function.zip"

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

# Create S3 bucket for Lambda code if it doesn't exist
create-bucket:
	@echo "Creating S3 bucket for artifacts..."
	@aws s3 mb s3://$(S3_BUCKET) --region $(AWS_REGION) 2>/dev/null || true

# Upload Lambda function code to S3
upload-function: package create-bucket
	@echo "Uploading Lambda function code to S3..."
	@aws s3 cp build/scanner-function.zip s3://$(S3_BUCKET)/scanner-function.zip
	@echo "Function code uploaded to s3://$(S3_BUCKET)/scanner-function.zip"

# Create Secrets Manager secret (done separately for security)
create-secret:
	@echo "Creating Secrets Manager secret..."
	@if [ -z "$(QUALYS_ACCESS_TOKEN)" ]; then \
		echo "ERROR: QUALYS_ACCESS_TOKEN environment variable not set"; \
		exit 1; \
	fi
	@SECRET_ARN=$$(aws secretsmanager create-secret \
		--name "$(STACK_NAME)-qualys-credentials" \
		--description "Qualys credentials for Lambda scanner" \
		--secret-string '{"qualys_pod":"$(QUALYS_POD)","qualys_access_token":"$(QUALYS_ACCESS_TOKEN)"}' \
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

# Deploy stack (native Lambda with Layer)
deploy: publish-layer upload-function create-secret
	@echo "Deploying CloudFormation stack..."
	@aws cloudformation deploy \
		--template-file cloudformation/single-account-native.yaml \
		--stack-name $(STACK_NAME) \
		--parameter-overrides \
			QualysPod=$(QUALYS_POD) \
			QualysSecretArn=$$(cat build/secret-arn.txt) \
			QScannerLayerArn=$$(cat build/layer-arn.txt) \
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

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/
	@echo "Clean complete"

# Delete stack
delete:
	@echo "Deleting CloudFormation stack..."
	@aws cloudformation delete-stack \
		--stack-name $(STACK_NAME) \
		--region $(AWS_REGION)
	@echo "Stack deletion initiated. Waiting for completion..."
	@aws cloudformation wait stack-delete-complete \
		--stack-name $(STACK_NAME) \
		--region $(AWS_REGION)
	@echo "Stack deleted"

# =============================================================================
# Multi-Account StackSet Deployment
# =============================================================================

# Create ECR repository for scanner container image
create-ecr-repo:
	@echo "Creating ECR repository..."
	@aws ecr create-repository \
		--repository-name $(ECR_REPO_NAME) \
		--image-scanning-configuration scanOnPush=true \
		--encryption-configuration encryptionType=KMS \
		--region $(AWS_REGION) 2>/dev/null || \
		echo "Repository already exists"
	@echo "ECR repository ready: $(ECR_REPO_NAME)"

# Build container image for scanner Lambda
build-image: layer
	@echo "Building container image..."
	@mkdir -p build/docker
	@# Create Dockerfile
	@echo 'FROM public.ecr.aws/lambda/python:3.11' > build/docker/Dockerfile
	@echo 'COPY lambda_function.py $${LAMBDA_TASK_ROOT}/' >> build/docker/Dockerfile
	@echo 'COPY bin/qscanner /opt/bin/qscanner' >> build/docker/Dockerfile
	@echo 'RUN chmod +x /opt/bin/qscanner' >> build/docker/Dockerfile
	@echo 'CMD ["lambda_function.lambda_handler"]' >> build/docker/Dockerfile
	@# Copy files
	@cp scanner-lambda/lambda_function.py build/docker/
	@mkdir -p build/docker/bin
	@gunzip -c scanner-lambda/qscanner.gz > build/docker/bin/qscanner
	@chmod +x build/docker/bin/qscanner
	@# Build image
	@cd build/docker && docker build -t $(ECR_REPO_NAME):latest .
	@echo "Container image built: $(ECR_REPO_NAME):latest"

# Push container image to ECR
push-image: create-ecr-repo build-image
	@echo "Pushing container image to ECR..."
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	ECR_URI=$$ACCOUNT_ID.dkr.ecr.$(AWS_REGION).amazonaws.com; \
	aws ecr get-login-password --region $(AWS_REGION) | docker login --username AWS --password-stdin $$ECR_URI; \
	docker tag $(ECR_REPO_NAME):latest $$ECR_URI/$(ECR_REPO_NAME):latest; \
	docker push $$ECR_URI/$(ECR_REPO_NAME):latest; \
	echo "$$ECR_URI/$(ECR_REPO_NAME):latest" > build/image-uri.txt
	@echo "Image pushed: $$(cat build/image-uri.txt)"

# Deploy StackSet to organization (each account gets own scanner)
deploy-stackset: push-image
	@echo "Deploying StackSet to organization..."
	@if [ -z "$(QUALYS_ACCESS_TOKEN)" ]; then \
		echo "ERROR: QUALYS_ACCESS_TOKEN environment variable not set"; \
		exit 1; \
	fi
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "ERROR: ORG_UNIT_IDS not set. Specify target OUs: make deploy-stackset ORG_UNIT_IDS=ou-xxxx-xxxxxxxx"; \
		exit 1; \
	fi
	@# Create StackSet
	@aws cloudformation create-stack-set \
		--stack-set-name $(STACK_NAME)-stackset \
		--template-body file://cloudformation/stackset.yaml \
		--parameters \
			ParameterKey=QualysPod,ParameterValue=$(QUALYS_POD) \
			ParameterKey=QualysAccessToken,ParameterValue=$(QUALYS_ACCESS_TOKEN) \
			ParameterKey=ScannerImageUri,ParameterValue=$$(cat build/image-uri.txt) \
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
				ParameterKey=ScannerImageUri,ParameterValue=$$(cat build/image-uri.txt) \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION)
	@# Create stack instances in target OUs
	@echo "Creating stack instances in OUs: $(ORG_UNIT_IDS)..."
	@aws cloudformation create-stack-instances \
		--stack-set-name $(STACK_NAME)-stackset \
		--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
		--regions $(AWS_REGION) \
		--operation-preferences FailureTolerancePercentage=10,MaxConcurrentPercentage=25 \
		--region $(AWS_REGION)
	@echo "StackSet deployment initiated. Monitor with:"
	@echo "  aws cloudformation describe-stack-set-operation --stack-set-name $(STACK_NAME)-stackset --operation-id <id> --region $(AWS_REGION)"

# Delete StackSet
delete-stackset:
	@echo "Deleting StackSet instances..."
	@aws cloudformation delete-stack-instances \
		--stack-set-name $(STACK_NAME)-stackset \
		--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
		--regions $(AWS_REGION) \
		--no-retain-stacks \
		--region $(AWS_REGION) || true
	@echo "Waiting for instances to be deleted..."
	@sleep 60
	@echo "Deleting StackSet..."
	@aws cloudformation delete-stack-set \
		--stack-set-name $(STACK_NAME)-stackset \
		--region $(AWS_REGION)
	@echo "StackSet deleted"

# =============================================================================
# Centralized Hub-Spoke Deployment
# =============================================================================

# Deploy hub scanner in security/central account
deploy-hub: push-image
	@echo "Deploying centralized hub scanner..."
	@if [ -z "$(QUALYS_ACCESS_TOKEN)" ]; then \
		echo "ERROR: QUALYS_ACCESS_TOKEN environment variable not set"; \
		exit 1; \
	fi
	@aws cloudformation deploy \
		--template-file cloudformation/centralized-hub.yaml \
		--stack-name $(STACK_NAME)-hub \
		--parameter-overrides \
			QualysPod=$(QUALYS_POD) \
			QualysAccessToken=$(QUALYS_ACCESS_TOKEN) \
			ScannerImageUri=$$(cat build/image-uri.txt) \
			OrganizationId=$(ORG_ID) \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION)
	@echo "Hub deployment complete!"
	@# Get outputs for spoke deployment
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-hub \
		--query 'Stacks[0].Outputs' \
		--region $(AWS_REGION) \
		--output table
	@# Save central event bus ARN for spoke deployment
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-hub \
		--query "Stacks[0].Outputs[?OutputKey=='CentralEventBusArn'].OutputValue" \
		--output text \
		--region $(AWS_REGION) > build/central-bus-arn.txt
	@echo ""
	@echo "Central Event Bus ARN: $$(cat build/central-bus-arn.txt)"
	@echo ""
	@echo "Next: Deploy spoke template to member accounts with:"
	@echo "  make deploy-spoke-stackset ORG_UNIT_IDS=ou-xxxx-xxxxxxxx"

# Deploy spoke template via StackSet to member accounts
deploy-spoke-stackset:
	@echo "Deploying spoke StackSet to member accounts..."
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "ERROR: ORG_UNIT_IDS not set. Specify target OUs: make deploy-spoke-stackset ORG_UNIT_IDS=ou-xxxx-xxxxxxxx"; \
		exit 1; \
	fi
	@if [ ! -f build/central-bus-arn.txt ]; then \
		echo "ERROR: Central Event Bus ARN not found. Deploy hub first: make deploy-hub"; \
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
	@# Create stack instances in target OUs
	@echo "Creating spoke instances in OUs: $(ORG_UNIT_IDS)..."
	@aws cloudformation create-stack-instances \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
		--regions $(AWS_REGION) \
		--operation-preferences FailureTolerancePercentage=10,MaxConcurrentPercentage=25 \
		--region $(AWS_REGION)
	@echo "Spoke StackSet deployment initiated!"
	@echo ""
	@echo "Monitor with:"
	@echo "  aws cloudformation list-stack-instances --stack-set-name $(STACK_NAME)-spoke-stackset --region $(AWS_REGION)"

# Delete spoke StackSet
delete-spoke-stackset:
	@echo "Deleting spoke StackSet instances..."
	@aws cloudformation delete-stack-instances \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
		--regions $(AWS_REGION) \
		--no-retain-stacks \
		--region $(AWS_REGION) || true
	@echo "Waiting for instances to be deleted..."
	@sleep 60
	@echo "Deleting spoke StackSet..."
	@aws cloudformation delete-stack-set \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--region $(AWS_REGION)
	@echo "Spoke StackSet deleted"

# Delete hub
delete-hub:
	@echo "Deleting hub stack..."
	@aws cloudformation delete-stack \
		--stack-name $(STACK_NAME)-hub \
		--region $(AWS_REGION)
	@aws cloudformation wait stack-delete-complete \
		--stack-name $(STACK_NAME)-hub \
		--region $(AWS_REGION)
	@echo "Hub deleted"
