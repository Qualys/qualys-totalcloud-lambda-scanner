# Event-Driven Lambda Scanning Architecture

This document describes the technical architecture for automated vulnerability scanning of AWS Lambda functions using Qualys QScanner. The solution captures Lambda deployment events and triggers security scans without manual intervention.

## Architecture Overview

The scanner operates as a Lambda function triggered by CloudTrail events via EventBridge. When developers create or update Lambda functions, the scanner automatically retrieves and analyzes the deployment package for vulnerabilities and exposed secrets.

```mermaid
flowchart TB
    subgraph developer["Developer Actions"]
        DEV[Developer]
        CLI[AWS CLI/SDK]
        CONSOLE[AWS Console]
    end

    subgraph events["Event Capture"]
        CT[CloudTrail]
        EB[EventBridge Rules]
    end

    subgraph scanner["Scanner Infrastructure"]
        SCAN[Scanner Lambda]
        LAYER[QScanner Layer]
        SECRET[Secrets Manager]
    end

    subgraph targets["Scan Targets"]
        ZIP[Zip Functions]
        IMG[Container Functions]
        ECR[ECR Registry]
    end

    subgraph storage["Results & Cache"]
        S3[S3 Results Bucket]
        DDB[DynamoDB Cache]
        SNS[SNS Notifications]
    end

    subgraph qualys["Qualys Platform"]
        TC[TotalCloud]
    end

    DEV --> CLI & CONSOLE
    CLI & CONSOLE -->|CreateFunction\nUpdateFunctionCode| CT
    CT --> EB
    EB -->|Trigger| SCAN
    SCAN --> LAYER
    SCAN -->|Get Credentials| SECRET
    SCAN -->|GetFunction API| ZIP
    SCAN -->|BatchGetImage| IMG
    IMG --> ECR
    SCAN -->|Check Cache| DDB
    SCAN -->|Store Results| S3
    SCAN -->|Notify| SNS
    SCAN -->|Report Findings| TC

    style developer fill:#e3f2fd
    style events fill:#fff3e0
    style scanner fill:#e8f5e9
    style targets fill:#f3e5f5
    style storage fill:#fce4ec
    style qualys fill:#fff8e1
```

## Core Components

### Event Detection

CloudTrail captures all Lambda API calls across the account. EventBridge rules match specific events that indicate code changes:

| Event Name | Trigger Condition |
|------------|-------------------|
| `CreateFunction20150331` | New function deployment |
| `UpdateFunctionCode20150331v2` | Code update to existing function |
| `UpdateFunctionConfiguration20150331v2` | Configuration change (optional) |

The scanner ignores its own deployments to prevent infinite scan loops.

### Scanner Lambda

The scanner Lambda executes QScanner against target functions. Key characteristics:

- **Memory**: 2048 MB default (configurable 512-10240 MB)
- **Timeout**: 900 seconds maximum
- **Ephemeral Storage**: 2048 MB for temporary scan artifacts
- **Reserved Concurrency**: 10 concurrent executions (prevents runaway during mass deployments)

QScanner runs as a Lambda Layer, keeping the function code minimal and updates independent.

### Scan Caching

DynamoDB stores scan results keyed by function ARN and code SHA256. When code hasn't changed, the scanner returns cached results instead of re-scanning:

```mermaid
flowchart LR
    subgraph input["Scan Request"]
        ARN[Function ARN]
        SHA[Code SHA256]
    end

    subgraph cache["Cache Lookup"]
        DDB[(DynamoDB)]
        CHECK{Cache Hit?}
    end

    subgraph action["Action"]
        SKIP[Return Cached]
        SCAN[Run QScanner]
    end

    ARN & SHA --> DDB
    DDB --> CHECK
    CHECK -->|Yes| SKIP
    CHECK -->|No| SCAN
    SCAN -->|Update| DDB

    style input fill:#e3f2fd
    style cache fill:#fff3e0
    style action fill:#e8f5e9
```

Cache TTL is configurable from 1-365 days (default: 30 days).

## Deployment Patterns

### Single Account, Single Region

The simplest deployment monitors Lambda functions within one AWS account and region.

```mermaid
flowchart TB
    subgraph account["AWS Account"]
        subgraph region["us-east-1"]
            CT[CloudTrail]
            EB[EventBridge]
            SCAN[Scanner Lambda]
            TARGETS[Target Functions]
            S3[Results Bucket]
            DDB[Cache Table]
        end
    end

    CT --> EB --> SCAN
    SCAN --> TARGETS
    SCAN --> S3 & DDB

    style account fill:#e3f2fd
    style region fill:#e8f5e9
```

**Use case**: Development environments, single-region production workloads.

### Single Account, Multi-Region

For organizations with Lambda functions across multiple regions, deploy the scanner stack to each region independently.

```mermaid
flowchart TB
    subgraph account["AWS Account"]
        subgraph east["us-east-1"]
            CT1[CloudTrail]
            EB1[EventBridge]
            SCAN1[Scanner]
            T1[Functions]
        end

        subgraph west["us-west-2"]
            CT2[CloudTrail]
            EB2[EventBridge]
            SCAN2[Scanner]
            T2[Functions]
        end

        subgraph eu["eu-west-1"]
            CT3[CloudTrail]
            EB3[EventBridge]
            SCAN3[Scanner]
            T3[Functions]
        end
    end

    CT1 --> EB1 --> SCAN1 --> T1
    CT2 --> EB2 --> SCAN2 --> T2
    CT3 --> EB3 --> SCAN3 --> T3

    style account fill:#e3f2fd
    style east fill:#e8f5e9
    style west fill:#fff3e0
    style eu fill:#f3e5f5
```

Each region maintains independent caches and results. Qualys TotalCloud aggregates findings centrally.

### Multi-Account with StackSets

For AWS Organizations, deploy scanner infrastructure to all member accounts using CloudFormation StackSets.

```mermaid
flowchart TB
    subgraph org["AWS Organization"]
        subgraph mgmt["Management Account"]
            SS[StackSet]
        end

        subgraph member1["Member Account A"]
            SCAN1[Scanner]
            T1[Functions]
        end

        subgraph member2["Member Account B"]
            SCAN2[Scanner]
            T2[Functions]
        end

        subgraph member3["Member Account C"]
            SCAN3[Scanner]
            T3[Functions]
        end
    end

    SS -->|Deploy| SCAN1 & SCAN2 & SCAN3
    SCAN1 --> T1
    SCAN2 --> T2
    SCAN3 --> T3

    style org fill:#e3f2fd
    style mgmt fill:#fff8e1
    style member1 fill:#e8f5e9
    style member2 fill:#fff3e0
    style member3 fill:#f3e5f5
```

Each account operates independently with its own credentials, caches, and results storage.

### Centralized Hub-Spoke

For centralized security operations, deploy a single scanner in a security account that receives events from all member accounts.

```mermaid
flowchart TB
    subgraph org["AWS Organization"]
        subgraph hub["Security Account (Hub)"]
            BUS[Central Event Bus]
            SCAN[Scanner Lambda]
            BULK[Bulk Scan Lambda]
            S3[Results Bucket]
            DDB[Cache Table]
        end

        subgraph spoke1["Member Account A"]
            CT1[CloudTrail]
            EB1[EventBridge]
            ROLE1[Cross-Account Role]
            T1[Functions]
        end

        subgraph spoke2["Member Account B"]
            CT2[CloudTrail]
            EB2[EventBridge]
            ROLE2[Cross-Account Role]
            T2[Functions]
        end
    end

    CT1 --> EB1 -->|Forward Events| BUS
    CT2 --> EB2 -->|Forward Events| BUS
    BUS --> SCAN
    SCAN -->|AssumeRole| ROLE1 --> T1
    SCAN -->|AssumeRole| ROLE2 --> T2
    SCAN --> S3 & DDB
    BULK -->|Invoke| SCAN

    style org fill:#e3f2fd
    style hub fill:#fff8e1
    style spoke1 fill:#e8f5e9
    style spoke2 fill:#f3e5f5
```

**Key features**:
- Single scanner Lambda in security account
- EventBridge cross-account event forwarding
- Cross-account role assumption with External ID
- Centralized results and caching
- Bulk scan capability for existing functions

## Security Implementation

### Credential Management

Qualys API credentials are stored in AWS Secrets Manager, never in environment variables or code:

```mermaid
flowchart LR
    subgraph scanner["Scanner Lambda"]
        CODE[Function Code]
    end

    subgraph secrets["Secrets Manager"]
        SECRET[Qualys Credentials]
    end

    subgraph qualys["Qualys API"]
        API[TotalCloud API]
    end

    CODE -->|GetSecretValue| SECRET
    SECRET -->|Pod + Token| CODE
    CODE -->|Authenticate| API

    style scanner fill:#e8f5e9
    style secrets fill:#fff3e0
    style qualys fill:#fce4ec
```

### Encryption

All data at rest uses customer-managed KMS keys:

| Resource | Encryption |
|----------|------------|
| DynamoDB Cache | KMS CMK |
| S3 Results Bucket | KMS CMK or AES-256 |
| SNS Notifications | KMS CMK |
| SQS Dead Letter Queue | KMS CMK |
| CloudWatch Logs | KMS CMK |
| Secrets Manager | KMS CMK |

S3 bucket policies enforce HTTPS-only access.

### IAM Least Privilege

The scanner Lambda role follows least-privilege principles:

| Permission | Scope |
|------------|-------|
| `lambda:GetFunction` | All functions in account |
| `lambda:TagResource` | Only `QualysScan*` tags |
| `ecr:BatchGetImage` | All repositories in account |
| `secretsmanager:GetSecretValue` | Specific secret ARN only |
| `dynamodb:GetItem/PutItem` | Specific table only |
| `s3:PutObject` | Specific bucket only |
| `sns:Publish` | Specific topic only |
| `cloudwatch:PutMetricData` | `QualysLambdaScanner` namespace only |

### Cross-Account Security

Hub-spoke deployments use External ID to prevent confused deputy attacks:

```mermaid
sequenceDiagram
    participant Hub as Hub Scanner
    participant STS as AWS STS
    participant Spoke as Spoke Role

    Hub->>STS: AssumeRole(RoleArn, ExternalId)
    STS->>Spoke: Validate Trust Policy
    Note over Spoke: Check: Principal = Hub Account<br/>Check: ExternalId matches
    Spoke-->>STS: Temporary Credentials
    STS-->>Hub: AccessKey, SecretKey, Token
    Hub->>Spoke: GetFunction (with temp creds)
```

The External ID must match between hub and spoke deployments.

## Bulk Scanning

The bulk scan Lambda enables on-demand scanning of all existing functions:

```mermaid
flowchart TB
    subgraph trigger["Trigger"]
        MANUAL[Manual Invocation]
        SCHEDULE[EventBridge Schedule]
    end

    subgraph bulk["Bulk Scan Lambda"]
        LIST[List Functions]
        FILTER[Apply Exclusions]
        BATCH[Batch Processing]
    end

    subgraph scanner["Scanner Lambda"]
        SCAN[QScanner]
    end

    MANUAL & SCHEDULE --> LIST
    LIST --> FILTER --> BATCH
    BATCH -->|Async Invoke| SCAN
    BATCH -->|Async Invoke| SCAN
    BATCH -->|Async Invoke| SCAN

    style trigger fill:#e3f2fd
    style bulk fill:#fff3e0
    style scanner fill:#e8f5e9
```

**Configuration options**:
- `BATCH_SIZE`: Functions per batch (default: 100)
- `MAX_WORKERS`: Concurrent invocations (default: 10)
- `INVOCATION_DELAY_MS`: Pause between batches (default: 100ms)
- `EXCLUDE_PATTERNS`: Skip matching function names

## Observability

### CloudWatch Metrics

The scanner publishes custom metrics to the `QualysLambdaScanner` namespace:

| Metric | Description |
|--------|-------------|
| `ScanSuccess` | Successful scan completions |
| `ScanPartialSuccess` | Scans with partial results |
| `ScanDuration` | Time to complete scan (seconds) |
| `CacheHit` | Scans skipped due to cache |
| `VulnerabilityCount` | Vulnerabilities detected |

### CloudWatch Alarms

Pre-configured alarms monitor scanner health:

- **Scanner Errors**: More than 5 errors in 5 minutes
- **Scanner Throttles**: Any throttling detected
- **DLQ Messages**: Failed invocations requiring investigation
- **Duration Warning**: Scans approaching timeout threshold

### X-Ray Tracing

Active tracing enables end-to-end visibility across the scan workflow for debugging and performance analysis.

## Cost Considerations

Monthly costs for typical deployments:

| Deployment Size | Daily Deployments | Estimated Monthly Cost |
|-----------------|-------------------|------------------------|
| Small | 50 | $5-10 |
| Medium | 500 | $15-25 |
| Large | 2000 | $40-60 |

**Cost drivers**:
- Lambda invocations and duration
- DynamoDB read/write capacity (on-demand billing)
- S3 storage for results
- CloudTrail events (if creating new trail)
- KMS API calls

Scan caching significantly reduces costs by avoiding redundant scans of unchanged code.

## Quick Start

1. **Create Qualys credentials** in Secrets Manager
2. **Deploy scanner stack** via CloudFormation or Terraform
3. **Verify EventBridge rules** are capturing Lambda events
4. **Deploy a test function** and confirm scan execution
5. **Check Qualys TotalCloud** for vulnerability findings

For detailed deployment instructions, see the [README](../README.md).
