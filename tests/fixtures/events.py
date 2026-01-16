SAMPLE_CREATE_FUNCTION_EVENT = {
    "version": "0",
    "id": "12345678-1234-1234-1234-123456789012",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.lambda",
    "account": "123456789012",
    "time": "2024-01-15T10:30:00Z",
    "region": "us-east-1",
    "detail": {
        "eventVersion": "1.08",
        "eventSource": "lambda.amazonaws.com",
        "eventName": "CreateFunction20150331",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "accountId": "123456789012"
        },
        "requestParameters": {
            "functionName": "test-function"
        },
        "responseElements": {
            "functionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-function",
            "functionName": "test-function",
            "runtime": "python3.11",
            "codeSha256": "abc123def456",
            "packageType": "Zip"
        }
    }
}

SAMPLE_UPDATE_CODE_EVENT = {
    "version": "0",
    "id": "12345678-1234-1234-1234-123456789013",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.lambda",
    "account": "123456789012",
    "time": "2024-01-15T11:30:00Z",
    "region": "us-east-1",
    "detail": {
        "eventVersion": "1.08",
        "eventSource": "lambda.amazonaws.com",
        "eventName": "UpdateFunctionCode20150331v2",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "accountId": "123456789012"
        },
        "requestParameters": {
            "functionName": "test-function"
        },
        "responseElements": {
            "functionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-function",
            "functionName": "test-function",
            "runtime": "python3.11",
            "codeSha256": "xyz789abc012",
            "packageType": "Zip"
        }
    }
}

SAMPLE_BULK_SCAN_EVENT = {
    "source": "qualys.bulk-scan",
    "detail-type": "Bulk Scan Request",
    "detail": {
        "eventName": "BulkScanRequest",
        "eventSource": "lambda.amazonaws.com",
        "requestParameters": {
            "functionName": "arn:aws:lambda:us-east-1:123456789012:function:target-function"
        },
        "responseElements": {
            "functionArn": "arn:aws:lambda:us-east-1:123456789012:function:target-function",
            "functionName": "target-function",
            "codeSha256": "bulk123scan456",
            "runtime": "python3.11",
            "packageType": "Zip"
        },
        "userIdentity": {
            "accountId": "123456789012"
        }
    }
}

SAMPLE_CONTAINER_IMAGE_EVENT = {
    "version": "0",
    "id": "12345678-1234-1234-1234-123456789014",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.lambda",
    "account": "123456789012",
    "time": "2024-01-15T12:30:00Z",
    "region": "us-east-1",
    "detail": {
        "eventVersion": "1.08",
        "eventSource": "lambda.amazonaws.com",
        "eventName": "CreateFunction20150331",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "accountId": "123456789012"
        },
        "requestParameters": {
            "functionName": "container-function"
        },
        "responseElements": {
            "functionArn": "arn:aws:lambda:us-east-1:123456789012:function:container-function",
            "functionName": "container-function",
            "codeSha256": "container123",
            "packageType": "Image"
        }
    }
}

INVALID_EVENT_NO_DETAIL = {
    "version": "0",
    "source": "aws.lambda"
}

INVALID_EVENT_NO_ARN = {
    "version": "0",
    "detail": {
        "eventName": "CreateFunction20150331"
    }
}
