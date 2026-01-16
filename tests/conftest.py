import json
import os

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def mock_aws_services():
    with mock_aws():
        yield


@pytest.fixture
def secrets_manager_client(mock_aws_services):
    return boto3.client("secretsmanager", region_name="us-east-1")


@pytest.fixture
def lambda_client(mock_aws_services):
    return boto3.client("lambda", region_name="us-east-1")


@pytest.fixture
def s3_client(mock_aws_services):
    return boto3.client("s3", region_name="us-east-1")


@pytest.fixture
def dynamodb_resource(mock_aws_services):
    return boto3.resource("dynamodb", region_name="us-east-1")


@pytest.fixture
def sns_client(mock_aws_services):
    return boto3.client("sns", region_name="us-east-1")


@pytest.fixture
def qualys_secret(secrets_manager_client):
    secret_value = {
        "qualys_pod": "US2",
        "qualys_access_token": "test_token_12345678901234567890"
    }
    response = secrets_manager_client.create_secret(
        Name="qualys-scanner-credentials",
        SecretString=json.dumps(secret_value)
    )
    return response["ARN"]


@pytest.fixture
def s3_bucket(s3_client):
    bucket_name = "qualys-scan-results-test"
    s3_client.create_bucket(Bucket=bucket_name)
    return bucket_name


@pytest.fixture
def sns_topic(sns_client):
    response = sns_client.create_topic(Name="qualys-scan-notifications")
    return response["TopicArn"]


@pytest.fixture
def scan_cache_table(dynamodb_resource):
    table_name = "qualys-scan-cache-test"
    table = dynamodb_resource.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "function_arn", "KeyType": "HASH"}
        ],
        AttributeDefinitions=[
            {"AttributeName": "function_arn", "AttributeType": "S"}
        ],
        BillingMode="PAY_PER_REQUEST"
    )
    table.wait_until_exists()
    return table_name


@pytest.fixture
def test_lambda_function(lambda_client):
    iam_client = boto3.client("iam", region_name="us-east-1")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }

    iam_client.create_role(
        RoleName="test-lambda-role",
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )

    function_name = "test-target-function"
    lambda_client.create_function(
        FunctionName=function_name,
        Runtime="python3.11",
        Role="arn:aws:iam::123456789012:role/test-lambda-role",
        Handler="handler.handler",
        Code={"ZipFile": b"fake code"},
        Description="Test function for scanning",
        Timeout=30,
        MemorySize=128
    )

    return f"arn:aws:lambda:us-east-1:123456789012:function:{function_name}"


@pytest.fixture
def scanner_env_vars(monkeypatch, qualys_secret, s3_bucket, sns_topic, scan_cache_table):
    monkeypatch.setenv("QUALYS_SECRET_ARN", qualys_secret)
    monkeypatch.setenv("RESULTS_S3_BUCKET", s3_bucket)
    monkeypatch.setenv("SNS_TOPIC_ARN", sns_topic)
    monkeypatch.setenv("SCAN_CACHE_TABLE", scan_cache_table)
    monkeypatch.setenv("ENABLE_TAGGING", "true")
    monkeypatch.setenv("SCAN_TIMEOUT", "300")
    monkeypatch.setenv("CACHE_TTL_DAYS", "30")
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "qualys-scanner")


class MockLambdaContext:
    def __init__(self):
        self.function_name = "qualys-scanner"
        self.function_version = "$LATEST"
        self.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:qualys-scanner"
        self.memory_limit_in_mb = 2048
        self.aws_request_id = "test-request-id-12345"
        self.log_group_name = "/aws/lambda/qualys-scanner"
        self.log_stream_name = "2024/01/15/[$LATEST]abc123"
        self.identity = None
        self.client_context = None

    def get_remaining_time_in_millis(self):
        return 300000


@pytest.fixture
def lambda_context():
    return MockLambdaContext()
