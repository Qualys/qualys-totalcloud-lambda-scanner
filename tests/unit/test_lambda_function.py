import os

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_REGION", "us-east-1")

import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from tests.fixtures.events import (
    SAMPLE_CREATE_FUNCTION_EVENT,
    SAMPLE_UPDATE_CODE_EVENT,
    SAMPLE_BULK_SCAN_EVENT,
    INVALID_EVENT_NO_DETAIL,
    INVALID_EVENT_NO_ARN,
)


class TestGetQualysCredentials:
    """Tests for get_qualys_credentials function."""

    @pytest.mark.unit
    @mock_aws
    def test_get_credentials_success(self, monkeypatch):
        """Test successful credential retrieval."""
        client = boto3.client("secretsmanager", region_name="us-east-1")
        secret_value = {
            "qualys_pod": "US2",
            "qualys_access_token": "test_token_12345678901234567890"
        }
        response = client.create_secret(
            Name="test-qualys-secret",
            SecretString=json.dumps(secret_value)
        )
        monkeypatch.setenv("QUALYS_SECRET_ARN", response["ARN"])

        import lambda_function
        lambda_function.secrets_manager = boto3.client("secretsmanager", region_name="us-east-1")
        lambda_function.QUALYS_SECRET_ARN = response["ARN"]

        creds = lambda_function.get_qualys_credentials()

        assert creds["qualys_pod"] == "US2"
        assert creds["qualys_access_token"] == "test_token_12345678901234567890"

    @pytest.mark.unit
    def test_get_credentials_missing_env_var(self, monkeypatch):
        """Test error when QUALYS_SECRET_ARN not set."""
        monkeypatch.delenv("QUALYS_SECRET_ARN", raising=False)

        import lambda_function
        lambda_function.QUALYS_SECRET_ARN = None

        with pytest.raises(ValueError, match="QUALYS_SECRET_ARN"):
            lambda_function.get_qualys_credentials()

    @pytest.mark.unit
    @mock_aws
    def test_get_credentials_invalid_pod(self, monkeypatch):
        """Test error when POD format is invalid."""
        client = boto3.client("secretsmanager", region_name="us-east-1")
        secret_value = {
            "qualys_pod": "invalid-pod",  # Invalid format
            "qualys_access_token": "test_token_12345678901234567890"
        }
        response = client.create_secret(
            Name="test-qualys-secret",
            SecretString=json.dumps(secret_value)
        )
        monkeypatch.setenv("QUALYS_SECRET_ARN", response["ARN"])

        import lambda_function
        lambda_function.secrets_manager = boto3.client("secretsmanager", region_name="us-east-1")
        lambda_function.QUALYS_SECRET_ARN = response["ARN"]

        with pytest.raises(ValueError, match="Invalid POD format"):
            lambda_function.get_qualys_credentials()


class TestCheckScanCache:
    """Tests for check_scan_cache function."""

    @pytest.mark.unit
    @mock_aws
    def test_cache_hit(self, monkeypatch):
        """Test cache hit when SHA matches and not expired."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="test-cache-table",
            KeySchema=[{"AttributeName": "function_arn", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "function_arn", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST"
        )
        table.wait_until_exists()

        function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test"
        code_sha256 = "abc123"

        table.put_item(Item={
            "function_arn": function_arn,
            "code_sha256": code_sha256,
            "scan_timestamp": datetime.utcnow().isoformat()
        })

        monkeypatch.setenv("SCAN_CACHE_TABLE", "test-cache-table")

        import lambda_function
        lambda_function.dynamodb = dynamodb
        lambda_function.SCAN_CACHE_TABLE = "test-cache-table"
        lambda_function.CACHE_TTL_DAYS = 30

        result = lambda_function.check_scan_cache(function_arn, code_sha256)
        assert result is True

    @pytest.mark.unit
    @mock_aws
    def test_cache_miss_different_sha(self, monkeypatch):
        """Test cache miss when SHA doesn't match."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="test-cache-table",
            KeySchema=[{"AttributeName": "function_arn", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "function_arn", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST"
        )
        table.wait_until_exists()

        function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test"

        table.put_item(Item={
            "function_arn": function_arn,
            "code_sha256": "old_sha256",
            "scan_timestamp": datetime.utcnow().isoformat()
        })

        monkeypatch.setenv("SCAN_CACHE_TABLE", "test-cache-table")

        import lambda_function
        lambda_function.dynamodb = dynamodb
        lambda_function.SCAN_CACHE_TABLE = "test-cache-table"
        lambda_function.CACHE_TTL_DAYS = 30

        result = lambda_function.check_scan_cache(function_arn, "new_sha256")
        assert result is False

    @pytest.mark.unit
    @mock_aws
    def test_cache_miss_expired(self, monkeypatch):
        """Test cache miss when entry is expired."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="test-cache-table",
            KeySchema=[{"AttributeName": "function_arn", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "function_arn", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST"
        )
        table.wait_until_exists()

        function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test"
        code_sha256 = "abc123"

        old_timestamp = datetime.utcnow() - timedelta(days=60)
        table.put_item(Item={
            "function_arn": function_arn,
            "code_sha256": code_sha256,
            "scan_timestamp": old_timestamp.isoformat()
        })

        monkeypatch.setenv("SCAN_CACHE_TABLE", "test-cache-table")

        import lambda_function
        lambda_function.dynamodb = dynamodb
        lambda_function.SCAN_CACHE_TABLE = "test-cache-table"
        lambda_function.CACHE_TTL_DAYS = 30

        result = lambda_function.check_scan_cache(function_arn, code_sha256)
        assert result is False

    @pytest.mark.unit
    def test_cache_disabled(self, monkeypatch):
        """Test that cache check returns False when disabled."""
        monkeypatch.delenv("SCAN_CACHE_TABLE", raising=False)

        import lambda_function
        lambda_function.SCAN_CACHE_TABLE = None

        result = lambda_function.check_scan_cache("arn", "sha256")
        assert result is False


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    @pytest.mark.unit
    def test_invalid_event_no_detail(self, lambda_context):
        """Test handler rejects events without detail."""
        import lambda_function

        response = lambda_function.lambda_handler(INVALID_EVENT_NO_DETAIL, lambda_context)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert "error" in body["message"].lower() or "invalid" in body["message"].lower()

    @pytest.mark.unit
    def test_skips_self_scan(self, lambda_context, monkeypatch):
        """Test handler skips scanning itself."""
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "test-function")

        import lambda_function
        lambda_function.QUALYS_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test"

        with patch.object(lambda_function, "get_qualys_credentials") as mock_creds:
            mock_creds.return_value = {
                "qualys_pod": "US2",
                "qualys_access_token": "test_token_12345678901234567890"
            }

            response = lambda_function.lambda_handler(SAMPLE_CREATE_FUNCTION_EVENT, lambda_context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "skip" in body["message"].lower() or body.get("function_arn")

    @pytest.mark.unit
    @mock_aws
    def test_handler_extracts_function_arn_from_response(self, lambda_context, monkeypatch):
        """Test handler correctly extracts function ARN from responseElements."""
        secrets_client = boto3.client("secretsmanager", region_name="us-east-1")
        secret_value = {
            "qualys_pod": "US2",
            "qualys_access_token": "test_token_12345678901234567890"
        }
        secret_response = secrets_client.create_secret(
            Name="test-secret",
            SecretString=json.dumps(secret_value)
        )

        iam_client = boto3.client("iam", region_name="us-east-1")
        iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            })
        )

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function",
            Runtime="python3.11",
            Role="arn:aws:iam::123456789012:role/test-role",
            Handler="handler.handler",
            Code={"ZipFile": b"fake"}
        )

        monkeypatch.setenv("QUALYS_SECRET_ARN", secret_response["ARN"])
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "qualys-scanner")

        import lambda_function
        lambda_function.secrets_manager = secrets_client
        lambda_function.lambda_client = lambda_client
        lambda_function.QUALYS_SECRET_ARN = secret_response["ARN"]
        lambda_function.SCAN_CACHE_TABLE = None  # Disable cache

        with patch.object(lambda_function, "run_qscanner") as mock_scan:
            mock_scan.return_value = {
                "success": True,
                "partial": False,
                "exit_code": 0,
                "results": {},
                "stdout": "",
                "stderr": ""
            }

            with patch.object(lambda_function, "store_results"):
                with patch.object(lambda_function, "publish_custom_metrics"):
                    response = lambda_function.lambda_handler(
                        SAMPLE_CREATE_FUNCTION_EVENT,
                        lambda_context
                    )

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body.get("scan_success") is True or "completed" in body.get("message", "").lower()


class TestUpdateScanCache:
    """Tests for update_scan_cache function."""

    @pytest.mark.unit
    @mock_aws
    def test_update_cache_success(self, monkeypatch):
        """Test successful cache update."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="test-cache-table",
            KeySchema=[{"AttributeName": "function_arn", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "function_arn", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST"
        )
        table.wait_until_exists()

        monkeypatch.setenv("SCAN_CACHE_TABLE", "test-cache-table")

        import lambda_function
        lambda_function.dynamodb = dynamodb
        lambda_function.SCAN_CACHE_TABLE = "test-cache-table"
        lambda_function.CACHE_TTL_DAYS = 30

        function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test"
        lambda_details = {
            "function_arn": function_arn,
            "function_name": "test",
            "code_sha256": "abc123",
            "package_type": "Zip",
            "runtime": "python3.11",
            "last_modified": "2024-01-15T10:00:00Z"
        }
        scan_results = {"success": True}

        lambda_function.update_scan_cache(function_arn, lambda_details, scan_results)

        response = table.get_item(Key={"function_arn": function_arn})
        assert "Item" in response
        assert response["Item"]["code_sha256"] == "abc123"
        assert response["Item"]["scan_success"] is True

    @pytest.mark.unit
    def test_update_cache_disabled(self, monkeypatch):
        """Test that update is skipped when cache is disabled."""
        monkeypatch.delenv("SCAN_CACHE_TABLE", raising=False)

        import lambda_function
        lambda_function.SCAN_CACHE_TABLE = None

        lambda_function.update_scan_cache("arn", {}, {})


class TestGetLambdaDetails:
    """Tests for get_lambda_details function."""

    @pytest.mark.unit
    @mock_aws
    def test_get_lambda_details_success(self):
        """Test successful Lambda details retrieval."""
        iam_client = boto3.client("iam", region_name="us-east-1")
        iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            })
        )

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function",
            Runtime="python3.11",
            Role="arn:aws:iam::123456789012:role/test-role",
            Handler="handler.handler",
            Code={"ZipFile": b"fake code"},
            MemorySize=256,
            Timeout=60
        )

        function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-function"

        import lambda_function
        lambda_function.lambda_client = lambda_client

        details = lambda_function.get_lambda_details(function_arn)

        assert details["function_name"] == "test-function"
        assert details["runtime"] == "python3.11"
        assert details["package_type"] == "Zip"
        assert details["memory_size"] == 256
        assert details["timeout"] == 60

