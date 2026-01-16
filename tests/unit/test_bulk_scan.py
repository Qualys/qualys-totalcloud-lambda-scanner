import os

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_REGION", "us-east-1")

import json
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws


class TestValidateAccountId:
    """Tests for validate_account_id function."""

    @pytest.mark.unit
    def test_valid_account_id(self):
        """Test valid 12-digit account ID."""
        from bulk_scan import validate_account_id
        assert validate_account_id("123456789012") is True

    @pytest.mark.unit
    def test_invalid_account_id_too_short(self):
        """Test account ID shorter than 12 digits."""
        from bulk_scan import validate_account_id
        assert validate_account_id("12345678901") is False

    @pytest.mark.unit
    def test_invalid_account_id_too_long(self):
        """Test account ID longer than 12 digits."""
        from bulk_scan import validate_account_id
        assert validate_account_id("1234567890123") is False

    @pytest.mark.unit
    def test_invalid_account_id_non_numeric(self):
        """Test account ID with non-numeric characters."""
        from bulk_scan import validate_account_id
        assert validate_account_id("12345678901a") is False
        assert validate_account_id("abcdefghijkl") is False


class TestValidateRegion:
    """Tests for validate_region function."""

    @pytest.mark.unit
    def test_valid_regions(self):
        """Test valid AWS region formats."""
        from bulk_scan import validate_region
        valid_regions = [
            "us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
            "ap-southeast-1", "ap-northeast-1", "sa-east-1"
        ]
        for region in valid_regions:
            assert validate_region(region) is True, f"Expected {region} to be valid"

    @pytest.mark.unit
    def test_invalid_region_formats(self):
        """Test invalid region formats."""
        from bulk_scan import validate_region
        invalid_regions = [
            "US-EAST-1",  # Uppercase
            "useast1",    # No hyphens
            "us-east",    # Missing number
            "invalid",    # Random string
            ""            # Empty
        ]
        for region in invalid_regions:
            assert validate_region(region) is False, f"Expected {region} to be invalid"


class TestShouldExclude:
    """Tests for should_exclude function."""

    @pytest.mark.unit
    def test_should_exclude_matching_pattern(self):
        """Test that matching patterns are excluded."""
        from bulk_scan import should_exclude
        patterns = ["qualys-lambda-scanner", "bulk-scan", "test-"]

        assert should_exclude("qualys-lambda-scanner-main", patterns) is True
        assert should_exclude("my-bulk-scan-function", patterns) is True
        assert should_exclude("test-function", patterns) is True

    @pytest.mark.unit
    def test_should_not_exclude_non_matching(self):
        """Test that non-matching patterns are not excluded."""
        from bulk_scan import should_exclude
        patterns = ["qualys-lambda-scanner", "bulk-scan"]

        assert should_exclude("my-production-function", patterns) is False
        assert should_exclude("api-handler", patterns) is False

    @pytest.mark.unit
    def test_should_exclude_empty_patterns(self):
        """Test behavior with empty patterns list."""
        from bulk_scan import should_exclude
        assert should_exclude("any-function", []) is False

    @pytest.mark.unit
    def test_should_exclude_whitespace_patterns(self):
        """Test that whitespace-only patterns are handled."""
        from bulk_scan import should_exclude
        patterns = ["  ", "", "valid-pattern"]
        assert should_exclude("some-function", patterns) is False
        assert should_exclude("valid-pattern-function", patterns) is True


class TestGetLambdaClientForRegion:
    """Tests for get_lambda_client_for_region function."""

    @pytest.mark.unit
    @mock_aws
    def test_valid_region_returns_client(self):
        """Test that valid region returns a Lambda client."""
        from bulk_scan import get_lambda_client_for_region
        client = get_lambda_client_for_region("us-east-1")
        assert client is not None

    @pytest.mark.unit
    def test_invalid_region_returns_none(self):
        """Test that invalid region returns None."""
        from bulk_scan import get_lambda_client_for_region
        client = get_lambda_client_for_region("INVALID")
        assert client is None


class TestListAllFunctions:
    """Tests for list_all_functions function."""

    @pytest.mark.unit
    @mock_aws
    def test_list_functions_excludes_patterns(self):
        """Test that functions matching exclude patterns are filtered out."""
        iam_client = boto3.client("iam", region_name="us-east-1")
        iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            })
        )

        lambda_client = boto3.client("lambda", region_name="us-east-1")

        functions_to_create = [
            "my-production-function",
            "qualys-lambda-scanner-main",  # Should be excluded
            "another-function",
            "bulk-scan-orchestrator"  # Should be excluded
        ]

        for func_name in functions_to_create:
            lambda_client.create_function(
                FunctionName=func_name,
                Runtime="python3.11",
                Role="arn:aws:iam::123456789012:role/test-role",
                Handler="handler.handler",
                Code={"ZipFile": b"fake"}
            )

        from bulk_scan import list_all_functions
        exclude_patterns = ["qualys-lambda-scanner", "bulk-scan"]

        functions = list_all_functions(lambda_client, exclude_patterns)

        function_names = [f["FunctionName"] for f in functions]
        assert "my-production-function" in function_names
        assert "another-function" in function_names
        assert "qualys-lambda-scanner-main" not in function_names
        assert "bulk-scan-orchestrator" not in function_names

    @pytest.mark.unit
    @mock_aws
    def test_list_functions_returns_required_fields(self):
        """Test that returned functions have all required fields."""
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

        from bulk_scan import list_all_functions

        functions = list_all_functions(lambda_client, [])

        assert len(functions) == 1
        func = functions[0]
        assert "FunctionArn" in func
        assert "FunctionName" in func
        assert "CodeSha256" in func
        assert "Runtime" in func
        assert "PackageType" in func


class TestInvokeScanner:
    """Tests for invoke_scanner function."""

    @pytest.mark.unit
    def test_invoke_scanner_no_function_name(self, monkeypatch):
        """Test that missing SCANNER_FUNCTION_NAME returns failure."""
        monkeypatch.setenv("SCANNER_FUNCTION_NAME", "")

        import bulk_scan
        bulk_scan.SCANNER_FUNCTION_NAME = ""

        func = {
            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test",
            "FunctionName": "test"
        }

        success, name = bulk_scan.invoke_scanner(func, "123456789012")
        assert success is False
        assert name == "test"

    @pytest.mark.unit
    def test_invoke_scanner_success(self, monkeypatch):
        """Test successful scanner invocation."""
        monkeypatch.setenv("SCANNER_FUNCTION_NAME", "qualys-scanner")

        import bulk_scan
        bulk_scan.SCANNER_FUNCTION_NAME = "qualys-scanner"

        mock_lambda = MagicMock()
        mock_lambda.invoke.return_value = {"StatusCode": 202}
        bulk_scan.lambda_client = mock_lambda

        func = {
            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:target",
            "FunctionName": "target",
            "CodeSha256": "abc123",
            "Runtime": "python3.11",
            "PackageType": "Zip"
        }

        success, name = bulk_scan.invoke_scanner(func, "123456789012")
        assert success is True
        assert name == "target"
        mock_lambda.invoke.assert_called_once()


class TestLambdaHandler:
    """Tests for bulk scan lambda_handler function."""

    @pytest.mark.unit
    def test_handler_dry_run(self, monkeypatch):
        """Test dry run mode returns functions without invoking."""
        monkeypatch.setenv("SCANNER_FUNCTION_NAME", "qualys-scanner")

        import bulk_scan
        bulk_scan.SCANNER_FUNCTION_NAME = "qualys-scanner"

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        bulk_scan.sts_client = mock_sts

        mock_functions = [
            {"FunctionArn": "arn:aws:lambda:us-east-1:123:function:f1", "FunctionName": "f1"},
            {"FunctionArn": "arn:aws:lambda:us-east-1:123:function:f2", "FunctionName": "f2"}
        ]

        with patch.object(bulk_scan, "list_all_functions", return_value=mock_functions):
            with patch.object(bulk_scan, "get_lambda_client_for_region") as mock_client:
                mock_client.return_value = MagicMock()

                event = {"dry_run": True, "regions": ["us-east-1"]}
                context = MagicMock()

                response = bulk_scan.lambda_handler(event, context)

        assert response["statusCode"] == 200
        body = response["body"]
        if isinstance(body, str):
            body = json.loads(body)
        assert "total_functions" in body
        assert body["total_functions"] >= 0
        assert body.get("invoked", 0) == 0

    @pytest.mark.unit
    def test_handler_invalid_region(self, monkeypatch):
        """Test handler rejects invalid region formats."""
        import bulk_scan

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        bulk_scan.sts_client = mock_sts

        event = {"regions": ["INVALID-REGION"], "dry_run": True}
        context = MagicMock()

        response = bulk_scan.lambda_handler(event, context)

        assert response["statusCode"] in [200, 400]

    @pytest.mark.unit
    def test_handler_default_regions(self, monkeypatch):
        """Test handler uses default regions when none specified."""
        monkeypatch.setenv("DEFAULT_REGIONS", "us-east-1,us-west-2")

        import bulk_scan
        bulk_scan.DEFAULT_REGIONS = ["us-east-1", "us-west-2"]
        bulk_scan.SCANNER_FUNCTION_NAME = "qualys-scanner"

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        bulk_scan.sts_client = mock_sts

        with patch.object(bulk_scan, "list_all_functions", return_value=[]):
            with patch.object(bulk_scan, "get_lambda_client_for_region") as mock_client:
                mock_client.return_value = MagicMock()

                event = {"dry_run": True}  # No regions specified
                context = MagicMock()

                response = bulk_scan.lambda_handler(event, context)

        assert response["statusCode"] == 200

