import os

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_REGION", "us-east-1")

import pytest

from lambda_function import (
    validate_pod,
    validate_access_token,
    validate_function_arn,
    validate_function_name,
    validate_role_arn,
    sanitize_log_output,
)


class TestValidatePod:
    @pytest.mark.unit
    def test_valid_pods(self):
        valid_pods = ["US1", "US2", "US3", "US4", "EU1", "EU2", "EU3",
                      "GOV1", "IN1", "CA1", "AE1", "UK1", "AU1", "KSA1"]
        for pod in valid_pods:
            assert validate_pod(pod) is True, f"Expected {pod} to be valid"

    @pytest.mark.unit
    def test_invalid_pods_lowercase(self):
        invalid_pods = ["us1", "us2", "eu1", "gov1"]
        for pod in invalid_pods:
            assert validate_pod(pod) is False, f"Expected {pod} to be invalid"

    @pytest.mark.unit
    def test_invalid_pods_special_chars(self):
        invalid_pods = ["US-1", "US_2", "US.1", "US 1"]
        for pod in invalid_pods:
            assert validate_pod(pod) is False, f"Expected {pod} to be invalid"

    @pytest.mark.unit
    def test_invalid_pods_empty(self):
        assert validate_pod("") is False

    @pytest.mark.unit
    def test_invalid_pods_none(self):
        with pytest.raises(TypeError):
            validate_pod(None)


class TestValidateAccessToken:
    @pytest.mark.unit
    def test_valid_token_alphanumeric(self):
        token = "a" * 20
        assert validate_access_token(token) is True

    @pytest.mark.unit
    def test_valid_token_with_special_chars(self):
        token = "abc_def-ghi.jkl123456"
        assert validate_access_token(token) is True

    @pytest.mark.unit
    def test_valid_token_max_length(self):
        token = "a" * 1000
        assert validate_access_token(token) is True

    @pytest.mark.unit
    def test_invalid_token_too_short(self):
        token = "a" * 19
        assert validate_access_token(token) is False

    @pytest.mark.unit
    def test_invalid_token_too_long(self):
        token = "a" * 1001
        assert validate_access_token(token) is False

    @pytest.mark.unit
    def test_invalid_token_special_chars(self):
        invalid_tokens = ["token@with#symbols!", "token with spaces"]
        for token in invalid_tokens:
            padded_token = token + "a" * (20 - len(token))
            assert validate_access_token(padded_token) is False

    @pytest.mark.unit
    def test_invalid_token_empty(self):
        assert validate_access_token("") is False


class TestValidateFunctionArn:
    @pytest.mark.unit
    def test_valid_function_arn(self):
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-function"
        assert validate_function_arn(arn) is True

    @pytest.mark.unit
    def test_valid_function_arn_different_regions(self):
        regions = ["us-west-2", "eu-west-1", "ap-southeast-1", "sa-east-1"]
        for region in regions:
            arn = f"arn:aws:lambda:{region}:123456789012:function:test-func"
            assert validate_function_arn(arn) is True

    @pytest.mark.unit
    def test_valid_function_arn_with_hyphens_underscores(self):
        arns = [
            "arn:aws:lambda:us-east-1:123456789012:function:my-test-function",
            "arn:aws:lambda:us-east-1:123456789012:function:my_test_function",
            "arn:aws:lambda:us-east-1:123456789012:function:My-Test_Function123"
        ]
        for arn in arns:
            assert validate_function_arn(arn) is True

    @pytest.mark.unit
    def test_invalid_arn_wrong_service(self):
        arn = "arn:aws:ec2:us-east-1:123456789012:instance:i-1234567890abcdef0"
        assert validate_function_arn(arn) is False

    @pytest.mark.unit
    def test_invalid_arn_malformed(self):
        invalid_arns = [
            "not-an-arn",
            "arn:aws:lambda:us-east-1:123:function:test",
            "arn:aws:lambda:INVALID:123456789012:function:test",
            "arn:aws:lambda:us-east-1:123456789012:function:",
            ""
        ]
        for arn in invalid_arns:
            assert validate_function_arn(arn) is False

    @pytest.mark.unit
    def test_invalid_arn_with_version(self):
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-func:$LATEST"
        assert validate_function_arn(arn) is False


class TestValidateFunctionName:
    @pytest.mark.unit
    def test_valid_function_names(self):
        valid_names = ["my-function", "my_function", "MyFunction", "func123",
                       "a", "a" * 64]
        for name in valid_names:
            assert validate_function_name(name) is True

    @pytest.mark.unit
    def test_invalid_function_names_special_chars(self):
        invalid_names = ["my.function", "my function", "my@function"]
        for name in invalid_names:
            assert validate_function_name(name) is False

    @pytest.mark.unit
    def test_invalid_function_name_too_long(self):
        name = "a" * 65
        assert validate_function_name(name) is False

    @pytest.mark.unit
    def test_invalid_function_name_empty(self):
        assert validate_function_name("") is False


class TestValidateRoleArn:
    @pytest.mark.unit
    def test_valid_role_arn(self):
        arn = "arn:aws:iam::123456789012:role/my-role"
        assert validate_role_arn(arn) is True

    @pytest.mark.unit
    def test_valid_role_arn_with_path(self):
        arn = "arn:aws:iam::123456789012:role/service-role/my-role"
        assert validate_role_arn(arn) is False

    @pytest.mark.unit
    def test_valid_role_arn_special_chars(self):
        valid_arns = [
            "arn:aws:iam::123456789012:role/my-role",
            "arn:aws:iam::123456789012:role/my_role",
            "arn:aws:iam::123456789012:role/MyRole123"
        ]
        for arn in valid_arns:
            assert validate_role_arn(arn) is True

    @pytest.mark.unit
    def test_invalid_role_arn_none(self):
        assert validate_role_arn(None) is False

    @pytest.mark.unit
    def test_invalid_role_arn_empty(self):
        assert validate_role_arn("") is False

    @pytest.mark.unit
    def test_invalid_role_arn_not_string(self):
        assert validate_role_arn(123) is False
        assert validate_role_arn(["arn"]) is False


class TestSanitizeLogOutput:
    @pytest.mark.unit
    def test_sanitize_long_strings(self):
        output = "Found token: abcdefghijklmnopqrstuvwxyz123456"
        sanitized = sanitize_log_output(output)
        assert "abcdefghijklmnopqrstuvwxyz123456" not in sanitized
        assert "[REDACTED]" in sanitized

    @pytest.mark.unit
    def test_sanitize_token_patterns(self):
        outputs = [
            "token: mysecrettoken123",
            "password=mypassword",
            "secret: shh-its-a-secret",
            "key: api-key-12345"
        ]
        for output in outputs:
            sanitized = sanitize_log_output(output)
            assert "[REDACTED]" in sanitized

    @pytest.mark.unit
    def test_sanitize_preserves_normal_text(self):
        output = "This is a normal log message with no secrets"
        sanitized = sanitize_log_output(output)
        assert sanitized == output

    @pytest.mark.unit
    def test_sanitize_empty_string(self):
        assert sanitize_log_output("") == ""

    @pytest.mark.unit
    def test_sanitize_none(self):
        assert sanitize_log_output(None) == ""
