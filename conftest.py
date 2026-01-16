import os
import sys

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_REGION", "us-east-1")

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scanner-lambda"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def reset_env(monkeypatch):
    env_vars = [
        "QUALYS_SECRET_ARN",
        "SNS_TOPIC_ARN",
        "RESULTS_S3_BUCKET",
        "SCAN_CACHE_TABLE",
        "ENABLE_TAGGING",
        "SCAN_TIMEOUT",
        "CACHE_TTL_DAYS",
    ]
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch
