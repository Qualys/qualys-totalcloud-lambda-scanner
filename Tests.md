# Testing Guide

## Quick Start

```bash
source .venv/bin/activate
pip install -e ".[dev]"
make test
```

## Test Types

| Command | Description | AWS Required |
|---------|-------------|--------------|
| `make test` | All unit tests | No |
| `make test-unit` | Unit tests only | No |
| `make test-integration` | Integration tests | Yes |
| `make test-smoke` | Smoke test with real Lambda | Yes |
| `make test-bulk-dry-run` | Bulk scan dry-run test | Yes |
| `make test-coverage` | Tests with coverage report | No |

## Unit Tests (65 tests)

Run without AWS credentials using moto mocking:

```bash
make test-unit
```

### Test Files

| File | Tests | Coverage |
|------|-------|----------|
| `tests/unit/test_validators.py` | 33 | Validation functions |
| `tests/unit/test_bulk_scan.py` | 19 | Bulk scan logic |
| `tests/unit/test_lambda_function.py` | 13 | Scanner Lambda |

## Integration Tests

Require deployed stack and AWS credentials:

```bash
export AWS_REGION=us-east-1
export STACK_NAME=qualys-lambda-scanner
make test-integration
```

### Smoke Test

Deploys a test Lambda, invokes scanner, verifies scan:

```bash
make test-smoke
```

### Bulk Scan Dry Run

Tests bulk scanning without actually scanning:

```bash
make test-bulk-dry-run
```

## Pre-Deployment Validation

```bash
export QUALYS_ACCESS_TOKEN="your-token"
export QUALYS_POD="US2"
make validate
```

Checks:
- AWS credentials valid
- Qualys token format
- QScanner binary exists
- CloudFormation templates valid
- Region format valid

## Coverage Report

```bash
make test-coverage
```

Generates HTML report in `htmlcov/`.

## Test Fixtures

Sample events in `tests/fixtures/events.py`:
- `SAMPLE_CREATE_FUNCTION_EVENT`
- `SAMPLE_UPDATE_CODE_EVENT`
- `SAMPLE_BULK_SCAN_EVENT`
- `SAMPLE_CONTAINER_IMAGE_EVENT`

## Adding Tests

1. Unit tests go in `tests/unit/`
2. Integration tests go in `tests/integration/`
3. Mark tests with `@pytest.mark.unit` or `@pytest.mark.integration`
4. Use fixtures from `tests/conftest.py`
