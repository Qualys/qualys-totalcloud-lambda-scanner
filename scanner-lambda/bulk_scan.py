"""
Bulk Scan Lambda - Scans all existing Lambda functions in an account.

This function is triggered manually or on a schedule to scan existing functions
that weren't caught by the event-driven scanner (CreateFunction/UpdateFunction events).

Architecture:
- Directly invokes the scanner Lambda asynchronously for each function
- Uses the existing DynamoDB cache to skip already-scanned functions
- No additional SQS queue needed - keeps costs minimal

Usage:
- Invoke manually to scan all functions in an account
- Schedule via EventBridge for periodic full scans (e.g., weekly)
- Pass account_ids list to scan across multiple accounts (centralized mode)

Environment Variables:
- SCANNER_FUNCTION_NAME: Name of the scanner Lambda to invoke
- CROSS_ACCOUNT_ROLE_NAME: Role name to assume in spoke accounts (optional)
- EXCLUDE_PATTERNS: Comma-separated function name patterns to exclude
- INVOCATION_DELAY_MS: Delay between invocations to avoid throttling (default: 100)
"""

import boto3
import json
import logging
import os
import re
import time
from typing import List, Dict, Any, Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Clients
lambda_client = boto3.client('lambda')
sts_client = boto3.client('sts')

# Environment variables
SCANNER_FUNCTION_NAME = os.environ.get('SCANNER_FUNCTION_NAME', '')
CROSS_ACCOUNT_ROLE_NAME = os.environ.get('CROSS_ACCOUNT_ROLE_NAME', '')
EXCLUDE_PATTERNS = os.environ.get('EXCLUDE_PATTERNS', 'qualys-lambda-scanner,bulk-scan').split(',')
INVOCATION_DELAY_MS = int(os.environ.get('INVOCATION_DELAY_MS', '100'))

# Validation patterns
ACCOUNT_ID_PATTERN = re.compile(r'^\d{12}$')


def validate_account_id(account_id: str) -> bool:
    """Validate AWS account ID format."""
    return bool(ACCOUNT_ID_PATTERN.match(account_id))


def should_exclude(function_name: str) -> bool:
    """Check if function should be excluded from scanning."""
    for pattern in EXCLUDE_PATTERNS:
        pattern = pattern.strip()
        if pattern and pattern in function_name:
            return True
    return False


def get_lambda_client_for_account(account_id: str) -> Optional[boto3.client]:
    """Get Lambda client for a specific account (cross-account)."""
    if not CROSS_ACCOUNT_ROLE_NAME:
        return None

    if not validate_account_id(account_id):
        logger.error(f"Invalid account ID format: {account_id}")
        return None

    try:
        role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}"
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='BulkScanSession',
            DurationSeconds=3600,
            ExternalId='qualys-lambda-scanner'
        )

        return boto3.client(
            'lambda',
            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
            aws_session_token=assumed_role['Credentials']['SessionToken']
        )
    except Exception as e:
        logger.error(f"Failed to assume role in account {account_id}: {e}")
        return None


def list_all_functions(client: boto3.client) -> List[Dict[str, Any]]:
    """List all Lambda functions using pagination."""
    functions = []
    paginator = client.get_paginator('list_functions')

    for page in paginator.paginate():
        for func in page.get('Functions', []):
            function_name = func.get('FunctionName', '')

            # Skip excluded functions
            if should_exclude(function_name):
                logger.debug(f"Excluding function: {function_name}")
                continue

            functions.append({
                'FunctionArn': func['FunctionArn'],
                'FunctionName': function_name,
                'CodeSha256': func.get('CodeSha256', ''),
                'Runtime': func.get('Runtime', 'container'),
                'PackageType': func.get('PackageType', 'Zip')
            })

    return functions


def invoke_scanner(func: Dict[str, Any], source_account: str) -> bool:
    """Invoke scanner Lambda asynchronously for a single function."""
    if not SCANNER_FUNCTION_NAME:
        logger.error("SCANNER_FUNCTION_NAME not configured")
        return False

    # Create a synthetic CloudTrail-like event for the scanner
    scan_event = {
        'source': 'qualys.bulk-scan',
        'detail-type': 'Bulk Scan Request',
        'detail': {
            'eventName': 'BulkScanRequest',
            'eventSource': 'lambda.amazonaws.com',
            'requestParameters': {
                'functionName': func['FunctionArn']
            },
            'responseElements': {
                'functionArn': func['FunctionArn'],
                'functionName': func['FunctionName'],
                'codeSha256': func['CodeSha256'],
                'runtime': func['Runtime'],
                'packageType': func['PackageType']
            },
            'userIdentity': {
                'accountId': source_account
            }
        }
    }

    try:
        lambda_client.invoke(
            FunctionName=SCANNER_FUNCTION_NAME,
            InvocationType='Event',  # Async invocation
            Payload=json.dumps(scan_event)
        )
        return True
    except Exception as e:
        logger.error(f"Failed to invoke scanner for {func['FunctionName']}: {e}")
        return False


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Bulk scan handler.

    Event format:
    {
        "account_ids": ["123456789012", "234567890123"],  # Optional: cross-account
        "dry_run": false,  # Optional: just count, don't invoke scanner
        "exclude_patterns": ["test-", "dev-"]  # Optional: additional excludes
    }
    """
    logger.info(f"Bulk scan triggered with event: {json.dumps(event)}")

    # Validate scanner function is configured
    if not SCANNER_FUNCTION_NAME:
        return {
            'statusCode': 500,
            'body': {'error': 'SCANNER_FUNCTION_NAME not configured'}
        }

    # Parse event
    account_ids = event.get('account_ids', [])
    dry_run = event.get('dry_run', False)
    additional_excludes = event.get('exclude_patterns', [])

    # Add additional exclude patterns
    global EXCLUDE_PATTERNS
    EXCLUDE_PATTERNS = EXCLUDE_PATTERNS + additional_excludes

    results = {
        'accounts_processed': 0,
        'accounts_failed': 0,
        'total_functions': 0,
        'invoked': 0,
        'failed': 0,
        'excluded': 0,
        'details': []
    }

    # Get current account ID
    current_account = sts_client.get_caller_identity()['Account']

    # If no account IDs specified, scan current account
    if not account_ids:
        account_ids = [current_account]

    for account_id in account_ids:
        account_id = str(account_id).strip()

        if not validate_account_id(account_id):
            logger.error(f"Invalid account ID: {account_id}")
            results['accounts_failed'] += 1
            continue

        logger.info(f"Processing account: {account_id}")

        try:
            # Get appropriate Lambda client for listing
            if account_id == current_account:
                list_client = lambda_client
            else:
                list_client = get_lambda_client_for_account(account_id)
                if not list_client:
                    results['accounts_failed'] += 1
                    results['details'].append({
                        'account': account_id,
                        'status': 'failed',
                        'error': 'Could not assume role'
                    })
                    continue

            # List all functions
            functions = list_all_functions(list_client)
            function_count = len(functions)
            results['total_functions'] += function_count

            logger.info(f"Found {function_count} functions in account {account_id}")

            if dry_run:
                results['details'].append({
                    'account': account_id,
                    'status': 'dry_run',
                    'functions': function_count
                })
            else:
                # Invoke scanner for each function
                invoked = 0
                failed = 0

                for func in functions:
                    if invoke_scanner(func, account_id):
                        invoked += 1
                    else:
                        failed += 1

                    # Small delay to avoid throttling
                    if INVOCATION_DELAY_MS > 0:
                        time.sleep(INVOCATION_DELAY_MS / 1000.0)

                results['invoked'] += invoked
                results['failed'] += failed

                results['details'].append({
                    'account': account_id,
                    'status': 'success',
                    'functions': function_count,
                    'invoked': invoked,
                    'failed': failed
                })

            results['accounts_processed'] += 1

        except Exception as e:
            logger.error(f"Error processing account {account_id}: {e}")
            results['accounts_failed'] += 1
            results['details'].append({
                'account': account_id,
                'status': 'error',
                'error': str(e)
            })

    logger.info(f"Bulk scan complete: {json.dumps(results)}")

    return {
        'statusCode': 200,
        'body': results
    }
