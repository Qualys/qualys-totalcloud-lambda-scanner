"""
Bulk Scan Lambda - Scans all existing Lambda functions in an account.

This function is triggered manually or on a schedule to scan existing functions
that weren't caught by the event-driven scanner (CreateFunction/UpdateFunction events).

Usage:
- Invoke manually to scan all functions in an account
- Schedule via EventBridge for periodic full scans
- Pass account_ids list to scan across multiple accounts (centralized mode)

Environment Variables:
- SCANNER_QUEUE_URL: SQS queue URL to send scan requests
- CROSS_ACCOUNT_ROLE_NAME: Role name to assume in spoke accounts (optional)
- SCAN_BATCH_SIZE: Number of functions to queue per batch (default: 100)
- EXCLUDE_PATTERNS: Comma-separated function name patterns to exclude
"""

import boto3
import json
import logging
import os
import re
from typing import List, Dict, Any, Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Clients
lambda_client = boto3.client('lambda')
sqs_client = boto3.client('sqs')
sts_client = boto3.client('sts')

# Environment variables
SCANNER_QUEUE_URL = os.environ.get('SCANNER_QUEUE_URL', '')
CROSS_ACCOUNT_ROLE_NAME = os.environ.get('CROSS_ACCOUNT_ROLE_NAME', '')
SCAN_BATCH_SIZE = int(os.environ.get('SCAN_BATCH_SIZE', '100'))
EXCLUDE_PATTERNS = os.environ.get('EXCLUDE_PATTERNS', 'qualys-lambda-scanner').split(',')

# Validation patterns
ACCOUNT_ID_PATTERN = re.compile(r'^\d{12}$')
FUNCTION_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


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
                logger.info(f"Excluding function: {function_name}")
                continue

            functions.append({
                'FunctionArn': func['FunctionArn'],
                'FunctionName': function_name,
                'CodeSha256': func.get('CodeSha256', ''),
                'Runtime': func.get('Runtime', 'container'),
                'PackageType': func.get('PackageType', 'Zip')
            })

    return functions


def queue_scan_requests(functions: List[Dict[str, Any]], source_account: str) -> Dict[str, int]:
    """Queue scan requests to SQS in batches."""
    if not SCANNER_QUEUE_URL:
        logger.error("SCANNER_QUEUE_URL not configured")
        return {'queued': 0, 'failed': 0}

    queued = 0
    failed = 0

    # Process in batches of 10 (SQS batch limit)
    for i in range(0, len(functions), 10):
        batch = functions[i:i+10]
        entries = []

        for idx, func in enumerate(batch):
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
                    'sourceAccount': source_account
                }
            }

            entries.append({
                'Id': str(idx),
                'MessageBody': json.dumps(scan_event),
                'MessageGroupId': 'bulk-scan',  # For FIFO queues
                'MessageDeduplicationId': f"{func['FunctionArn']}-{func['CodeSha256']}"
            })

        try:
            # Try FIFO queue first, fall back to standard
            try:
                response = sqs_client.send_message_batch(
                    QueueUrl=SCANNER_QUEUE_URL,
                    Entries=entries
                )
            except sqs_client.exceptions.InvalidParameterValue:
                # Standard queue - remove FIFO-specific params
                for entry in entries:
                    entry.pop('MessageGroupId', None)
                    entry.pop('MessageDeduplicationId', None)
                response = sqs_client.send_message_batch(
                    QueueUrl=SCANNER_QUEUE_URL,
                    Entries=entries
                )

            queued += len(response.get('Successful', []))
            failed += len(response.get('Failed', []))

            for failure in response.get('Failed', []):
                logger.error(f"Failed to queue: {failure}")

        except Exception as e:
            logger.error(f"Batch send failed: {e}")
            failed += len(batch)

    return {'queued': queued, 'failed': failed}


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Bulk scan handler.

    Event format:
    {
        "account_ids": ["123456789012", "234567890123"],  # Optional: cross-account
        "dry_run": false,  # Optional: just count, don't queue
        "exclude_patterns": ["test-", "dev-"]  # Optional: additional excludes
    }
    """
    logger.info(f"Bulk scan triggered with event: {json.dumps(event)}")

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
        'queued': 0,
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
            # Get appropriate Lambda client
            if account_id == current_account:
                client = lambda_client
            else:
                client = get_lambda_client_for_account(account_id)
                if not client:
                    results['accounts_failed'] += 1
                    results['details'].append({
                        'account': account_id,
                        'status': 'failed',
                        'error': 'Could not assume role'
                    })
                    continue

            # List all functions
            functions = list_all_functions(client)
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
                # Queue scan requests
                queue_result = queue_scan_requests(functions, account_id)
                results['queued'] += queue_result['queued']
                results['failed'] += queue_result['failed']

                results['details'].append({
                    'account': account_id,
                    'status': 'success',
                    'functions': function_count,
                    'queued': queue_result['queued'],
                    'failed': queue_result['failed']
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
