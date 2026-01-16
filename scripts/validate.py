#!/usr/bin/env python3

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_status(check: str, passed: bool, message: str = "") -> None:
    status = f"{GREEN}OK{RESET}" if passed else f"{RED}FAIL{RESET}"
    msg = f" - {message}" if message else ""
    print(f"  [{status}] {check}{msg}")


def print_warning(check: str, message: str) -> None:
    print(f"  [{YELLOW}WARN{RESET}] {check} - {message}")


def check_aws_credentials() -> Tuple[bool, str]:
    try:
        result = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            identity = json.loads(result.stdout)
            account_id = identity.get("Account", "unknown")
            return True, f"Account {account_id}"
        else:
            return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "Timeout checking credentials"
    except FileNotFoundError:
        return False, "AWS CLI not found"
    except Exception as e:
        return False, str(e)


def check_qualys_token() -> Tuple[bool, str]:
    token = os.environ.get("QUALYS_ACCESS_TOKEN", "")
    if not token:
        return False, "QUALYS_ACCESS_TOKEN not set"

    if not re.match(r"^[a-zA-Z0-9_.-]{20,1000}$", token):
        return False, "Invalid token format"

    return True, f"Token set ({len(token)} chars)"


def check_qualys_pod() -> Tuple[bool, str]:
    pod = os.environ.get("QUALYS_POD", "")
    if not pod:
        return False, "QUALYS_POD not set (use QUALYS_POD=US2 or similar)"

    valid_pods = ["US1", "US2", "US3", "US4", "GOV1", "EU1", "EU2", "EU3",
                  "IN1", "CA1", "AE1", "UK1", "AU1", "KSA1"]

    if pod not in valid_pods:
        return False, f"Invalid POD '{pod}'. Valid: {', '.join(valid_pods)}"

    return True, f"POD={pod}"


def check_qscanner_binary() -> Tuple[bool, str]:
    script_dir = Path(__file__).parent.parent
    qscanner_path = script_dir / "scanner-lambda" / "qscanner.gz"

    if not qscanner_path.exists():
        return False, f"Not found: {qscanner_path}"

    size_mb = qscanner_path.stat().st_size / (1024 * 1024)

    sha_file = qscanner_path.with_suffix(".gz.sha256")
    if sha_file.exists():
        expected_sha = sha_file.read_text().strip().split()[0]
        actual_sha = hashlib.sha256(qscanner_path.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            return False, f"SHA256 mismatch"
        return True, f"Found ({size_mb:.1f} MB, SHA256 verified)"

    return True, f"Found ({size_mb:.1f} MB)"


def check_cloudformation_templates() -> Tuple[bool, str]:
    script_dir = Path(__file__).parent.parent
    cfn_dir = script_dir / "cloudformation"

    if not cfn_dir.exists():
        return False, "cloudformation/ directory not found"

    templates = list(cfn_dir.glob("*.yaml"))
    if not templates:
        return False, "No YAML templates found"

    try:
        result = subprocess.run(
            ["cfn-lint", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        cfn_lint_available = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        cfn_lint_available = False

    if cfn_lint_available:
        errors = []
        for template in templates:
            result = subprocess.run(
                ["cfn-lint", str(template)],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode != 0:
                errors.append(template.name)

        if errors:
            return False, f"Lint errors in: {', '.join(errors)}"
        return True, f"{len(templates)} templates validated"
    else:
        return True, f"{len(templates)} templates found (install cfn-lint for validation)"


def check_region(region: str = None) -> Tuple[bool, str]:
    region = region or os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", ""))
    if not region:
        return False, "AWS_REGION not set"

    if not re.match(r"^[a-z]{2}-[a-z]+-\d+$", region):
        return False, f"Invalid region format: {region}"

    return True, f"Region={region}"


def check_org_unit_ids(ou_ids: str = None) -> Tuple[bool, str]:
    ou_ids = ou_ids or os.environ.get("ORG_UNIT_IDS", "")
    if not ou_ids:
        return True, "Not set (not required for single-account)"

    pattern = r"^ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}$"
    ous = [ou.strip() for ou in ou_ids.split(",")]

    invalid = [ou for ou in ous if not re.match(pattern, ou)]
    if invalid:
        return False, f"Invalid OU format: {', '.join(invalid)}"

    return True, f"{len(ous)} OUs configured"


def check_make_available() -> Tuple[bool, str]:
    try:
        result = subprocess.run(
            ["make", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            version = result.stdout.split("\n")[0]
            return True, version
        return False, "make command failed"
    except FileNotFoundError:
        return False, "make not found"
    except subprocess.TimeoutExpired:
        return False, "Timeout"


def run_validation(deployment_type: str = "single-account") -> int:
    print(f"\n{BOLD}Qualys Lambda Scanner - Pre-flight Validation{RESET}\n")
    print(f"Deployment type: {deployment_type}\n")

    all_passed = True
    warnings = []

    print(f"{BOLD}Required Checks:{RESET}")

    passed, msg = check_aws_credentials()
    print_status("AWS Credentials", passed, msg)
    all_passed = all_passed and passed

    passed, msg = check_qualys_token()
    print_status("Qualys Token", passed, msg)
    all_passed = all_passed and passed

    passed, msg = check_qualys_pod()
    print_status("Qualys POD", passed, msg)
    all_passed = all_passed and passed

    passed, msg = check_qscanner_binary()
    print_status("QScanner Binary", passed, msg)
    all_passed = all_passed and passed

    passed, msg = check_region()
    print_status("AWS Region", passed, msg)
    all_passed = all_passed and passed

    if deployment_type in ["stackset", "hub-spoke"]:
        print(f"\n{BOLD}Multi-Account Checks:{RESET}")

        passed, msg = check_org_unit_ids()
        print_status("Organization Unit IDs", passed, msg)
        if deployment_type == "stackset" and not passed:
            all_passed = False

    print(f"\n{BOLD}Optional Checks:{RESET}")

    passed, msg = check_cloudformation_templates()
    print_status("CloudFormation Templates", passed, msg)
    if not passed:
        warnings.append(("CloudFormation", msg))

    passed, msg = check_make_available()
    print_status("Make Available", passed, msg)
    if not passed:
        warnings.append(("Make", msg))

    print()
    if warnings:
        print(f"{YELLOW}Warnings:{RESET}")
        for check, msg in warnings:
            print(f"  - {check}: {msg}")
        print()

    if all_passed:
        print(f"{GREEN}{BOLD}All required checks passed!{RESET}")
        print("You can proceed with deployment.\n")
        return 0
    else:
        print(f"{RED}{BOLD}Some checks failed.{RESET}")
        print("Please fix the issues above before deploying.\n")
        return 1


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Pre-flight validation for Qualys Lambda Scanner deployment"
    )
    parser.add_argument(
        "--type", "-t",
        choices=["single-account", "stackset", "hub-spoke"],
        default="single-account",
        help="Deployment type (default: single-account)"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only show failures"
    )

    args = parser.parse_args()
    sys.exit(run_validation(args.type))


if __name__ == "__main__":
    main()

