#!/usr/bin/env python3

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


DEFAULT_CONFIG = {
    "version": "1.0",
    "qualys": {
        "pod": "US2"
    },
    "aws": {
        "default_region": "us-east-1",
        "stack_name": "qualys-lambda-scanner"
    },
    "deployment": {
        "type": "single-account",
        "regions": ["us-east-1"],
        "stackset": {
            "org_unit_ids": [],
            "auto_deployment": True,
            "retain_on_removal": False
        }
    },
    "scanner": {
        "memory_size": 2048,
        "timeout": 900,
        "ephemeral_storage": 2048,
        "reserved_concurrency": 10,
        "enable_tagging": True,
        "enable_s3_results": True,
        "enable_sns_notifications": True,
        "enable_scan_cache": True,
        "enable_bulk_scan": True,
        "cache_ttl_days": 30
    },
    "bulk_scan": {
        "schedule": "",
        "exclude_patterns": ["qualys-lambda-scanner", "bulk-scan"],
        "invocation_delay_ms": 100,
        "max_workers": 10,
        "batch_size": 100,
        "default_regions": ["us-east-1"]
    },
    "layer": {
        "name": "qscanner"
    }
}


def deep_merge(base: Dict, override: Dict) -> Dict:
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    if config_path:
        path = Path(config_path)
    else:
        search_paths = [
            Path.cwd() / ".qualys-scanner.yml",
            Path.cwd() / "qualys-scanner.yml",
            Path.cwd().parent / ".qualys-scanner.yml",
        ]
        path = None
        for search_path in search_paths:
            if search_path.exists():
                path = search_path
                break

    config = DEFAULT_CONFIG.copy()

    if path and path.exists():
        with open(path) as f:
            file_config = yaml.safe_load(f) or {}
        config = deep_merge(config, file_config)

    config = apply_env_overrides(config)

    return config


def apply_env_overrides(config: Dict[str, Any]) -> Dict[str, Any]:
    if os.environ.get("QUALYS_POD"):
        config["qualys"]["pod"] = os.environ["QUALYS_POD"]

    if os.environ.get("AWS_REGION"):
        config["aws"]["default_region"] = os.environ["AWS_REGION"]
    elif os.environ.get("AWS_DEFAULT_REGION"):
        config["aws"]["default_region"] = os.environ["AWS_DEFAULT_REGION"]

    if os.environ.get("STACK_NAME"):
        config["aws"]["stack_name"] = os.environ["STACK_NAME"]

    if os.environ.get("ORG_UNIT_IDS"):
        ous = [ou.strip() for ou in os.environ["ORG_UNIT_IDS"].split(",") if ou.strip()]
        config["deployment"]["stackset"]["org_unit_ids"] = ous

    if os.environ.get("REGIONS"):
        regions = [r.strip() for r in os.environ["REGIONS"].split(",") if r.strip()]
        config["deployment"]["regions"] = regions

    if os.environ.get("SCANNER_MEMORY_SIZE"):
        try:
            config["scanner"]["memory_size"] = int(os.environ["SCANNER_MEMORY_SIZE"])
        except ValueError:
            pass

    if os.environ.get("SCANNER_TIMEOUT"):
        try:
            config["scanner"]["timeout"] = int(os.environ["SCANNER_TIMEOUT"])
        except ValueError:
            pass

    if os.environ.get("ENABLE_TAGGING"):
        config["scanner"]["enable_tagging"] = os.environ["ENABLE_TAGGING"].lower() == "true"

    if os.environ.get("CACHE_TTL_DAYS"):
        try:
            config["scanner"]["cache_ttl_days"] = int(os.environ["CACHE_TTL_DAYS"])
        except ValueError:
            pass

    if os.environ.get("BULK_SCAN_SCHEDULE"):
        config["bulk_scan"]["schedule"] = os.environ["BULK_SCAN_SCHEDULE"]

    if os.environ.get("MAX_WORKERS"):
        try:
            config["bulk_scan"]["max_workers"] = int(os.environ["MAX_WORKERS"])
        except ValueError:
            pass

    if os.environ.get("BATCH_SIZE"):
        try:
            config["bulk_scan"]["batch_size"] = int(os.environ["BATCH_SIZE"])
        except ValueError:
            pass

    return config


def to_makefile_vars(config: Dict[str, Any]) -> Dict[str, str]:
    vars = {}

    vars["QUALYS_POD"] = config["qualys"]["pod"]
    vars["AWS_REGION"] = config["aws"]["default_region"]
    vars["STACK_NAME"] = config["aws"]["stack_name"]

    vars["DEPLOYMENT_TYPE"] = config["deployment"]["type"]

    regions = config["deployment"]["regions"]
    if regions:
        vars["REGIONS"] = ",".join(regions)

    org_unit_ids = config["deployment"]["stackset"]["org_unit_ids"]
    if org_unit_ids:
        vars["ORG_UNIT_IDS"] = ",".join(org_unit_ids)

    vars["SCANNER_MEMORY_SIZE"] = str(config["scanner"]["memory_size"])
    vars["SCANNER_TIMEOUT"] = str(config["scanner"]["timeout"])
    vars["TAG"] = "true" if config["scanner"]["enable_tagging"] else "false"
    vars["CACHE_TTL_DAYS"] = str(config["scanner"]["cache_ttl_days"])

    vars["ENABLE_S3_RESULTS"] = "true" if config["scanner"]["enable_s3_results"] else "false"
    vars["ENABLE_SNS_NOTIFICATIONS"] = "true" if config["scanner"]["enable_sns_notifications"] else "false"
    vars["ENABLE_SCAN_CACHE"] = "true" if config["scanner"]["enable_scan_cache"] else "false"
    vars["ENABLE_BULK_SCAN"] = "true" if config["scanner"]["enable_bulk_scan"] else "false"

    if config["bulk_scan"]["schedule"]:
        vars["BULK_SCAN_SCHEDULE"] = config["bulk_scan"]["schedule"]

    vars["MAX_WORKERS"] = str(config["bulk_scan"]["max_workers"])
    vars["BATCH_SIZE"] = str(config["bulk_scan"]["batch_size"])

    vars["LAYER_NAME"] = config["layer"]["name"]

    return vars


def print_config(config: Dict[str, Any]) -> None:
    print(yaml.dump(config, default_flow_style=False, sort_keys=False))


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Load and display Qualys Lambda Scanner configuration"
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--makefile-vars", "-m",
        action="store_true",
        help="Output as Makefile variables"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON"
    )

    args = parser.parse_args()
    config = load_config(args.config)

    if args.makefile_vars:
        vars = to_makefile_vars(config)
        for key, value in vars.items():
            print(f"{key}={value}")
    elif args.json:
        import json
        print(json.dumps(config, indent=2))
    else:
        print_config(config)


if __name__ == "__main__":
    main()

