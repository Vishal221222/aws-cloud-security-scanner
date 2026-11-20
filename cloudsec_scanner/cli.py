from __future__ import annotations

import argparse
import sys

from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

from .aws_session import create_aws_session
from .reports import save_report
from .scanner import CloudSecurityScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only AWS Cloud Security Scanner")
    parser.add_argument("--profile", default=None, help="AWS CLI profile name (optional)")
    parser.add_argument("--regions", default="us-east-1", help="Comma-separated AWS regions")
    parser.add_argument("--output-dir", default="reports", help="Directory for JSON and CSV reports")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    regions = [region.strip() for region in args.regions.split(",") if region.strip()]
    try:
        session = create_aws_session(args.profile, regions[0] if regions else "us-east-1")
        report = CloudSecurityScanner(session).scan(regions)
        json_path, csv_path = save_report(report, args.output_dir)
    except ProfileNotFound as exc:
        print(f"AWS profile not found: {exc}", file=sys.stderr)
        return 2
    except (ClientError, BotoCoreError, ValueError) as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    print(f"Account: {report.account_id}")
    print(f"Caller:  {report.caller_arn}")
    print(f"Regions: {', '.join(report.regions)}")
    print("Findings:")
    for severity, count in report.summary().items():
        if severity != "TOTAL":
            print(f"  {severity:8} {count}")
    print(f"  {'TOTAL':8} {report.summary()['TOTAL']}")
    print(f"JSON report: {json_path}")
    print(f"CSV report:  {csv_path}")
    if report.diagnostics:
        print(f"\nChecks skipped or incomplete: {len(report.diagnostics)}")
        for item in report.diagnostics:
            print(f"  - {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
