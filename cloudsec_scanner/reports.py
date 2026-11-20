from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from .models import ScanReport


def json_bytes(report: ScanReport) -> bytes:
    return json.dumps(report.to_dict(), indent=2, default=str).encode("utf-8")


def csv_bytes(report: ScanReport) -> bytes:
    buffer = io.StringIO(newline="")
    fieldnames = [
        "finding_id", "severity", "service", "title", "resource_id", "region",
        "description", "evidence", "remediation", "compliance_tags",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for finding in report.findings:
        row = finding.to_dict()
        row["evidence"] = json.dumps(row["evidence"], default=str)
        row["compliance_tags"] = "; ".join(row["compliance_tags"])
        writer.writerow({key: row.get(key, "") for key in fieldnames})
    return buffer.getvalue().encode("utf-8-sig")


def save_report(report: ScanReport, output_dir: str | Path = "reports") -> tuple[Path, Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    safe_timestamp = report.scanned_at.replace(":", "-").replace("+", "_")
    stem = f"aws-security-scan-{report.account_id}-{safe_timestamp}"
    json_path = output_path / f"{stem}.json"
    csv_path = output_path / f"{stem}.csv"
    json_path.write_bytes(json_bytes(report))
    csv_path.write_bytes(csv_bytes(report))
    return json_path, csv_path
