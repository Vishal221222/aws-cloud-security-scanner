from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    finding_id: str
    service: str
    severity: str
    title: str
    resource_id: str
    region: str
    description: str
    evidence: dict[str, Any]
    remediation: str
    compliance_tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    account_id: str
    caller_arn: str
    scanned_at: str
    regions: list[str]
    findings: list[Finding]
    diagnostics: list[str] = field(default_factory=list)
    scanner_version: str = "1.0.0"

    @classmethod
    def create(
        cls,
        account_id: str,
        caller_arn: str,
        regions: list[str],
        findings: list[Finding],
        diagnostics: list[str] | None = None,
    ) -> "ScanReport":
        return cls(
            account_id=account_id,
            caller_arn=caller_arn,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            regions=regions,
            findings=sorted(
                findings,
                key=lambda item: (
                    SEVERITY_ORDER.get(item.severity, 99),
                    item.service,
                    item.resource_id,
                ),
            ),
            diagnostics=diagnostics or [],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "caller_arn": self.caller_arn,
            "scanned_at": self.scanned_at,
            "regions": self.regions,
            "scanner_version": self.scanner_version,
            "summary": self.summary(),
            "findings": [finding.to_dict() for finding in self.findings],
            "diagnostics": self.diagnostics,
        }

    def summary(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        counts["TOTAL"] = len(self.findings)
        return counts
