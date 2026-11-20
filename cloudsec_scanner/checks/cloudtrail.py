from __future__ import annotations

from ..models import Finding
from .common import add_diagnostic, make_finding


def check_cloudtrail(session, inspection_region: str, findings: list[Finding], diagnostics: list[str]) -> None:
    """Check account-level multi-region trail coverage from one selected region."""
    cloudtrail = session.client("cloudtrail", region_name=inspection_region)
    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", [])
    except Exception as exc:
        add_diagnostic(diagnostics, "CloudTrail trail inventory", exc)
        return

    multi_region_trails = [trail for trail in trails if trail.get("IsMultiRegionTrail") is True]
    if not multi_region_trails:
        findings.append(
            make_finding(
                finding_id="CT-001",
                service="CloudTrail",
                severity="HIGH",
                title="No multi-region CloudTrail trail was detected",
                resource_id="AWS account",
                region="global",
                description="The scanner did not find a multi-region CloudTrail trail in the selected account context. This may indicate incomplete API activity logging; organization-level logging was not independently evaluated.",
                evidence={"trails_returned": len(trails), "multi_region_trails": 0},
                remediation="Configure an organization-approved multi-region CloudTrail trail and centralize logs in a protected S3 destination.",
                compliance_tags=["CIS AWS Foundations", "NIST CSF DE.CM"],
            )
        )
        return

    for trail in multi_region_trails:
        trail_id = trail.get("TrailARN") or trail.get("Name") or "unknown trail"
        try:
            status = cloudtrail.get_trail_status(Name=trail_id)
            if status.get("IsLogging") is not True:
                findings.append(
                    make_finding(
                        finding_id="CT-002",
                        service="CloudTrail",
                        severity="HIGH",
                        title="Multi-region CloudTrail trail is not logging",
                        resource_id=trail_id,
                        region="global",
                        description="The CloudTrail trail exists but its status reports IsLogging=false.",
                        evidence={"is_logging": status.get("IsLogging")},
                        remediation="Start logging after validating the destination bucket, permissions, retention, and approved organization policy.",
                        compliance_tags=["CIS AWS Foundations", "NIST CSF DE.CM"],
                    )
                )
            if trail.get("LogFileValidationEnabled") is not True:
                findings.append(
                    make_finding(
                        finding_id="CT-003",
                        service="CloudTrail",
                        severity="MEDIUM",
                        title="CloudTrail log file validation is not enabled",
                        resource_id=trail_id,
                        region="global",
                        description="The trail metadata does not report log file validation enabled.",
                        evidence={"log_file_validation_enabled": trail.get("LogFileValidationEnabled", False)},
                        remediation="Enable CloudTrail log file validation to help detect modification or deletion of delivered log files.",
                        compliance_tags=["CIS AWS Foundations", "NIST CSF DE.CM"],
                    )
                )
        except Exception as exc:
            add_diagnostic(diagnostics, f"CloudTrail status for {trail_id}", exc)
