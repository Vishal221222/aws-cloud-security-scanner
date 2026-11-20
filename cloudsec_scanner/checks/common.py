from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from ..models import Finding


def error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        return str(error.response.get("Error", {}).get("Code", "UnknownClientError"))
    return error.__class__.__name__


def add_diagnostic(diagnostics: list[str], component: str, error: Exception) -> None:
    diagnostics.append(f"{component}: {error_code(error)} — {str(error)[:240]}")


def make_finding(
    *,
    finding_id: str,
    service: str,
    severity: str,
    title: str,
    resource_id: str,
    region: str,
    description: str,
    evidence: dict[str, Any] | None = None,
    remediation: str,
    compliance_tags: list[str] | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        service=service,
        severity=severity,
        title=title,
        resource_id=resource_id,
        region=region,
        description=description,
        evidence=evidence or {},
        remediation=remediation,
        compliance_tags=compliance_tags or [],
    )
