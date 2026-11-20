from __future__ import annotations

from ..models import Finding
from ..rules import classify_open_ports, public_ingress_rules
from .common import add_diagnostic, make_finding


def check_security_groups(ec2, region: str, findings: list[Finding], diagnostics: list[str]) -> None:
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for group in page.get("SecurityGroups", []):
                exposed = public_ingress_rules(group.get("IpPermissions", []))
                if not exposed:
                    continue
                severities = [classify_open_ports(rule) for rule in exposed]
                severity = "HIGH" if any(item[0] == "HIGH" for item in severities) else (
                    "MEDIUM" if any(item[0] == "MEDIUM" for item in severities) else "LOW"
                )
                findings.append(
                    make_finding(
                        finding_id="EC2-001",
                        service="EC2 / VPC",
                        severity=severity,
                        title="Security group allows ingress from the entire internet",
                        resource_id=group.get("GroupId", "unknown"),
                        region=region,
                        description="At least one inbound rule allows traffic from 0.0.0.0/0 or ::/0. Public web access can be intentional, but administrative and data-service ports should not be exposed directly.",
                        evidence={
                            "group_name": group.get("GroupName"),
                            "vpc_id": group.get("VpcId"),
                            "public_ingress_rules": exposed,
                            "risk_notes": [note for _, note in severities],
                        },
                        remediation="Restrict inbound CIDRs to trusted networks, use a load balancer for public web traffic, and use VPN or a managed access service for administration.",
                        compliance_tags=["CIS AWS Foundations", "NIST CSF PR.AC"],
                    )
                )
    except Exception as exc:
        add_diagnostic(diagnostics, f"Security group inventory ({region})", exc)
