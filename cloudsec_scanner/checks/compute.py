from __future__ import annotations

from ..models import Finding
from .common import add_diagnostic, make_finding


def check_ebs_volumes(ec2, region: str, findings: list[Finding], diagnostics: list[str]) -> None:
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                if volume.get("Encrypted") is False:
                    findings.append(
                        make_finding(
                            finding_id="EC2-002",
                            service="EBS",
                            severity="MEDIUM",
                            title="EBS volume is not encrypted",
                            resource_id=volume.get("VolumeId", "unknown"),
                            region=region,
                            description="The EBS volume metadata reports Encrypted=false.",
                            evidence={
                                "encrypted": volume.get("Encrypted"),
                                "state": volume.get("State"),
                                "size_gib": volume.get("Size"),
                                "attached_instance_ids": [item.get("InstanceId") for item in volume.get("Attachments", [])],
                            },
                            remediation="Plan an approved migration to an encrypted EBS volume or snapshot. Enable EBS encryption by default for future volumes in the region.",
                            compliance_tags=["NIST CSF PR.DS", "CIS AWS Foundations"],
                        )
                    )
    except Exception as exc:
        add_diagnostic(diagnostics, f"EBS volume inventory ({region})", exc)


def check_rds_instances(rds, region: str, findings: list[Finding], diagnostics: list[str]) -> None:
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                db_id = db.get("DBInstanceIdentifier", "unknown")
                arn = db.get("DBInstanceArn", db_id)
                if db.get("PubliclyAccessible") is True:
                    findings.append(
                        make_finding(
                            finding_id="RDS-001",
                            service="RDS",
                            severity="HIGH",
                            title="RDS database instance is publicly accessible",
                            resource_id=arn,
                            region=region,
                            description="The RDS instance metadata reports PubliclyAccessible=true. Network controls may still restrict actual reachability; verify the subnet and security-group paths.",
                            evidence={"db_instance_identifier": db_id, "publicly_accessible": True, "engine": db.get("Engine")},
                            remediation="Disable public accessibility unless explicitly required. Prefer private subnets and tightly scoped security-group rules.",
                            compliance_tags=["CIS AWS Foundations", "NIST CSF PR.AC"],
                        )
                    )
                if db.get("StorageEncrypted") is False:
                    findings.append(
                        make_finding(
                            finding_id="RDS-002",
                            service="RDS",
                            severity="MEDIUM",
                            title="RDS database storage is not encrypted",
                            resource_id=arn,
                            region=region,
                            description="The RDS instance metadata reports StorageEncrypted=false.",
                            evidence={"db_instance_identifier": db_id, "storage_encrypted": False, "engine": db.get("Engine")},
                            remediation="Plan a supported migration or snapshot-copy workflow to an encrypted database instance. Confirm application downtime and backup requirements before changes.",
                            compliance_tags=["NIST CSF PR.DS", "CIS AWS Foundations"],
                        )
                    )
    except Exception as exc:
        add_diagnostic(diagnostics, f"RDS inventory ({region})", exc)
