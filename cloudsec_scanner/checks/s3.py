from __future__ import annotations

from botocore.exceptions import ClientError

from ..models import Finding
from .common import add_diagnostic, make_finding


PUBLIC_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}


def check_s3(session, findings: list[Finding], diagnostics: list[str]) -> None:
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as exc:  # permissions and service errors are surfaced as diagnostics
        add_diagnostic(diagnostics, "S3 bucket inventory", exc)
        return

    for bucket in buckets:
        name = bucket["Name"]
        resource = f"arn:aws:s3:::{name}"
        bucket_region = "unknown"
        try:
            location = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            bucket_region = location or "us-east-1"
        except Exception as exc:
            add_diagnostic(diagnostics, f"S3 region lookup for {name}", exc)

        try:
            config = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            missing_flags = [
                key
                for key in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
                if config.get(key) is not True
            ]
            if missing_flags:
                findings.append(
                    make_finding(
                        finding_id="S3-001",
                        service="S3",
                        severity="HIGH",
                        title="S3 Block Public Access is not fully enabled",
                        resource_id=resource,
                        region=bucket_region,
                        description="One or more bucket-level S3 Block Public Access controls are disabled or not configured.",
                        evidence={"flags_not_enabled": missing_flags},
                        remediation="Enable all four S3 Block Public Access settings unless a documented exception requires public access.",
                        compliance_tags=["CIS AWS Foundations", "NIST CSF PR.AC"],
                    )
                )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchPublicAccessBlockConfiguration":
                findings.append(
                    make_finding(
                        finding_id="S3-001",
                        service="S3",
                        severity="HIGH",
                        title="S3 Block Public Access configuration is missing",
                        resource_id=resource,
                        region=bucket_region,
                        description="No bucket-level S3 Block Public Access configuration was found.",
                        evidence={"error_code": code},
                        remediation="Configure all four S3 Block Public Access settings and review account-level public access controls.",
                        compliance_tags=["CIS AWS Foundations", "NIST CSF PR.AC"],
                    )
                )
            else:
                add_diagnostic(diagnostics, f"S3 public access block for {name}", exc)
        except Exception as exc:
            add_diagnostic(diagnostics, f"S3 public access block for {name}", exc)

        try:
            status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
            if status.get("IsPublic") is True:
                findings.append(
                    make_finding(
                        finding_id="S3-002",
                        service="S3",
                        severity="CRITICAL",
                        title="S3 bucket policy allows public access",
                        resource_id=resource,
                        region=bucket_region,
                        description="AWS reports that the bucket policy grants public access.",
                        evidence={"is_public": True},
                        remediation="Review and remove unintended public principals or actions from the bucket policy. Preserve public access only for a documented public website or data distribution use case.",
                        compliance_tags=["CIS AWS Foundations", "NIST CSF PR.AC"],
                    )
                )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in {"NoSuchBucketPolicy"}:
                add_diagnostic(diagnostics, f"S3 bucket policy status for {name}", exc)
        except Exception as exc:
            add_diagnostic(diagnostics, f"S3 bucket policy status for {name}", exc)

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            public_grants = []
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI")
                if uri in PUBLIC_GROUP_URIS:
                    public_grants.append(
                        {"group": PUBLIC_GROUP_URIS[uri], "permission": grant.get("Permission", "unknown")}
                    )
            if public_grants:
                findings.append(
                    make_finding(
                        finding_id="S3-003",
                        service="S3",
                        severity="MEDIUM",
                        title="S3 bucket ACL contains a public group grant",
                        resource_id=resource,
                        region=bucket_region,
                        description="The bucket ACL contains a grant to AllUsers or AuthenticatedUsers. Account or bucket public-access controls may still block effective access.",
                        evidence={"public_grants": public_grants},
                        remediation="Remove public ACL grants unless they are explicitly required; prefer bucket policies and account-level Block Public Access controls.",
                        compliance_tags=["CIS AWS Foundations", "NIST CSF PR.AC"],
                    )
                )
        except Exception as exc:
            add_diagnostic(diagnostics, f"S3 bucket ACL for {name}", exc)

        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(
                    make_finding(
                        finding_id="S3-004",
                        service="S3",
                        severity="LOW",
                        title="No explicit S3 bucket encryption configuration found",
                        resource_id=resource,
                        region=bucket_region,
                        description="The bucket has no explicit server-side encryption configuration. Amazon S3 applies SSE-S3 encryption by default to new objects, so this finding means an explicit bucket-level encryption policy was not detected; it does not prove existing objects are unencrypted.",
                        evidence={"error_code": code},
                        remediation="Set an explicit default encryption configuration, preferably SSE-KMS where key control and audit requirements call for it.",
                        compliance_tags=["NIST CSF PR.DS", "CIS AWS Foundations"],
                    )
                )
            else:
                add_diagnostic(diagnostics, f"S3 encryption configuration for {name}", exc)
        except Exception as exc:
            add_diagnostic(diagnostics, f"S3 encryption configuration for {name}", exc)

        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                findings.append(
                    make_finding(
                        finding_id="S3-005",
                        service="S3",
                        severity="LOW",
                        title="S3 bucket versioning is not enabled",
                        resource_id=resource,
                        region=bucket_region,
                        description="Bucket versioning is not enabled, reducing recovery options after accidental deletion or overwrite.",
                        evidence={"versioning_status": versioning.get("Status", "NotConfigured")},
                        remediation="Enable versioning where recovery, retention, or object-lock workflows require it; define lifecycle rules to manage storage costs.",
                        compliance_tags=["NIST CSF PR.DS"],
                    )
                )
        except Exception as exc:
            add_diagnostic(diagnostics, f"S3 versioning for {name}", exc)

        try:
            logging = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
            if not logging:
                findings.append(
                    make_finding(
                        finding_id="S3-006",
                        service="S3",
                        severity="LOW",
                        title="S3 server access logging is not configured",
                        resource_id=resource,
                        region=bucket_region,
                        description="S3 server access logging is not configured for this bucket. Other logging mechanisms may exist, but this check did not find bucket-level server access logging.",
                        evidence={"logging_enabled": False},
                        remediation="Enable S3 server access logging or document an approved alternative for access auditing.",
                        compliance_tags=["NIST CSF DE.CM", "CIS AWS Foundations"],
                    )
                )
        except Exception as exc:
            add_diagnostic(diagnostics, f"S3 logging for {name}", exc)
