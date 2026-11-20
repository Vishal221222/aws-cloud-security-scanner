from __future__ import annotations

from typing import Any

from ..models import Finding
from ..rules import managed_policy_document, policy_has_broad_service_access, policy_has_wildcard_admin_access
from .common import add_diagnostic, make_finding


def _document_finding(
    *,
    findings: list[Finding],
    name: str,
    arn: str,
    document: dict[str, Any],
    source: str,
) -> None:
    if policy_has_wildcard_admin_access(document):
        findings.append(
            make_finding(
                finding_id="IAM-002",
                service="IAM",
                severity="CRITICAL",
                title="IAM policy grants wildcard administrator access",
                resource_id=arn or name,
                region="global",
                description="An Allow statement grants Action '*' on Resource '*'. This is an obvious broad-privilege pattern and should be reviewed against business need.",
                evidence={"policy_name": name, "policy_arn": arn, "policy_source": source},
                remediation="Replace wildcard permissions with narrowly scoped actions and resources. Review the principals attached to this policy and apply least privilege.",
                compliance_tags=["CIS AWS Foundations", "NIST CSF PR.AC"],
            )
        )
        return

    broad = policy_has_broad_service_access(document)
    if broad:
        findings.append(
            make_finding(
                finding_id="IAM-003",
                service="IAM",
                severity="HIGH",
                title="IAM policy grants broad service-level access",
                resource_id=arn or name,
                region="global",
                description="The policy grants one or more service-wide action wildcards on all resources. Validate whether the scope is required.",
                evidence={"policy_name": name, "policy_arn": arn, "broad_actions": broad, "policy_source": source},
                remediation="Replace service-wide action wildcards with the minimum required API actions and resource ARNs; add conditions where appropriate.",
                compliance_tags=["CIS AWS Foundations", "NIST CSF PR.AC"],
            )
        )


def check_iam(session, findings: list[Finding], diagnostics: list[str]) -> None:
    iam = session.client("iam")
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        if summary.get("AccountMFAEnabled", 0) != 1:
            findings.append(
                make_finding(
                    finding_id="IAM-001",
                    service="IAM",
                    severity="HIGH",
                    title="Root account MFA is not enabled",
                    resource_id="AWS account root user",
                    region="global",
                    description="The IAM account summary does not report MFA enabled for the root user.",
                    evidence={"AccountMFAEnabled": summary.get("AccountMFAEnabled", 0)},
                    remediation="Enable MFA for the AWS account root user. Prefer a hardware security key or passkey where supported, and do not use the root user for daily tasks.",
                    compliance_tags=["CIS AWS Foundations", "NIST CSF PR.AA"],
                )
            )
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            findings.append(
                make_finding(
                    finding_id="IAM-004",
                    service="IAM",
                    severity="CRITICAL",
                    title="Root account access keys are present",
                    resource_id="AWS account root user",
                    region="global",
                    description="The account summary reports one or more access keys for the root user. Root access keys create a high-impact credential risk.",
                    evidence={"AccountAccessKeysPresent": summary.get("AccountAccessKeysPresent")},
                    remediation="Deactivate and delete root access keys after confirming they are not required. Use roles or federated identities for automation.",
                    compliance_tags=["CIS AWS Foundations", "NIST CSF PR.AA"],
                )
            )
    except Exception as exc:
        add_diagnostic(diagnostics, "IAM account summary", exc)

    try:
        paginator = iam.get_paginator("get_account_authorization_details")
        seen: set[tuple[str, str]] = set()
        for page in paginator.paginate():
            for policy in page.get("Policies", []):
                detail = managed_policy_document(policy)
                if isinstance(detail, dict):
                    arn = policy.get("Arn", "")
                    name = policy.get("PolicyName", arn or "Managed policy")
                    key = (arn, name)
                    if key not in seen:
                        seen.add(key)
                        _document_finding(
                            findings=findings,
                            name=name,
                            arn=arn,
                            document=detail,
                            source="managed policy",
                        )

            for collection_name, principal_type in (
                ("RoleDetailList", "role"),
                ("UserDetailList", "user"),
                ("GroupDetailList", "group"),
            ):
                for principal in page.get(collection_name, []):
                    principal_name = principal.get("RoleName") or principal.get("UserName") or principal.get("GroupName") or "unknown"
                    principal_arn = principal.get("Arn", principal_name)
                    for inline in principal.get("RolePolicyList", []) + principal.get("UserPolicyList", []) + principal.get("GroupPolicyList", []):
                        document = inline.get("PolicyDocument")
                        if isinstance(document, dict):
                            policy_name = inline.get("PolicyName", "inline policy")
                            key = (principal_arn, policy_name)
                            if key not in seen:
                                seen.add(key)
                                _document_finding(
                                    findings=findings,
                                    name=f"{principal_type}/{principal_name}/{policy_name}",
                                    arn=principal_arn,
                                    document=document,
                                    source="inline policy",
                                )
    except Exception as exc:
        add_diagnostic(diagnostics, "IAM policy inventory", exc)
