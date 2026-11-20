from __future__ import annotations

from collections.abc import Iterable
from typing import Any


WORLD_IPV4 = "0.0.0.0/0"
WORLD_IPV6 = "::/0"
SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def public_ingress_rules(permissions: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return security-group ingress permissions open to the entire IPv4/IPv6 internet."""
    exposed: list[dict[str, Any]] = []
    for permission in permissions:
        world_ranges: list[str] = []
        for item in permission.get("IpRanges", []) or []:
            if item.get("CidrIp") == WORLD_IPV4:
                world_ranges.append(WORLD_IPV4)
        for item in permission.get("Ipv6Ranges", []) or []:
            if item.get("CidrIpv6") == WORLD_IPV6:
                world_ranges.append(WORLD_IPV6)
        if world_ranges:
            exposed.append(
                {
                    "protocol": permission.get("IpProtocol", "unknown"),
                    "from_port": permission.get("FromPort"),
                    "to_port": permission.get("ToPort"),
                    "world_ranges": sorted(set(world_ranges)),
                }
            )
    return exposed


def policy_has_wildcard_admin_access(policy_document: dict[str, Any]) -> bool:
    """Detect Allow statements granting every action on every resource.

    This deliberately identifies an obvious high-risk pattern, not every possible
    privilege-escalation path. Conditions, NotAction and policy variables are not
    interpreted as a full IAM policy evaluation engine.
    """
    statements = _as_list(policy_document.get("Statement"))
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = _as_list(statement.get("Action"))
        resources = _as_list(statement.get("Resource"))
        has_all_actions = any(str(action).strip() in {"*", "*:*"} for action in actions)
        has_all_resources = any(str(resource).strip() == "*" for resource in resources)
        if has_all_actions and has_all_resources:
            return True
    return False


def policy_has_broad_service_access(policy_document: dict[str, Any]) -> list[str]:
    """Return service wildcards granted on all resources, e.g. ec2:* on *."""
    broad_services: set[str] = set()
    statements = _as_list(policy_document.get("Statement"))
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        resources = _as_list(statement.get("Resource"))
        if "*" not in [str(resource).strip() for resource in resources]:
            continue
        for action in _as_list(statement.get("Action")):
            action_text = str(action).strip()
            if action_text.endswith(":*") and action_text not in {"*:*"}:
                broad_services.add(action_text)
    return sorted(broad_services)


def classify_open_ports(rule: dict[str, Any]) -> tuple[str, str]:
    """Return (severity, explanation) for an internet-exposed security-group rule."""
    protocol = str(rule.get("protocol", ""))
    start = rule.get("from_port")
    end = rule.get("to_port")
    if protocol == "-1" or start is None or end is None:
        return "HIGH", "All protocols or all ports are exposed to the internet."

    exposed_sensitive = [
        f"{port} ({name})"
        for port, name in SENSITIVE_PORTS.items()
        if int(start) <= port <= int(end)
    ]
    if exposed_sensitive:
        return "HIGH", "Internet-exposed administrative or data-service ports: " + ", ".join(exposed_sensitive)
    if int(start) <= 443 <= int(end) or int(start) <= 80 <= int(end):
        if int(start) == int(end) and int(start) in {80, 443}:
            return "LOW", "Public web traffic can be intentional; verify that the service is designed to be internet-facing."
    return "MEDIUM", "A port range is reachable from the entire internet; verify that public access is required."


def managed_policy_document(policy_detail: dict[str, Any]) -> dict[str, Any] | None:
    """Extract the default IAM managed-policy version document from IAM API output."""
    direct = policy_detail.get("PolicyDocument")
    if isinstance(direct, dict):
        return direct
    versions = _as_list(policy_detail.get("PolicyVersionList"))
    default_version_id = policy_detail.get("DefaultVersionId")
    for version in versions:
        if version.get("IsDefaultVersion") is True or version.get("VersionId") == default_version_id:
            document = version.get("Document")
            return document if isinstance(document, dict) else None
    return None
