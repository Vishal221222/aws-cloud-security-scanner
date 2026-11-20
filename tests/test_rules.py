from cloudsec_scanner.rules import (
    classify_open_ports,
    managed_policy_document,
    policy_has_broad_service_access,
    policy_has_wildcard_admin_access,
    public_ingress_rules,
)


def test_detects_world_open_ipv4_ingress():
    rules = public_ingress_rules([
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ])
    assert len(rules) == 1
    assert rules[0]["from_port"] == 22
    assert classify_open_ports(rules[0])[0] == "HIGH"


def test_does_not_flag_restricted_cidr_as_public():
    rules = public_ingress_rules([
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "203.0.113.10/32"}],
        }
    ])
    assert rules == []


def test_detects_world_open_ipv6_ingress():
    rules = public_ingress_rules([
        {
            "IpProtocol": "-1",
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
    ])
    assert len(rules) == 1
    assert classify_open_ports(rules[0])[0] == "HIGH"


def test_detects_wildcard_admin_policy():
    doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    assert policy_has_wildcard_admin_access(doc) is True


def test_ignores_read_only_scoped_policy():
    doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::example/*"}]}
    assert policy_has_wildcard_admin_access(doc) is False
    assert policy_has_broad_service_access(doc) == []


def test_detects_broad_service_wildcard():
    doc = {"Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}
    assert policy_has_wildcard_admin_access(doc) is False
    assert policy_has_broad_service_access(doc) == ["ec2:*"]


def test_extracts_default_managed_policy_version_document():
    detail = {
        "DefaultVersionId": "v2",
        "PolicyVersionList": [
            {"VersionId": "v1", "IsDefaultVersion": False, "Document": {"Statement": []}},
            {"VersionId": "v2", "IsDefaultVersion": True, "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
        ],
    }
    document = managed_policy_document(detail)
    assert document is not None
    assert policy_has_wildcard_admin_access(document) is True
