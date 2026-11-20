from __future__ import annotations

from botocore.exceptions import BotoCoreError

from .checks.cloudtrail import check_cloudtrail
from .checks.compute import check_ebs_volumes, check_rds_instances
from .checks.iam import check_iam
from .checks.network import check_security_groups
from .checks.s3 import check_s3
from .models import ScanReport


class CloudSecurityScanner:
    """Read-only AWS configuration scanner. It never changes AWS resources."""

    def __init__(self, session):
        self.session = session

    def scan(self, regions: list[str]) -> ScanReport:
        normalized_regions = list(dict.fromkeys(region.strip() for region in regions if region.strip()))
        if not normalized_regions:
            raise ValueError("Provide at least one AWS region, e.g. us-east-1")

        diagnostics: list[str] = []
        findings = []
        identity = self.session.client("sts").get_caller_identity()

        # Global services are checked once.
        check_s3(self.session, findings, diagnostics)
        check_iam(self.session, findings, diagnostics)
        check_cloudtrail(self.session, normalized_regions[0], findings, diagnostics)

        # Regional resources are checked in each requested region.
        for region in normalized_regions:
            ec2 = self.session.client("ec2", region_name=region)
            rds = self.session.client("rds", region_name=region)
            check_security_groups(ec2, region, findings, diagnostics)
            check_ebs_volumes(ec2, region, findings, diagnostics)
            check_rds_instances(rds, region, findings, diagnostics)

        return ScanReport.create(
            account_id=identity.get("Account", "unknown"),
            caller_arn=identity.get("Arn", "unknown"),
            regions=normalized_regions,
            findings=findings,
            diagnostics=diagnostics,
        )
