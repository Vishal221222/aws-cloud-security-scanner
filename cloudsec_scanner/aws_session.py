from __future__ import annotations

import boto3


def create_aws_session(profile_name: str | None = None, default_region: str = "us-east-1"):
    """Use the standard AWS credential chain; credentials are never stored by this app."""
    profile = profile_name.strip() if profile_name and profile_name.strip() else None
    return boto3.Session(profile_name=profile, region_name=default_region)
