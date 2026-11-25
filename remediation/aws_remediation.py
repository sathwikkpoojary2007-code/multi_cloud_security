"""
AWS remediation actions for MultiCloudSecurity.

This module contains the actual AWS configuration changes.

Safety:
    Remediation is only executed when explicitly approved.
"""

import boto3
from connectors.aws_session import create_session


def enable_s3_block_public_access(
    bucket_name,
    region_name=None,
    credentials=None,
):
    """
    Enable all four S3 Block Public Access controls.

    This is the remediation for AWS-S3-001.
    """

    credentials = credentials or {}
    if credentials.get("access_key_id") or credentials.get("role_arn") or credentials.get("profile"):
        session = create_session(credentials, region_name=region_name)
        if not region_name:
            try:
                loc = session.client("s3").get_bucket_location(Bucket=bucket_name).get("LocationConstraint")
                region_name = loc or "us-east-1"
                if region_name == "EU":
                    region_name = "eu-west-1"
            except Exception:
                region_name = credentials.get("region") or None
        s3 = session.client("s3", region_name=region_name) if region_name else session.client("s3")
    else:
        s3 = boto3.client("s3", region_name=region_name) if region_name else boto3.client("s3")

    response = s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    )

    return {
        "provider": "aws",
        "resource_id": bucket_name,
        "action": "ENABLE_S3_BLOCK_PUBLIC_ACCESS",
        "status": "APPLIED",
        "response": str(response)
    }
