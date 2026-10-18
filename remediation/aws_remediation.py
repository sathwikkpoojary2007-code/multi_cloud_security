"""
AWS remediation actions for MultiCloudSecurity.

This module contains the actual AWS configuration changes.

Safety:
    Remediation is only executed when explicitly approved.
"""

import boto3


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
    session = boto3.Session(
        aws_access_key_id=credentials.get("access_key_id") or None,
        aws_secret_access_key=credentials.get("secret_access_key") or None,
        aws_session_token=credentials.get("session_token") or None,
        region_name=region_name or credentials.get("region") or None,
    )
    s3 = session.client("s3", region_name=region_name) if region_name else session.client("s3")

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
