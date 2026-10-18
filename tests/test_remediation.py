from unittest.mock import patch

from remediation.remediation_engine import (
    remediate_finding
)


def test_remediation_requires_approval():

    recommendation = {
        "provider": "aws",
        "resource_id": "test-bucket",
        "remediation_type": (
            "AWS_S3_BLOCK_PUBLIC_ACCESS"
        ),
        "status": "PENDING_APPROVAL"
    }

    result = remediate_finding(
        recommendation,
        approved=False
    )

    assert result["status"] == (
        "PENDING_APPROVAL"
    )


@patch(
    "remediation.aws_remediation.boto3.client"
)
def test_approved_s3_remediation(
    mock_boto_client
):

    mock_s3 = mock_boto_client.return_value

    mock_s3.put_public_access_block.return_value = {
        "ResponseMetadata": {
            "HTTPStatusCode": 200
        }
    }

    recommendation = {
        "provider": "aws",
        "resource_id": "test-bucket",
        "remediation_type": (
            "AWS_S3_BLOCK_PUBLIC_ACCESS"
        ),
        "status": "PENDING_APPROVAL"
    }

    result = remediate_finding(
        recommendation,
        approved=True
    )

    assert result["status"] == "APPLIED"

    mock_s3.put_public_access_block.assert_called_once_with(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    )