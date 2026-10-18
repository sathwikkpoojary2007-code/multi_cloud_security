from unittest.mock import patch

from remediation.aws_workflow import (
    execute_aws_remediation_workflow
)


def test_aws_remediation_workflow():

    resource = {
        "provider": "aws",
        "resource_id": "test-bucket",
        "security": {
            "exposure": 1.0,
            "privilege": 0.0,
            "encryption": 0.0,
            "logging": 0.0,
            "network_security": 0.0,
            "identity_security": 0.0,
            "configuration_security": 0.0
        },
        "findings": [
            {
                "provider": "aws",
                "resource_id": "test-bucket",
                "rule": "AWS-S3-001",
                "severity": "HIGH",
                "title": (
                    "S3 Block Public Access is not "
                    "fully enabled"
                )
            }
        ]
    }

    recommendation = {
        "provider": "aws",
        "resource_id": "test-bucket",
        "rule": "AWS-S3-001",
        "severity": "HIGH",
        "remediation_type": (
            "AWS_S3_BLOCK_PUBLIC_ACCESS"
        ),
        "status": "PENDING_APPROVAL"
    }

    def fake_rescan(resource):

        rescanned = dict(resource)

        rescanned["security"] = {
            "exposure": 0.0,
            "privilege": 0.0,
            "encryption": 0.0,
            "logging": 0.0,
            "network_security": 0.0,
            "identity_security": 0.0,
            "configuration_security": 0.0
        }

        rescanned["findings"] = []

        rescanned["risk_score"] = 0.0

        return rescanned

    with patch(
        "remediation.aws_remediation.boto3.client"
    ) as mock_boto_client:

        mock_s3 = (
            mock_boto_client.return_value
        )

        mock_s3.put_public_access_block.return_value = {
            "ResponseMetadata": {
                "HTTPStatusCode": 200
            }
        }

        result = execute_aws_remediation_workflow(
            resource,
            recommendation,
            approved=True,
            rescan_function=fake_rescan
        )

    assert result["remediation"]["status"] == (
        "APPLIED"
    )

    assert result["verification"][
        "status"
    ] == "VERIFIED"

    assert result["verification"][
        "remediation_verified"
    ] is True

    assert result["findings"] == []

    assert result["risk_score"] == 0.0