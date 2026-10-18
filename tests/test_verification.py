from verification.verification_engine import (
    verify_remediation
)


def test_successful_remediation():

    previous_findings = [
        {
            "rule": "AWS-S3-001",
            "severity": "HIGH"
        }
    ]

    resource_after_remediation = {
        "findings": []
    }

    result = verify_remediation(
        resource_after_remediation,
        previous_findings
    )

    assert result["remediation_verified"] is True

    assert result["status"] == "VERIFIED"

    assert "AWS-S3-001" in (
        result["resolved_rules"]
    )


def test_failed_remediation():

    previous_findings = [
        {
            "rule": "AWS-S3-001",
            "severity": "HIGH"
        }
    ]

    resource_after_remediation = {
        "findings": [
            {
                "rule": "AWS-S3-001",
                "severity": "HIGH"
            }
        ]
    }

    result = verify_remediation(
        resource_after_remediation,
        previous_findings
    )

    assert result["remediation_verified"] is False

    assert result["status"] == (
        "REMEDIATION_FAILED"
    )

    assert "AWS-S3-001" in (
        result["remaining_rules"]
    )