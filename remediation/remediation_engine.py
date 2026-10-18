"""
MultiCloudSecurity remediation engine.

The remediation engine converts approved recommendations
into provider-specific remediation actions.

Safety model:

    recommendation
          ↓
    approval required
          ↓
    remediation action
          ↓
    re-scan
          ↓
    verification
"""


from remediation.aws_remediation import (
    enable_s3_block_public_access
)


def remediate_finding(
    recommendation,
    approved=False
):
    """
    Execute a remediation recommendation.

    Remediation is blocked unless approved=True.
    """

    if not approved:

        return {
            "status": "PENDING_APPROVAL",
            "message": (
                "Remediation was not executed because "
                "explicit approval was not provided."
            ),
            "recommendation": recommendation
        }

    provider = recommendation.get(
        "provider"
    )

    remediation_type = recommendation.get(
        "remediation_type"
    )

    resource_id = recommendation.get(
        "resource_id"
    )

    # ---------------------------------------------------------
    # AWS S3
    # ---------------------------------------------------------

    if (
        provider == "aws"
        and remediation_type
        == "AWS_S3_BLOCK_PUBLIC_ACCESS"
    ):

        return enable_s3_block_public_access(
            resource_id
        )

    # ---------------------------------------------------------
    # Unsupported remediation
    # ---------------------------------------------------------

    return {
        "status": "NOT_IMPLEMENTED",
        "message": (
            "A remediation handler has not yet been "
            "implemented for this recommendation."
        ),
        "provider": provider,
        "resource_id": resource_id,
        "remediation_type": remediation_type
    }