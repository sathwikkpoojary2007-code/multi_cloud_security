"""
AWS remediation workflow.

Coordinates:

    recommendation
        ↓
    approval
        ↓
    remediation
        ↓
    re-scan
        ↓
    verification
        ↓
    benchmark update
"""

from remediation.remediation_engine import (
    remediate_finding
)

from verification.verification_engine import (
    verify_remediation
)

from compliance.benchmarks.benchmark_engine import (
    attach_benchmarks
)


def execute_aws_remediation_workflow(
    resource,
    recommendation,
    approved=False,
    rescan_function=None
):
    """
    Execute the complete AWS remediation workflow.

    Parameters
    ----------
    resource:
        Current normalized resource.

    recommendation:
        Recommendation generated for the resource.

    approved:
        Explicit approval flag.

    rescan_function:
        Function that re-collects and re-processes the
        resource after remediation.

    Returns
    -------
    dict
        Updated resource containing remediation and
        verification information.
    """

    # ---------------------------------------------------------
    # Store the original findings
    # ---------------------------------------------------------

    previous_findings = list(
        resource.get(
            "findings",
            []
        )
    )

    # ---------------------------------------------------------
    # Require approval
    # ---------------------------------------------------------

    remediation_result = remediate_finding(
        recommendation,
        approved=approved
    )

    resource["remediation"] = (
        remediation_result
    )

    # ---------------------------------------------------------
    # Stop if remediation was not applied
    # ---------------------------------------------------------

    if remediation_result.get(
        "status"
    ) != "APPLIED":

        resource["verification"] = {
            "remediation_verified": False,
            "status": "NOT_EVALUATED",
            "message": (
                "Remediation was not applied, "
                "so verification was not performed."
            )
        }

        return resource

    # ---------------------------------------------------------
    # Re-scan
    # ---------------------------------------------------------

    if rescan_function is None:

        resource["verification"] = {
            "remediation_verified": False,
            "status": "NOT_EVALUATED",
            "message": (
                "Remediation was applied, but no "
                "re-scan function was provided."
            )
        }

        return resource

    rescanned_resource = rescan_function(
        resource
    )

    # ---------------------------------------------------------
    # Replace current security state
    # ---------------------------------------------------------

    resource["security"] = rescanned_resource.get(
        "security",
        resource.get("security", {})
    )

    resource["findings"] = rescanned_resource.get(
        "findings",
        []
    )

    resource["risk_score"] = rescanned_resource.get(
        "risk_score",
        resource.get("risk_score", 0)
    )

    # ---------------------------------------------------------
    # Verify remediation
    # ---------------------------------------------------------

    verify_remediation(
        resource,
        previous_findings
    )

    # ---------------------------------------------------------
    # Re-evaluate benchmarks
    # ---------------------------------------------------------

    attach_benchmarks(
        resource
    )

    return resource