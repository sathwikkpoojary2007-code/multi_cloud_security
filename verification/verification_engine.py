"""
Verification engine for MultiCloudSecurity.

Verification compares the security state before and after
remediation.

A remediation is considered verified only when the relevant
security finding is no longer present after re-scanning.
"""


def verify_remediation(
    resource,
    previous_findings
):
    """
    Verify whether remediation removed the previous findings.

    Parameters
    ----------
    resource:
        The resource after remediation and re-scan.

    previous_findings:
        Findings detected before remediation.

    Returns
    -------
    dict
        Verification result.
    """

    current_findings = resource.get(
        "findings",
        []
    )

    previous_rules = {
        finding.get("rule")
        for finding in previous_findings
        if finding.get("rule")
    }

    current_rules = {
        finding.get("rule")
        for finding in current_findings
        if finding.get("rule")
    }

    resolved_rules = (
        previous_rules - current_rules
    )

    remaining_rules = (
        previous_rules & current_rules
    )

    # ---------------------------------------------------------
    # All previous findings resolved
    # ---------------------------------------------------------

    if previous_rules and not remaining_rules:

        result = {
            "remediation_verified": True,
            "status": "VERIFIED",
            "resolved_rules": sorted(
                resolved_rules
            ),
            "remaining_rules": [],
            "message": (
                "The previous security findings "
                "were no longer detected after "
                "re-scanning the resource."
            )
        }

    # ---------------------------------------------------------
    # Some findings remain
    # ---------------------------------------------------------

    elif remaining_rules:

        result = {
            "remediation_verified": False,
            "status": "REMEDIATION_FAILED",
            "resolved_rules": sorted(
                resolved_rules
            ),
            "remaining_rules": sorted(
                remaining_rules
            ),
            "message": (
                "One or more security findings "
                "remain after remediation."
            )
        }

    # ---------------------------------------------------------
    # Nothing to verify
    # ---------------------------------------------------------

    else:

        result = {
            "remediation_verified": False,
            "status": "NOT_EVALUATED",
            "resolved_rules": [],
            "remaining_rules": [],
            "message": (
                "There were no previous findings "
                "available for verification."
            )
        }

    resource["verification"] = result

    return result