def check_cisco_security(resource):

    findings = []

    security = resource.get("security", {})

    if security.get("exposure", 0.0) == 1.0:

        findings.append({
            "provider": "cisco",
            "resource_id": resource.get("resource_id"),
            "rule": "CISCO-FW-001",
            "severity": "HIGH",
            "title": "Overly permissive firewall rule",
            "description": (
                "Firewall rule allows any protocol from any source "
                "to any destination."
            )
        })

    return findings