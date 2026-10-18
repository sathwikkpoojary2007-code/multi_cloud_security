def check_cloudflare_security(resource):

    findings = []

    security = resource.get("security", {})

    if security.get("exposure", 0.0) == 1.0:

        findings.append({
            "provider": "cloudflare",
            "resource_id": resource.get("resource_id"),
            "rule": "CLOUDFLARE-WEB-001",
            "severity": "HIGH",
            "title": "Cloudflare managed WAF is not enabled on one or more active zones",
            "description": (
                "An active zone does not have the Cloudflare Managed Ruleset attached to its managed firewall phase."
            )
        })

    return findings
