"""Map observed security findings to reviewed remediation recommendations."""


REMEDIATIONS = {
    "AWS-S3-001": {
        "remediation_type": "AWS_S3_BLOCK_PUBLIC_ACCESS",
        "title": "Enable all four S3 Block Public Access controls",
        "supported": True,
        "impact": "Blocks public ACL and bucket-policy access at this bucket.",
    },
    "AZURE-STORAGE-001": {
        "remediation_type": "AZURE_STORAGE_HARDEN",
        "title": "Disable anonymous blob access and require secure transport",
        "supported": True,
        "impact": "Disables public network and anonymous blob access, and enforces HTTPS with TLS 1.2. This can interrupt workloads that require public access; confirm private network connectivity first.",
    },
    "CISCO-FW-001": {
        "remediation_type": "CISCO_DENY_ANY_ANY",
        "title": "Change broad allow rules to deny",
        "supported": True,
        "impact": "Changes every any-protocol, any-source, any-destination allow rule on this network to deny. This can interrupt traffic; inspect the listed rule and confirm before applying.",
    },
    "CLOUDFLARE-WEB-001": {
        "remediation_type": "CLOUDFLARE_DEPLOY_MANAGED_WAF",
        "title": "Deploy Cloudflare Managed Ruleset to uncovered active zones",
        "supported": True,
        "impact": "Adds Cloudflare’s managed WAF ruleset while preserving existing phase rules. Managed rules may block malicious requests; review provider events after deployment.",
    },
}


def build_recommendations(findings, ml_assessment=None):
    priority = (ml_assessment or {}).get("risk_band", "REVIEW")
    recommendations = []
    for finding in findings:
        item = REMEDIATIONS.get(finding.get("rule"))
        if not item:
            recommendations.append({
                "rule": finding.get("rule"),
                "title": "Review the finding and define an approved remediation.",
                "supported": False,
                "priority": priority,
            })
            continue
        recommendations.append({
            "rule": finding.get("rule"),
            "remediation_type": item["remediation_type"],
            "title": item["title"],
            "supported": item["supported"],
            "impact": item["impact"],
            "priority": priority,
        })
    return recommendations
