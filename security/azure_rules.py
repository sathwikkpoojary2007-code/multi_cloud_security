def check_azure_security(resource):

    findings = []

    security = resource.get("security", {})

    if security.get("exposure", 0.0) == 1.0:

        findings.append({
            "provider": "azure",
            "resource_id": resource.get("resource_id"),
            "rule": "AZURE-STORAGE-001",
            "severity": "HIGH",
            "title": "Azure Storage Account allows public network access",
            "description": (
                "Public network access is enabled for the "
                "Azure Storage Account."
            )
        })

    return findings