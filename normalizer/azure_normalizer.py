def normalize_azure_storage(resource):

    exposure = 0.0
    privilege = 0.0
    encryption = 0.0
    logging = 0.0
    network_security = 0.0
    identity_security = 0.0
    configuration_security = 0.0

    # Public network access
    if resource.get("public_network_access") == "Enabled":
        exposure = 1.0
        network_security = 1.0

    # Blob public access
    if resource.get("allow_blob_public_access") is True:
        exposure = 1.0

    # HTTPS-only
    if resource.get("https_traffic_only") is not True:
        encryption = 1.0

    # TLS baseline
    if resource.get("minimum_tls_version") != "TLS1_2":
        encryption = 1.0

    return {
        "provider": "azure",
        "resource_type": "storage_account",
        "resource_id": resource.get(
            "resource_id"
        ),
        "security": {
            "exposure": exposure,
            "privilege": privilege,
            "encryption": encryption,
            "logging": logging,
            "network_security": network_security,
            "identity_security": identity_security,
            "configuration_security": configuration_security
        },
        # Azure inputs here establish exposure and transport settings only.
        # They do not establish encryption at rest or the other dimensions.
        "evaluated_dimensions": (
            ["exposure"] if (
                resource.get("public_network_access") in ("Enabled", "Disabled")
                or isinstance(resource.get("allow_blob_public_access"), bool)
            ) else []
        ) + (
            ["network_security"]
            if resource.get("public_network_access") in ("Enabled", "Disabled")
            else []
        ),
        "benchmark_evidence": {
            "MC-003": (
                resource.get("https_traffic_only") is True
                and resource.get("minimum_tls_version") == "TLS1_2"
            ) if "https_traffic_only" in resource and "minimum_tls_version" in resource else None
        },
        "metadata": {
            "name": resource.get("name"),
            "location": resource.get("location"),
            "minimum_tls_version": resource.get(
                "minimum_tls_version"
            ),
            "allow_blob_public_access": resource.get(
                "allow_blob_public_access"
            ),
            "public_network_access": resource.get(
                "public_network_access"
            ),
            "https_traffic_only": resource.get(
                "https_traffic_only"
            )
        }
    }
