def normalize_cisco_resource(network):

    firewall_data = network.get("firewall_rules", {})
    rules = firewall_data.get("rules", [])

    exposure = 0.0
    logging = 0.0
    network_security = 0.0

    for rule in rules:

        if (
            rule.get("policy") == "allow"
            and rule.get("protocol") == "Any"
            and rule.get("srcCidr") == "Any"
            and rule.get("destCidr") == "Any"
        ):
            exposure = 1.0
            network_security = 1.0

        if rule.get("syslogEnabled") is False:
            logging = 1.0

    return {
        "provider": "cisco",
        "resource_type": "firewall",
        "resource_id": network.get(
            "network_id",
            "unknown"
        ),
        "security": {
            "exposure": exposure,
            "privilege": 0.0,
            "encryption": 0.0,
            "logging": logging,
            "network_security": network_security,
            "identity_security": 0.0,
            "configuration_security": 0.0
        },
        "evaluated_dimensions": (
            ["exposure", "network_security"]
            if "rules" in firewall_data else []
        ) + (
            ["logging"]
            if rules and all(isinstance(rule.get("syslogEnabled"), bool) for rule in rules)
            else []
        ),
        "metadata": {
            "organization": network.get(
                "organization"
            ),
            "network": network.get(
                "network"
            ),
            "network_id": network.get("network_id"),
            "firewall_rules": rules,
        }
    }
