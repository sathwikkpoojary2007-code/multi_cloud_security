def normalize_cloudflare_resource(resource):

    zones = resource.get("zones", [])

    active_zones = 0
    security_rules = 0

    for zone in zones:

        if zone.get("status") == "active":
            active_zones += 1

        security_rules += len(
            zone.get("security_rules", [])
        )

    uncovered_zones = [zone for zone in zones if zone.get("status") == "active" and zone.get("managed_waf_enabled") is False]
    waf_evaluated = all(zone.get("status") != "active" or isinstance(zone.get("managed_waf_enabled"), bool) for zone in zones)
    exposure = 1.0 if uncovered_zones else 0.0

    network_security = 0.0

    if uncovered_zones:
        network_security = 1.0

    return {
        "provider": "cloudflare",
        "resource_type": "web_security",
        "resource_id": resource.get(
            "account_id"
        ),
        "security": {
            "exposure": exposure,
            "privilege": 0.0,
            "encryption": 0.0,
            "logging": 0.0,
            "network_security": network_security,
            "identity_security": 0.0,
            "configuration_security": 0.0
        },
        "evaluated_dimensions": ["exposure", "network_security"] if "zones" in resource and waf_evaluated else [],
        "metadata": {
            "account_name": resource.get(
                "account_name"
            ),
            "zone_count": len(zones),
            "active_zone_count": active_zones,
            "security_rule_count": security_rules,
            "zones": zones,
            "uncovered_zone_ids": [zone.get("zone_id") for zone in uncovered_zones],
        }
    }
