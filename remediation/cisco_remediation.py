"""Narrow Meraki firewall remediation that preserves unrelated rules."""
import os


def deny_any_any_rules(network_id, credentials):
    key = credentials.get("api_key") or os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        raise ValueError("Save a Meraki API key on the Service Connections page first.")
    import meraki
    dashboard = meraki.DashboardAPI(api_key=key, suppress_logging=True)
    current = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(network_id)
    rules = current.get("rules", [])
    matches = [rule for rule in rules if rule.get("policy") == "allow" and rule.get("protocol") == "Any" and rule.get("srcCidr") == "Any" and rule.get("destCidr") == "Any"]
    if not matches:
        return {"status": "APPLIED", "updated": 0, "message": "No broad allow rule remains."}
    updated = [dict(rule, policy="deny") if rule in matches else rule for rule in rules]
    result = dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(
        network_id, rules=updated,
        **({"syslogDefaultRule": current["syslogDefaultRule"]} if "syslogDefaultRule" in current else {}),
    )
    return {"status": "APPLIED", "updated": len(matches), "network_id": network_id, "rules": result.get("rules", updated)}
