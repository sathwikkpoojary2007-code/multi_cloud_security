"""Read security configuration from Cisco Meraki networks."""

import json
import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def collect_cisco_security_data(api_key=None):
    api_key = api_key or os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not api_key:
        raise ValueError("MERAKI_DASHBOARD_API_KEY is not configured")

    import meraki

    dashboard = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    all_data = []
    for org in dashboard.organizations.getOrganizations():
        for network in dashboard.organizations.getOrganizationNetworks(org["id"]):
            network_data = {
                "organization": org["name"],
                "network": network["name"],
                "network_id": network["id"],
            }
            try:
                network_data["firewall_rules"] = (
                    dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(network["id"])
                )
            except Exception as error:
                network_data["firewall_rules"] = {"error": str(error)}
            all_data.append(network_data)
    return all_data


if __name__ == "__main__":
    data = collect_cisco_security_data()
    output = PROJECT_ROOT / "data" / "cisco_raw.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Cisco Meraki networks collected: {len(data)}")
    print(f"Saved: {output}")
