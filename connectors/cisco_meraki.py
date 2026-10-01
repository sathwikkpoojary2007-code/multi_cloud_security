import os
import json
import meraki

print("Starting Cisco Meraki security data collection...")

api_key = os.environ.get("MERAKI_DASHBOARD_API_KEY")

if not api_key:
    print("ERROR: Meraki API key not found.")
    exit()

dashboard = meraki.DashboardAPI(
    api_key=api_key,
    suppress_logging=True
)

all_data = []

organizations = dashboard.organizations.getOrganizations()

for org in organizations:
    org_id = org["id"]

    networks = dashboard.organizations.getOrganizationNetworks(org_id)

    for network in networks:
        network_id = network["id"]

        network_data = {
            "organization": org["name"],
            "network": network["name"],
            "network_id": network_id
        }

        try:
            firewall = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(
                network_id
            )

            network_data["firewall_rules"] = firewall

        except Exception as e:
            network_data["firewall_rules"] = {
                "error": str(e)
            }

        all_data.append(network_data)

with open("data/cisco_raw.json", "w") as file:
    json.dump(all_data, file, indent=4)

print("Cisco security data saved successfully.")
print(json.dumps(all_data, indent=4))