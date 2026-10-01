import json

from normalizer.cisco_normalizer import normalize_cisco_resource
from security.risk_engine import calculate_risk


with open("data/cisco_raw.json") as file:
    raw = json.load(file)


for network in raw:

    normalized = normalize_cisco_resource(network)

    security = normalized["security"]

    print("\n=== CISCO COMMON MODEL ===")
    print("Provider:", normalized["provider"])
    print("Resource Type:", normalized["resource_type"])
    print("Resource ID:", normalized["resource_id"])

    print("\nSecurity Values:")
    print("Exposure:", security["exposure"])
    print("Privilege:", security["privilege"])
    print("Encryption:", security["encryption"])
    print("Logging:", security["logging"])

    risk_score = calculate_risk(
        exposure=security["exposure"],
        privilege=security["privilege"],
        encryption=security["encryption"],
        logging=security["logging"]
    )

    print("\n=== RISK RESULT ===")
    print("Cisco Risk Score:", risk_score)