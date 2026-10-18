import json

from normalizer.azure_normalizer import normalize_azure_storage
from security.azure_rules import check_azure_security
from security.risk_engine import calculate_risk


with open("data/azure_raw.json") as file:
    raw = json.load(file)


for resource in raw:

    normalized = normalize_azure_storage(resource)

    security = normalized["security"]

    risk_score = calculate_risk(
        exposure=security["exposure"],
        privilege=security["privilege"],
        encryption=security["encryption"],
        logging=security["logging"]
    )

    findings = check_azure_security(normalized)

    print("\nAzure Common Model:")
    print(json.dumps(normalized, indent=4))

    print("\nAzure Security Findings:")
    print(json.dumps(findings, indent=4))

    print("\nAzure Risk Score:", risk_score)