import json

from normalizer.cloudflare_normalizer import (
    normalize_cloudflare_resource
)

from security.cloudflare_rules import (
    check_cloudflare_security
)

from security.risk_engine import (
    calculate_risk
)


with open("data/cloudflare_raw.json") as file:
    raw = json.load(file)


for resource in raw:

    normalized = normalize_cloudflare_resource(resource)

    security = normalized["security"]

    findings = check_cloudflare_security(normalized)

    risk_score = calculate_risk(
        exposure=security["exposure"],
        privilege=security["privilege"],
        encryption=security["encryption"],
        logging=security["logging"]
    )

    print("\nCloudflare Common Model:")
    print(json.dumps(normalized, indent=4))

    print("\nCloudflare Security Findings:")
    print(json.dumps(findings, indent=4))

    print("\nCloudflare Risk Score:", risk_score)