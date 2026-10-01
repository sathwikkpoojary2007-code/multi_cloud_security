import json

from normalizer.cisco_normalizer import normalize_cisco_resource
from security.cisco_rules import check_cisco_firewall
from security.risk_engine import calculate_risk


with open("data/cisco_raw.json") as file:
    raw = json.load(file)


for network in raw:

    normalized = normalize_cisco_resource(network)

    findings = check_cisco_firewall(normalized)

    for finding in findings:

        # HIGH firewall exposure finding
        exposure = 1.0

        # No privilege weakness detected by this rule
        privilege = 0.0

        # Encryption is not evaluated by this rule
        encryption = 0.0

        # Logging is disabled in the observed firewall rule
        logging = 1.0

        risk = calculate_risk(
            exposure=exposure,
            privilege=privilege,
            encryption=encryption,
            logging=logging
        )

        print("\nCisco Security Finding:")
        print(json.dumps(finding, indent=4))

        print("\nCisco Risk Score:", risk)