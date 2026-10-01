import json

from normalizer.common_model import normalize_s3_bucket
from normalizer.cisco_normalizer import normalize_cisco_resource

from security.s3_rules import check_s3_security
from security.cisco_rules import check_cisco_security

from security.risk_engine import calculate_risk


print("\n========== MULTI-CLOUD SECURITY PIPELINE ==========")


# ================= AWS =================

with open("data/aws_s3_security_raw.json") as file:
    aws_raw = json.load(file)

for bucket in aws_raw:

    normalized = normalize_s3_bucket(bucket)

    findings = check_s3_security(normalized)

    security = normalized["security"]

    risk = calculate_risk(
        security["exposure"],
        security["privilege"],
        security["encryption"],
        security["logging"]
    )

    print("\n----- AWS -----")
    print("Resource:", normalized["resource_id"])
    print("Risk Score:", risk)

    print("Findings:")
    for finding in findings:
        print("-", finding["rule"], "|", finding["severity"])


# ================= CISCO =================

with open("data/cisco_raw.json") as file:
    cisco_raw = json.load(file)

for network in cisco_raw:

    normalized = normalize_cisco_resource(network)

    findings = check_cisco_security(normalized)

    security = normalized["security"]

    risk = calculate_risk(
        security["exposure"],
        security["privilege"],
        security["encryption"],
        security["logging"]
    )

    print("\n----- CISCO -----")
    print("Resource:", normalized["resource_id"])
    print("Risk Score:", risk)

    print("Findings:")
    for finding in findings:
        print("-", finding["rule"], "|", finding["severity"])


print("\n========== PIPELINE COMPLETE ==========")