import json

from normalizer.common_model import normalize_s3_bucket
from normalizer.cisco_normalizer import normalize_cisco_resource
from security.risk_engine import calculate_risk


print("========== MULTI-CLOUD RISK TEST ==========")


# ---------------- AWS ----------------

with open("data/aws_s3_security_raw.json") as file:
    aws_raw = json.load(file)

for bucket in aws_raw:

    aws_resource = normalize_s3_bucket(bucket)
    security = aws_resource["security"]

    aws_risk = calculate_risk(
        exposure=security["exposure"],
        privilege=security["privilege"],
        encryption=security["encryption"],
        logging=security["logging"]
    )

    print("\nAWS")
    print("Resource:", aws_resource["resource_id"])
    print("Exposure:", security["exposure"])
    print("Privilege:", security["privilege"])
    print("Encryption:", security["encryption"])
    print("Logging:", security["logging"])
    print("Risk Score:", aws_risk)


# ---------------- CISCO ----------------

with open("data/cisco_raw.json") as file:
    cisco_raw = json.load(file)

for network in cisco_raw:

    cisco_resource = normalize_cisco_resource(network)
    security = cisco_resource["security"]

    cisco_risk = calculate_risk(
        exposure=security["exposure"],
        privilege=security["privilege"],
        encryption=security["encryption"],
        logging=security["logging"]
    )

    print("\nCISCO")
    print("Resource:", cisco_resource["resource_id"])
    print("Exposure:", security["exposure"])
    print("Privilege:", security["privilege"])
    print("Encryption:", security["encryption"])
    print("Logging:", security["logging"])
    print("Risk Score:", cisco_risk)


print("\n========== TEST COMPLETE ==========")