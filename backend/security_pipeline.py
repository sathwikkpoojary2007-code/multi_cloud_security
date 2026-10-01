import json

from normalizer.common_model import normalize_s3_bucket
from normalizer.cisco_normalizer import normalize_cisco_resource

from security.s3_rules import check_s3_security
from security.cisco_rules import check_cisco_security

from security.risk_engine import calculate_risk


def process_aws():

    results = []

    with open("data/aws_s3_security_raw.json") as file:
        aws_raw = json.load(file)

    for bucket in aws_raw:

        resource = normalize_s3_bucket(bucket)

        findings = check_s3_security(resource)

        security = resource["security"]

        risk_score = calculate_risk(
            security["exposure"],
            security["privilege"],
            security["encryption"],
            security["logging"]
        )

        results.append({
            "provider": "aws",
            "resource_id": resource["resource_id"],
            "resource_type": resource["resource_type"],
            "security": security,
            "findings": findings,
            "risk_score": risk_score
        })

    return results


def process_cisco():

    results = []

    with open("data/cisco_raw.json") as file:
        cisco_raw = json.load(file)

    for network in cisco_raw:

        resource = normalize_cisco_resource(network)

        findings = check_cisco_security(resource)

        security = resource["security"]

        risk_score = calculate_risk(
            security["exposure"],
            security["privilege"],
            security["encryption"],
            security["logging"]
        )

        results.append({
            "provider": "cisco",
            "resource_id": resource["resource_id"],
            "resource_type": resource["resource_type"],
            "security": security,
            "findings": findings,
            "risk_score": risk_score
        })

    return results


def run_security_pipeline():

    results = []

    results.extend(process_aws())
    results.extend(process_cisco())

    return results


if __name__ == "__main__":

    results = run_security_pipeline()

    print("\n========== MULTI-CLOUD SECURITY RESULTS ==========")

    print(json.dumps(results, indent=4))