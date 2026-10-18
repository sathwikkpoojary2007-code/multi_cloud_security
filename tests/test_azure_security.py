import json

from normalizer.azure_normalizer import normalize_azure_storage
from security.azure_rules import check_azure_security


with open("data/azure_raw.json") as file:
    raw = json.load(file)


for resource in raw:

    normalized = normalize_azure_storage(resource)

    findings = check_azure_security(normalized)

    print("\nAzure Security Findings:")

    print(json.dumps(findings, indent=4))