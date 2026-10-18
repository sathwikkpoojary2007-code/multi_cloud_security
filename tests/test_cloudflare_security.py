import json

from normalizer.cloudflare_normalizer import (
    normalize_cloudflare_resource
)

from security.cloudflare_rules import (
    check_cloudflare_security
)


with open("data/cloudflare_raw.json") as file:
    raw = json.load(file)


for resource in raw:

    normalized = normalize_cloudflare_resource(resource)

    findings = check_cloudflare_security(normalized)

    print("\nCloudflare Security Findings:")
    print(json.dumps(findings, indent=4))