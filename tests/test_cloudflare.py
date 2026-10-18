import json

from normalizer.cloudflare_normalizer import (
    normalize_cloudflare_resource
)


with open("data/cloudflare_raw.json") as file:
    raw = json.load(file)


for resource in raw:

    normalized = normalize_cloudflare_resource(resource)

    print("\nCloudflare Common Model:")
    print(json.dumps(normalized, indent=4))