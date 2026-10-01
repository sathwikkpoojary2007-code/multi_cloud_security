import json

from normalizer.cisco_normalizer import normalize_cisco_resource


with open("data/cisco_raw.json") as file:
    raw = json.load(file)


for network in raw:
    normalized = normalize_cisco_resource(network)

    print("Normalized Cisco Resource:")
    print(json.dumps(normalized, indent=4))