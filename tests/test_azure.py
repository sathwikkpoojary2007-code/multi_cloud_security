import json

from normalizer.azure_normalizer import normalize_azure_storage


with open("data/azure_raw.json") as file:
    raw = json.load(file)


for resource in raw:

    normalized = normalize_azure_storage(resource)

    print("Azure Common Model:")
    print(json.dumps(normalized, indent=4))