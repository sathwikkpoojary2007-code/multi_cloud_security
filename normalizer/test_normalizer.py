import json
from pathlib import Path

from normalizer.common_model import normalize_s3_bucket


# Find the project root automatically
BASE_DIR = Path(__file__).resolve().parent.parent

data_file = BASE_DIR / "data" / "aws_s3_security_raw.json"

print("Reading:", data_file)

with open(data_file, "r") as file:
    raw_data = json.load(file)


for bucket in raw_data:

    normalized = normalize_s3_bucket(bucket)

    print("\n========== NORMALIZED RESOURCE ==========")
    print(json.dumps(normalized, indent=4))