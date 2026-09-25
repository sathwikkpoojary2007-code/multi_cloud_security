import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common_model import normalize_s3_bucket

project_folder = r"C:\Users\Prakhyath L\MultiCloudSecurity"

data_file = os.path.join(
    project_folder,
    "data",
    "aws_s3_security_raw.json"
)

print("Reading:", data_file)

with open(data_file, "r") as file:
    buckets = json.load(file)

print("Buckets found:", len(buckets))

for bucket in buckets:
    normalized = normalize_s3_bucket(bucket)

    print("NORMALIZED RESOURCE")
    print(json.dumps(normalized, indent=4))
    print("-----------------------------")