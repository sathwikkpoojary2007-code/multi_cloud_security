import json
import os
import sys

# Allow Python to find the normalizer
sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "normalizer"
    )
)

from common_model import normalize_s3_bucket


project_folder = r"C:\Users\Prakhyath L\MultiCloudSecurity"

data_file = os.path.join(
    project_folder,
    "data",
    "aws_s3_security_raw.json"
)

with open(data_file, "r") as file:
    buckets = json.load(file)


print("Running security rules...")
print()


for bucket in buckets:

    resource = normalize_s3_bucket(bucket)

    public_access = resource["security"]["public_access_block"]

    if (
        public_access["block_public_acls"] is False
        or public_access["ignore_public_acls"] is False
        or public_access["block_public_policy"] is False
        or public_access["restrict_public_buckets"] is False
    ):

        print("SECURITY FINDING")
        print("Provider:", resource["provider"])
        print("Resource type:", resource["resource_type"])
        print("Resource:", resource["resource_id"])
        print("Issue: S3 Block Public Access is not fully enabled")
        print("Severity: HIGH")
        print("-----------------------------")