import json
from pathlib import Path

import boto3


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def collect_s3_security_data(credentials=None):
    """
    Collect security configuration for AWS S3 buckets.

    Returns a list of bucket security configurations.
    """

    credentials = credentials or {}
    session = boto3.Session(
        aws_access_key_id=credentials.get("access_key_id") or None,
        aws_secret_access_key=credentials.get("secret_access_key") or None,
        aws_session_token=credentials.get("session_token") or None,
        region_name=credentials.get("region") or None,
    )
    s3 = session.client("s3")

    results = []

    paginator = s3.get_paginator("list_buckets")
    buckets = (
        bucket
        for page in paginator.paginate(PaginationConfig={"PageSize": 1000})
        for bucket in page.get("Buckets", [])
    )

    for bucket in buckets:

        bucket_name = bucket["Name"]
        bucket_region = bucket.get("BucketRegion")
        bucket_s3 = session.client("s3", region_name=bucket_region) if bucket_region else s3

        # -----------------------------------------------------
        # Public Access Block
        # -----------------------------------------------------

        collection_errors = []
        public_access_evaluated = False
        encryption_evaluated = False

        try:

            public_access_response = (
                bucket_s3.get_public_access_block(
                    Bucket=bucket_name
                )
            )

            public_access = (
                public_access_response[
                    "PublicAccessBlockConfiguration"
                ]
            )
            public_access_evaluated = True

        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:

            public_access = {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
            public_access_evaluated = True
        except Exception as error:
            public_access = None
            collection_errors.append(f"public_access_block: {error}")

        # -----------------------------------------------------
        # Encryption
        # -----------------------------------------------------

        try:

            encryption_response = (
                bucket_s3.get_bucket_encryption(
                    Bucket=bucket_name
                )
            )

            encryption = (
                encryption_response[
                    "ServerSideEncryptionConfiguration"
                ]
            )
            encryption_evaluated = True

        except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:

            encryption = None
            encryption_evaluated = True
        except Exception as error:
            encryption = None
            collection_errors.append(f"encryption: {error}")

        results.append({
            "provider": "aws",
            "resource_type": "storage_bucket",
            "bucket_name": bucket_name,
            "region": bucket_region,
            "public_access_block": public_access,
            "public_access_evaluated": public_access_evaluated,
            "encryption": encryption,
            "encryption_evaluated": encryption_evaluated,
            "collection_errors": collection_errors,
        })

    return results


if __name__ == "__main__":

    data = collect_s3_security_data()

    print(
        "AWS S3 security resources:",
        len(data)
    )

    output = PROJECT_ROOT / "data" / "aws_s3_security_raw.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Saved: {output}")

    for bucket in data:

        print(
            bucket["bucket_name"]
        )
