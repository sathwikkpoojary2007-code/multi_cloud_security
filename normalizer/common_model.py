def normalize_s3_bucket(bucket):

    public_access = bucket["public_access_block"]

    normalized = {
        "provider": "aws",
        "resource_type": "storage_bucket",
        "resource_id": bucket["bucket_name"],

        "security": {
            "public_access_block": {
                "block_public_acls": public_access["BlockPublicAcls"],
                "ignore_public_acls": public_access["IgnorePublicAcls"],
                "block_public_policy": public_access["BlockPublicPolicy"],
                "restrict_public_buckets": public_access["RestrictPublicBuckets"]
            }
        }
    }

    return normalized