def normalize_s3_bucket(bucket):

    public_access = bucket["public_access_block"]

    # Exposure:
    # 1.0 means public access controls are not fully enabled.
    if (
        public_access["BlockPublicAcls"] is False
        or public_access["IgnorePublicAcls"] is False
        or public_access["BlockPublicPolicy"] is False
        or public_access["RestrictPublicBuckets"] is False
    ):
        exposure = 1.0
    else:
        exposure = 0.0

    return {
        "provider": "aws",
        "resource_type": "storage_bucket",
        "resource_id": bucket["bucket_name"],

        "security": {
            "exposure": exposure,
            "privilege": 0.0,
            "encryption": 0.0,
            "logging": 0.0
        },

        "metadata": {}
    }