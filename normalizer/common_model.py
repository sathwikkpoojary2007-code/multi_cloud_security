def normalize_s3_bucket(bucket):

    public_access = bucket.get("public_access_block") or {}

    exposure = 0.0
    encryption = 0.0
    logging = 0.0
    privilege = 0.0
    network_security = 0.0
    identity_security = 0.0
    configuration_security = 0.0

    # Public access protection
    public_access_keys = (
        "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
        "RestrictPublicBuckets"
    )
    public_access_complete = (
        bucket.get("public_access_evaluated", True) is True
        and all(isinstance(public_access.get(key), bool) for key in public_access_keys)
    )
    if public_access_complete and any(public_access[key] is False for key in public_access_keys):
        exposure = 1.0

    # Server side encryption. A missing field is unknown; an explicit null
    # means no bucket encryption configuration was returned.
    encryption_data = bucket.get("encryption")
    encryption_evaluated = False
    if bucket.get("encryption_evaluated", "encryption" in bucket) is True and encryption_data is None:
        encryption = 1.0
        encryption_evaluated = True
    elif bucket.get("encryption_evaluated", True) is True and isinstance(encryption_data, dict):
        rules = encryption_data.get("Rules")
        if isinstance(rules, list) and rules:
            algorithms = [
                rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                for rule in rules
                if isinstance(rule, dict)
                and isinstance(rule.get("ApplyServerSideEncryptionByDefault"), dict)
            ]
            if len(algorithms) == len(rules):
                encryption = 0.0 if all(
                    algorithm in ("AES256", "aws:kms", "aws:kms:dsse")
                    for algorithm in algorithms
                ) else 1.0
                encryption_evaluated = True

    return {
        "provider": "aws",
        "resource_type": "storage_bucket",
        "resource_id": bucket["bucket_name"],
        "security": {
            "exposure": exposure,
            "privilege": privilege,
            "encryption": encryption,
            "logging": logging,
            "network_security": network_security,
            "identity_security": identity_security,
            "configuration_security": configuration_security
        },
        # Only dimensions backed by complete provider data may produce PASS.
        "evaluated_dimensions": (
            ["exposure"]
            if public_access_complete else []
        ) + (["encryption"] if encryption_evaluated else []),
        "metadata": {
            "region": bucket.get("region"),
            "public_access_block": public_access,
            "collection_errors": bucket.get("collection_errors", []),
        }
    }
