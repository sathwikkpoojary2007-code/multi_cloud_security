import json

from connectors.aws_test import collect_s3_security_data
from normalizer.common_model import normalize_s3_bucket
from security.s3_rules import check_s3_security
from security.risk_engine import calculate_risk


def rescan_aws_bucket(resource):
    """
    Re-collect an AWS S3 bucket after remediation
    and rebuild its normalized security state.
    """

    resource_id = resource.get(
        "resource_id"
    )

    raw_resources = collect_s3_security_data()

    for bucket in raw_resources:

        bucket_name = bucket.get(
            "bucket_name"
        )

        if bucket_name != resource_id:
            continue

        normalized = normalize_s3_bucket(
            bucket
        )

        findings = check_s3_security(
            normalized
        )

        normalized["findings"] = findings

        security = normalized.get(
            "security",
            {}
        )

        normalized["risk_score"] = calculate_risk(
            exposure=security.get(
                "exposure",
                0.0
            ),
            privilege=security.get(
                "privilege",
                0.0
            ),
            encryption=security.get(
                "encryption",
                0.0
            ),
            logging=security.get(
                "logging",
                0.0
            ),
            network_security=security.get(
                "network_security",
                0.0
            ),
            identity_security=security.get(
                "identity_security",
                0.0
            ),
            configuration_security=security.get(
                "configuration_security",
                0.0
            )
        )

        return normalized

    raise ValueError(
        f"AWS bucket '{resource_id}' "
        "was not found during re-scan."
    )