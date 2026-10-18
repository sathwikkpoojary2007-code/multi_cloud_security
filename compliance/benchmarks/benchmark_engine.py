"""Benchmark evaluator for the normalized MultiCloudSecurity model."""

from .mappings import BENCHMARKS


DIMENSION_BENCHMARKS = {
    "exposure",
    "privilege",
    "encryption",
    "logging",
    "network_security",
    "identity_security",
    "configuration_security",
}


def _dimension_failed(resource, dimension):
    security = resource.get("security", {})
    if dimension not in resource.get("evaluated_dimensions", []):
        return None

    value = security.get(dimension)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not 0.0 <= value <= 1.0:
        return None

    return value > 0.0


def _has_active_findings(resource):
    findings = resource.get(
        "findings",
        []
    )

    return len(findings) > 0


def evaluate_resource(resource):

    provider = resource.get(
        "provider"
    )

    results = []

    for benchmark in BENCHMARKS:

        if provider not in benchmark["providers"]:
            continue

        benchmark_id = benchmark["id"]

        status = "NOT_EVALUATED"

        dimension = benchmark.get(
            "dimension"
        )

        # ---------------------------------------------------------
        # MC-010
        # Vulnerabilities and detected weaknesses are remediated
        # ---------------------------------------------------------

        if benchmark_id == "MC-010":

            verification = resource.get(
                "verification",
                {}
            )

            if verification.get(
                "remediation_verified"
            ) is True:

                status = "PASS"

            elif _has_active_findings(resource):

                status = "FAIL"

            else:

                status = "NOT_EVALUATED"

        # ---------------------------------------------------------
        # MC-011
        # Recovery capability is protected and testable
        # ---------------------------------------------------------

        elif benchmark_id == "MC-011":

            recovery = resource.get(
                "recovery",
                {}
            )

            if recovery.get(
                "verified"
            ) is True:

                status = "PASS"

            else:

                status = "NOT_EVALUATED"

        # ---------------------------------------------------------
        # MC-012
        # Risk is calculated and prioritized consistently
        # ---------------------------------------------------------

        elif benchmark_id == "MC-012":

            risk_score = resource.get(
                "risk_score"
            )

            if (
                isinstance(
                    risk_score,
                    (int, float)
                )
                and 0 <= risk_score <= 100
                and isinstance(resource.get("risk_coverage"), (int, float))
                and resource.get("risk_coverage", 0) > 0
            ):

                status = "PASS"

            else:

                status = "NOT_EVALUATED"

        # These checks need dedicated evidence. A broad encryption or
        # logging score cannot prove transport protection or log quality.
        elif benchmark_id in {"MC-003", "MC-007"}:
            evidence = resource.get("benchmark_evidence", {}).get(benchmark_id)
            if evidence is True:
                status = "PASS"
            elif evidence is False:
                status = "FAIL"

        # ---------------------------------------------------------
        # Standard dimension-based benchmarks
        # ---------------------------------------------------------

        elif dimension in DIMENSION_BENCHMARKS:
            failed = _dimension_failed(resource, dimension)
            if failed is True:
                status = "FAIL"
            elif failed is False:
                status = "PASS"

        results.append({
            "benchmark_id": benchmark_id,
            "name": benchmark["name"],
            "status": status,
            "severity": benchmark["severity"],
            "cis": benchmark["cis"],
            "nist_csf": benchmark["nist_csf"],
            "nist_sp_800_53": benchmark[
                "nist_sp_800_53"
            ],
            "dimension": benchmark["dimension"],
            "check": benchmark["check"],
            "remediation_goal": benchmark[
                "remediation_goal"
            ],
        })

    return results


def attach_benchmarks(resource):

    resource["benchmarks"] = evaluate_resource(
        resource
    )

    return resource
