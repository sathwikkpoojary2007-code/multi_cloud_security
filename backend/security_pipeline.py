"""Run the local multi-cloud security analysis pipeline."""

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from normalizer.common_model import normalize_s3_bucket
from normalizer.cisco_normalizer import normalize_cisco_resource
from normalizer.azure_normalizer import normalize_azure_storage
from normalizer.cloudflare_normalizer import normalize_cloudflare_resource
from security.s3_rules import check_s3_security
from security.cisco_rules import check_cisco_security
from security.azure_rules import check_azure_security
from security.cloudflare_rules import check_cloudflare_security
from security.risk_engine import RISK_WEIGHTS
from compliance.benchmarks.benchmark_engine import attach_benchmarks
from ml.risk_model import predict_resource
from remediation.recommendations import build_recommendations


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_REPORT_PATH = DEFAULT_DATA_DIR / "processed_results.json"
REPORT_HISTORY_DIR = DEFAULT_DATA_DIR / "reports"

PROVIDERS = {
    "aws": ("aws_s3_security_raw.json", normalize_s3_bucket, check_s3_security),
    "cisco": ("cisco_raw.json", normalize_cisco_resource, check_cisco_security),
    "azure": ("azure_raw.json", normalize_azure_storage, check_azure_security),
    "cloudflare": (
        "cloudflare_raw.json",
        normalize_cloudflare_resource,
        check_cloudflare_security,
    ),
}


def calculate_resource_risk(resource):
    """Calculate a weighted risk score from normalized security dimensions."""
    security = resource.get("security", {})
    evaluated = set(resource.get("evaluated_dimensions", []))
    measured = {
        key: value for key, value in security.items()
        if key in evaluated
        and key in RISK_WEIGHTS
        and isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0.0 <= value <= 1.0
    }
    coverage_weight = sum(RISK_WEIGHTS[key] for key in measured)
    resource["risk_coverage"] = round(coverage_weight * 100, 1)
    if coverage_weight == 0:
        return None
    measured_risk = sum(RISK_WEIGHTS[key] * measured[key] for key in measured)
    return round(measured_risk / coverage_weight * 100, 2)


def process_resource(normalized, security_checker):
    """Add findings, risk and benchmark results to one normalized resource."""
    normalized["findings"] = security_checker(normalized)
    normalized["risk_score"] = calculate_resource_risk(normalized)
    normalized["ml_assessment"] = predict_resource(normalized)
    normalized["recommendations"] = build_recommendations(
        normalized["findings"], normalized["ml_assessment"]
    )
    attach_benchmarks(normalized)
    return normalized


def _process_provider(provider, data_dir):
    filename, normalizer, checker = PROVIDERS[provider]
    source_path = data_dir / filename
    if not source_path.exists():
        return [], {"status": "missing", "file": filename}

    with source_path.open("r", encoding="utf-8") as file:
        raw_resources = json.load(file)
    if not isinstance(raw_resources, list):
        raise ValueError(f"{filename} must contain a JSON array")

    processed = []
    for item in raw_resources:
        normalized = normalizer(item)
        processed.append(process_resource(normalized, checker))
    return processed, {"status": "processed", "file": filename, "count": len(processed)}


def summarize_results(resources):
    """Return counts used by both the CLI and dashboard."""
    provider_counts = Counter(resource.get("provider", "unknown") for resource in resources)
    risk_bands = Counter()
    benchmark_counts = Counter()
    findings = []
    risk_values = []
    coverage_values = []

    for resource in resources:
        risk = resource.get("risk_score")
        if isinstance(risk, (int, float)):
            risk_values.append(risk)
            risk_bands["High" if risk >= 70 else "Medium" if risk >= 35 else "Low"] += 1
        coverage = resource.get("risk_coverage")
        if isinstance(coverage, (int, float)):
            coverage_values.append(coverage)
        findings.extend(resource.get("findings", []))
        benchmark_counts.update(
            item.get("status", "NOT_EVALUATED")
            for item in resource.get("benchmarks", [])
        )

    return {
        "resource_count": len(resources),
        "finding_count": len(findings),
        "high_risk_count": sum(1 for score in risk_values if score >= 70),
        "average_risk": round(sum(risk_values) / len(risk_values), 2) if risk_values else 0,
        "average_risk_coverage": round(sum(coverage_values) / len(coverage_values), 1) if coverage_values else 0,
        "provider_counts": dict(provider_counts),
        "risk_bands": {band: risk_bands.get(band, 0) for band in ("High", "Medium", "Low")},
        "benchmark_counts": {
            status: benchmark_counts.get(status, 0)
            for status in ("PASS", "FAIL", "NOT_EVALUATED")
        },
        "findings_by_severity": dict(Counter(
            finding.get("severity", "UNKNOWN") for finding in findings
        )),
    }


def run_analysis(data_dir=DEFAULT_DATA_DIR, output_path=DEFAULT_REPORT_PATH):
    """Analyze available provider snapshots and write a dashboard report."""
    data_dir = Path(data_dir)
    all_resources = []
    provider_status = {}

    for provider in PROVIDERS:
        try:
            resources, status = _process_provider(provider, data_dir)
            all_resources.extend(resources)
            provider_status[provider] = status
        except Exception as error:
            provider_status[provider] = {
                "status": "error",
                "file": PROVIDERS[provider][0],
                "message": str(error),
            }

    report = {
        "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summarize_results(all_resources),
        "providers": provider_status,
        "resources": all_resources,
    }
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)
    if output_path.resolve() == DEFAULT_REPORT_PATH.resolve():
        REPORT_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        history_path = REPORT_HISTORY_DIR / f"scan-{report['run_id']}.json"
        history_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze local multi-cloud security snapshots.")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT_PATH)
    args = parser.parse_args(argv)

    report = run_analysis(args.data_dir, args.output)
    summary = report["summary"]
    print(f"Analysis report: {args.output.resolve()}")
    print(f"Resources: {summary['resource_count']}  Findings: {summary['finding_count']}  Average risk: {summary['average_risk']}")
    print("Provider snapshots:")
    for provider, status in report["providers"].items():
        count = status.get("count", 0)
        print(f"  {provider:<12} {status['status']:<10} {count} resource(s)")
        if status.get("message"):
            print(f"    {status['message']}")
    return 0 if summary["resource_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
