"""Generate a fictional enterprise portfolio for presentations and demonstrations."""
from pathlib import Path
import json

from backend.security_pipeline import process_resource, summarize_results
from normalizer.common_model import normalize_s3_bucket
from normalizer.azure_normalizer import normalize_azure_storage
from normalizer.cisco_normalizer import normalize_cisco_resource
from normalizer.cloudflare_normalizer import normalize_cloudflare_resource
from security.s3_rules import check_s3_security
from security.azure_rules import check_azure_security
from security.cisco_rules import check_cisco_security
from security.cloudflare_rules import check_cloudflare_security

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "demo_portfolio.json"
DEMO_VERSION = 2
COMPANIES = (
    ("Northstar Commerce", "northstar"),
    ("Asterion Health Systems", "asterion"),
    ("Meridian Financial Group", "meridian"),
    ("Cinder Cloud Services", "cinder"),
)


def generate_resources():
    result = []
    for company_index, (company, slug) in enumerate(COMPANIES):
        for index in range(1, 13):
            secure = (index + company_index) % 4 != 0
            controls = {key: secure for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
            raw = {
                "bucket_name": f"demo-{slug}-prod-data-{index:02d}", "region": ("us-east-1", "us-west-2", "eu-west-1")[index % 3],
                "public_access_block": controls, "public_access_evaluated": True,
                "encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}, "encryption_evaluated": True,
                "company_name": company, "environment": "production" if index % 3 else "staging", "owner": ("Data Platform", "Security Operations", "Analytics")[index % 3],
                "estimated_size_gb": index * (12500 + company_index * 3900), "object_count": index * 1_780_000,
                "data_classification": ("Confidential", "Internal", "Restricted")[index % 3], "cost_center": f"CC-{company_index + 1}4{index:02d}",
            }
            result.append(("aws", raw, normalize_s3_bucket, check_s3_security))
        for index in range(1, 7):
            public = (index + company_index) % 3 == 0
            raw = {
                "provider": "azure", "resource_type": "storage_account",
                "resource_id": f"/subscriptions/demo-{slug}/resourceGroups/rg-{slug}-prod/providers/Microsoft.Storage/storageAccounts/{slug}st{index:02d}",
                "name": f"{slug}st{index:02d}", "location": ("eastus", "westeurope", "centralus")[index % 3],
                "public_network_access": "Enabled" if public else "Disabled", "allow_blob_public_access": public,
                "https_traffic_only": True, "minimum_tls_version": "TLS1_2", "company_name": company,
                "environment": "production" if index % 2 else "development", "owner": "Cloud Platform",
                "estimated_size_gb": index * 8400, "blob_count": index * 940_000, "data_classification": "Internal", "cost_center": f"CC-{company_index + 1}5{index:02d}",
            }
            result.append(("azure", raw, normalize_azure_storage, check_azure_security))
        for index in range(1, 4):
            broad = (index + company_index) % 2 == 0
            rules = [{"comment": "Demo broad rule" if broad else "Approved web service", "policy": "allow", "protocol": "Any" if broad else "tcp", "srcPort": "Any", "srcCidr": "Any", "destPort": "Any" if broad else "443", "destCidr": "Any" if broad else "10.20.0.0/16", "syslogEnabled": True}]
            raw = {"organization": f"{company} Network", "network": f"{company} Region {index}", "network_id": f"demo-net-{slug}-{index:02d}", "firewall_rules": {"rules": rules}, "company_name": company, "environment": "production", "connected_devices": 140 + index * 230, "critical_services": ["ERP", "Customer portal", "Data exchange"]}
            result.append(("cisco", raw, normalize_cisco_resource, check_cisco_security))
        zones = []
        for index in range(1, 5):
            waf = (index + company_index) % 3 != 0
            zones.append({"zone_id": f"demo-zone-{slug}-{index:02d}", "zone_name": f"{slug}-service-{index:02d}.example.test", "status": "active", "security_rules": [], "managed_waf_enabled": waf})
        raw = {"provider": "cloudflare", "account_id": f"demo-account-{slug}", "account_name": company, "company_name": company, "zones": zones}
        result.append(("cloudflare", raw, normalize_cloudflare_resource, check_cloudflare_security))

    resources = []
    for provider, raw, normalizer, checker in result:
        resource = process_resource(normalizer(raw), checker)
        resource["is_demo"] = True
        resource["metadata"].update({"company_name": raw.get("company_name", "Demo"), "environment": raw.get("environment", "production"), "owner": raw.get("owner", "Cloud Security"), "demo_notice": "Fictional demo inventory; no live cloud account is connected.", "portfolio_schema": DEMO_VERSION})
        for key in ("estimated_size_gb", "object_count", "blob_count", "data_classification", "cost_center", "connected_devices", "critical_services"):
            if key in raw:
                resource["metadata"][key] = raw[key]
        resources.append(resource)
    return resources


def load_or_create():
    if DATA_FILE.exists():
        try:
            resources = json.loads(DATA_FILE.read_text(encoding="utf-8"))
            if isinstance(resources, list) and len(resources) >= 80 and all(r.get("metadata", {}).get("portfolio_schema") == DEMO_VERSION for r in resources):
                return resources
        except (OSError, json.JSONDecodeError):
            pass
    resources = generate_resources()
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(resources, indent=2, ensure_ascii=False), encoding="utf-8")
    return resources


def disable():
    DATA_FILE.unlink(missing_ok=True)


def reset_portfolio():
    """Restore the deterministic portfolio, including its intentional findings."""
    resources = generate_resources()
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(resources, indent=2, ensure_ascii=False), encoding="utf-8")
    return resources


def simulate_remediation(provider, resource_id, rule):
    """Apply a local-only simulated fix to one fictional evaluator resource."""
    expected_rules = {
        "aws": "AWS-S3-001", "azure": "AZURE-STORAGE-001",
        "cisco": "CISCO-FW-001", "cloudflare": "CLOUDFLARE-WEB-001",
    }
    if expected_rules.get(provider) != rule:
        raise ValueError("No demo simulation is available for this provider rule.")
    resources = load_or_create()
    resource = next((item for item in resources if item.get("provider") == provider and item.get("resource_id") == resource_id and item.get("is_demo")), None)
    if not resource:
        raise ValueError("Fictional demo resource was not found.")
    if not any(finding.get("rule") == rule for finding in resource.get("findings", [])):
        raise ValueError("This demo finding is already fixed or is no longer present.")

    metadata = resource.setdefault("metadata", {})
    if provider == "aws":
        metadata["public_access_block"] = {key: True for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
        resource.setdefault("security", {})["exposure"] = 0.0
    elif provider == "azure":
        metadata.update({"public_network_access": "Disabled", "allow_blob_public_access": False, "https_traffic_only": True, "minimum_tls_version": "TLS1_2"})
        resource.setdefault("security", {}).update({"exposure": 0.0, "network_security": 0.0, "encryption": 0.0})
    elif provider == "cisco":
        for firewall_rule in metadata.get("firewall_rules", []):
            if firewall_rule.get("policy") == "allow" and firewall_rule.get("protocol") == "Any" and firewall_rule.get("srcCidr") == "Any" and firewall_rule.get("destCidr") == "Any":
                firewall_rule["policy"] = "deny"
        resource.setdefault("security", {}).update({"exposure": 0.0, "network_security": 0.0})
    else:
        for zone in metadata.get("zones", []):
            if zone.get("status") == "active":
                zone["managed_waf_enabled"] = True
        resource.setdefault("security", {}).update({"exposure": 0.0, "network_security": 0.0})

    checker = {"aws": check_s3_security, "azure": check_azure_security, "cisco": check_cisco_security, "cloudflare": check_cloudflare_security}[provider]
    process_resource(resource, checker)
    resource["remediation"] = {"status": "SIMULATED", "message": "Local demo simulation only. No provider API was called.", "rule": rule}
    DATA_FILE.write_text(json.dumps(resources, indent=2, ensure_ascii=False), encoding="utf-8")
    return resource


def simulate_manual_configuration(provider, resource_id, changes):
    """Persist a validated manual configuration edit to fictional data only."""
    from remediation.manual_configuration import validate_changes
    validate_changes(provider, changes)
    resources = load_or_create()
    resource = next((item for item in resources if item.get("provider") == provider and item.get("resource_id") == resource_id and item.get("is_demo")), None)
    if not resource:
        raise ValueError("Fictional demo resource was not found.")
    metadata = resource.setdefault("metadata", {})
    security = resource.setdefault("security", {})
    if provider == "aws":
        metadata["public_access_block"] = dict(changes["public_access_block"])
        security["exposure"] = 1.0 if any(value is False for value in changes["public_access_block"].values()) else 0.0
    elif provider == "azure":
        metadata.update(changes)
        network_open = changes.get("public_network_access", metadata.get("public_network_access")) == "Enabled"
        blob_public = changes.get("allow_blob_public_access", metadata.get("allow_blob_public_access")) is True
        transport_weak = changes.get("https_traffic_only", metadata.get("https_traffic_only")) is not True or changes.get("minimum_tls_version", metadata.get("minimum_tls_version")) != "TLS1_2"
        security.update({"exposure": 1.0 if network_open or blob_public else 0.0, "network_security": 1.0 if network_open else 0.0, "encryption": 1.0 if transport_weak else 0.0})
    elif provider == "cisco":
        if json.dumps(changes["expected_rules"], sort_keys=True) != json.dumps(metadata.get("firewall_rules", []), sort_keys=True):
            raise ValueError("Demo firewall rules changed. Reopen the editor and try again.")
        metadata["firewall_rules"] = changes["rules"]
        broad_allow = any(rule.get("policy") == "allow" and str(rule.get("protocol", "")).lower() == "any" and rule.get("srcCidr") == "Any" and rule.get("destCidr") == "Any" for rule in changes["rules"])
        security.update({"exposure": 1.0 if broad_allow else 0.0, "network_security": 1.0 if broad_allow else 0.0})
    elif provider == "cloudflare":
        zones = metadata.get("zones", [])
        active_ids = {zone.get("zone_id") for zone in zones if zone.get("status") == "active"}
        if set(changes["zones"]) != active_ids:
            raise ValueError("Choose settings for every active demo zone.")
        for zone in zones:
            if zone.get("zone_id") in changes["zones"]:
                zone["managed_waf_enabled"] = changes["zones"][zone["zone_id"]]
        uncovered = any(zone.get("status") == "active" and zone.get("managed_waf_enabled") is False for zone in zones)
        security.update({"exposure": 1.0 if uncovered else 0.0, "network_security": 1.0 if uncovered else 0.0})
    else:
        raise ValueError("Manual demo configuration is unavailable for this provider.")

    # Re-evaluate the observed settings themselves, not a prior cached score or
    # the fact that the form was submitted. An unchanged unsafe configuration
    # must continue to fail; a finding clears only when its actual controls pass.
    if provider == "aws":
        block = metadata.get("public_access_block", {})
        keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        unsafe = any(block.get(key) is False for key in keys)
        security["exposure"] = 1.0 if unsafe else 0.0
    elif provider == "azure":
        network_open = metadata.get("public_network_access") == "Enabled"
        blob_public = metadata.get("allow_blob_public_access") is True
        transport_weak = metadata.get("https_traffic_only") is not True or metadata.get("minimum_tls_version") != "TLS1_2"
        security.update({
            "exposure": 1.0 if network_open or blob_public else 0.0,
            "network_security": 1.0 if network_open else 0.0,
            "encryption": 1.0 if transport_weak else 0.0,
        })
    elif provider == "cisco":
        broad_allow = any(
            str(rule.get("policy", "")).lower() == "allow"
            and str(rule.get("protocol", "")).lower() == "any"
            and str(rule.get("srcCidr", "")).lower() == "any"
            and str(rule.get("destCidr", "")).lower() == "any"
            for rule in metadata.get("firewall_rules", [])
        )
        security.update({"exposure": 1.0 if broad_allow else 0.0, "network_security": 1.0 if broad_allow else 0.0})
    elif provider == "cloudflare":
        uncovered = any(zone.get("status") == "active" and zone.get("managed_waf_enabled") is not True for zone in metadata.get("zones", []))
        security.update({"exposure": 1.0 if uncovered else 0.0, "network_security": 1.0 if uncovered else 0.0})

    checker = {"aws": check_s3_security, "azure": check_azure_security, "cisco": check_cisco_security, "cloudflare": check_cloudflare_security}[provider]
    process_resource(resource, checker)
    resource["remediation"] = {"status": "SIMULATED_MANUAL", "message": "Local demo configuration edit only. No provider API was called."}
    DATA_FILE.write_text(json.dumps(resources, indent=2, ensure_ascii=False), encoding="utf-8")
    return resource
