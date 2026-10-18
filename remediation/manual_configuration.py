"""Apply validated, explicitly approved provider configuration edits."""
import json
import os


def validate_changes(provider, changes):
    if not isinstance(changes, dict):
        raise ValueError("Configuration changes must be an object.")
    if provider == "aws":
        keys = {"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"}
        value = changes.get("public_access_block")
        if not isinstance(value, dict) or set(value) != keys or any(type(value[key]) is not bool for key in keys):
            raise ValueError("Choose true or false for each of the four S3 public-access controls.")
    elif provider == "azure":
        allowed = {"public_network_access", "allow_blob_public_access", "https_traffic_only", "minimum_tls_version"}
        if not changes or set(changes) - allowed:
            raise ValueError("Unsupported Azure storage settings were submitted.")
        if "public_network_access" in changes and changes["public_network_access"] not in {"Enabled", "Disabled"}:
            raise ValueError("Public network access must be Enabled or Disabled.")
        for key in ("allow_blob_public_access", "https_traffic_only"):
            if key in changes and type(changes[key]) is not bool:
                raise ValueError(f"{key} must be a true or false value.")
        if "minimum_tls_version" in changes and changes["minimum_tls_version"] not in {"TLS1_0", "TLS1_1", "TLS1_2"}:
            raise ValueError("Select a supported minimum TLS version.")
    elif provider == "cisco":
        rules = changes.get("rules")
        expected = changes.get("expected_rules")
        if not isinstance(rules, list) or not isinstance(expected, list) or len(rules) > 200:
            raise ValueError("Firewall configuration must be a valid rule list (up to 200 rules).")
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("policy") not in {"allow", "deny"} or str(rule.get("protocol", "")).lower() not in {"any", "tcp", "udp", "icmp", "icmp6"} or not all(isinstance(rule.get(key), str) and rule[key].strip() for key in ("srcCidr", "destCidr")):
                raise ValueError("Each Meraki rule needs a valid policy, protocol, source, and destination.")
    elif provider == "cloudflare":
        zones = changes.get("zones")
        if not isinstance(zones, dict) or not zones or any(type(value) is not bool for value in zones.values()):
            raise ValueError("Choose whether the managed WAF should be enabled for each active zone.")
    else:
        raise ValueError("Manual configuration is unavailable for this provider.")
    return changes


def apply_changes(provider, resource, changes, credentials):
    validate_changes(provider, changes)
    resource_id = resource["resource_id"]
    if provider == "aws":
        import boto3
        auth = credentials or {}
        aws_session = boto3.Session(
            aws_access_key_id=auth.get("access_key_id") or None,
            aws_secret_access_key=auth.get("secret_access_key") or None,
            aws_session_token=auth.get("session_token") or None,
        )
        region = resource.get("metadata", {}).get("region") or auth.get("region")
        client = aws_session.client("s3", region_name=region) if region else aws_session.client("s3")
        client.put_public_access_block(Bucket=resource_id, PublicAccessBlockConfiguration=changes["public_access_block"])
        return {"status": "APPLIED", "provider": provider, "resource_id": resource_id, "public_access_block": changes["public_access_block"]}
    if provider == "azure":
        from remediation.azure_remediation import _client_for
        client, group, name = _client_for(resource_id, credentials)
        result = client.storage_accounts.update(group, name, changes)
        return {"status": "APPLIED", "provider": provider, "resource_id": resource_id, "changed": changes, "public_network_access": getattr(result, "public_network_access", None)}
    if provider == "cisco":
        import meraki
        network_id = resource_id
        dashboard = meraki.DashboardAPI(api_key=(credentials or {}).get("api_key") or os.environ.get("MERAKI_DASHBOARD_API_KEY"), suppress_logging=True)
        current = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(network_id)
        live_rules = current.get("rules", [])
        if json.dumps(live_rules, sort_keys=True) != json.dumps(changes["expected_rules"], sort_keys=True):
            raise ValueError("Meraki firewall rules changed since this page was scanned. Rescan and reopen the editor before saving.")
        args = {"rules": changes["rules"]}
        if "syslogDefaultRule" in current:
            args["syslogDefaultRule"] = current["syslogDefaultRule"]
        dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(network_id, **args)
        return {"status": "APPLIED", "provider": provider, "resource_id": resource_id, "rule_count": len(changes["rules"])}
    if provider == "cloudflare":
        from remediation.cloudflare_remediation import set_managed_waf
        zones = {zone.get("zone_id"): zone for zone in resource.get("metadata", {}).get("zones", [])}
        if set(changes["zones"]) - set(zones):
            raise ValueError("The zone list has changed since this resource was scanned. Rescan before editing it.")
        result = set_managed_waf((credentials or {}).get("api_token"), changes["zones"])
        return {"status": "APPLIED", "provider": provider, "resource_id": resource_id, **result}
