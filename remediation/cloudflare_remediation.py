"""Deploy Cloudflare's managed WAF ruleset without replacing existing phase rules."""
import json
import urllib.error
import urllib.request

from connectors.cloudflare_connector import MANAGED_WAF_ID


def _request(token, method, path, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        "https://api.cloudflare.com/client/v4" + path, data=data, method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not result.get("success"):
        raise RuntimeError("Cloudflare rejected the managed WAF update.")
    return result.get("result") or {}


def deploy_managed_waf(account, credentials):
    token = credentials.get("api_token")
    if not token:
        raise ValueError("Save a Cloudflare API token on the Service Connections page first.")
    updated = []
    for zone in account.get("metadata", {}).get("zones", []):
        if zone.get("status") != "active" or zone.get("managed_waf_enabled") is not False:
            continue
        zone_id = zone.get("zone_id")
        path = f"/zones/{zone_id}/rulesets/phases/http_request_firewall_managed/entrypoint"
        try:
            current = _request(token, "GET", path)
            rules = current.get("rules", [])
            ruleset_id = current.get("id")
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            rules, ruleset_id = [], None
        if any(rule.get("action") == "execute" and (rule.get("action_parameters") or {}).get("id") == MANAGED_WAF_ID for rule in rules):
            continue
        rules.append({
            "action": "execute", "expression": "true",
            "action_parameters": {"id": MANAGED_WAF_ID, "version": "latest"},
            "description": "MultiCloudSecurity: Cloudflare Managed Ruleset",
            "enabled": True,
        })
        body = {"name": current.get("name") or "MultiCloudSecurity managed WAF", "kind": "zone", "phase": "http_request_firewall_managed", "rules": rules}
        if ruleset_id:
            _request(token, "PUT", f"/zones/{zone_id}/rulesets/{ruleset_id}", body)
        else:
            _request(token, "POST", path, body)
        updated.append(zone_id)
    if not updated:
        return {"status": "APPLIED", "updated": [], "message": "All active zones already have the managed WAF ruleset."}
    return {"status": "APPLIED", "updated": updated}


def set_managed_waf(token, desired_zones):
    if not token:
        raise ValueError("Save a Cloudflare API token on the Service Connections page first.")
    changed = []
    for zone_id, should_enable in desired_zones.items():
        path = f"/zones/{zone_id}/rulesets/phases/http_request_firewall_managed/entrypoint"
        try:
            current = _request(token, "GET", path)
            rules = current.get("rules", [])
            ruleset_id = current.get("id")
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            current, rules, ruleset_id = {}, [], None
        matching = [rule for rule in rules if rule.get("action") == "execute" and (rule.get("action_parameters") or {}).get("id") == MANAGED_WAF_ID]
        if bool(matching) == should_enable:
            continue
        if should_enable:
            rules.append({"action": "execute", "expression": "true", "action_parameters": {"id": MANAGED_WAF_ID, "version": "latest"}, "description": "MultiCloudSecurity: Cloudflare Managed Ruleset", "enabled": True})
        else:
            rules = [rule for rule in rules if rule not in matching]
        body = {"rules": rules}
        if ruleset_id:
            _request(token, "PUT", f"/zones/{zone_id}/rulesets/{ruleset_id}", body)
        elif rules:
            _request(token, "POST", path, {"name": "MultiCloudSecurity managed WAF", "kind": "zone", "phase": "http_request_firewall_managed", "rules": rules})
        changed.append(zone_id)
    return {"updated_zone_ids": changed}
