import os
import json
import urllib.request
from pathlib import Path

from cloudflare import Cloudflare

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MANAGED_WAF_ID = "efb7b8c949ac4650a09736fc376e9aee"


def _api(api_token, path):
    request = urllib.request.Request(
        "https://api.cloudflare.com/client/v4" + path,
        headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def collect_cloudflare_data(api_token=None):

    api_token = api_token or os.environ.get("CLOUDFLARE_API_TOKEN")

    if not api_token:
        raise ValueError(
            "CLOUDFLARE_API_TOKEN is not configured"
        )

    client = Cloudflare(
        api_token=api_token
    )

    results = []

    accounts = client.accounts.list()

    for account in accounts:

        account_data = {
            "provider": "cloudflare",
            "account_id": account.id,
            "account_name": account.name,
            "zones": []
        }

        zones = client.zones.list(
            account={"id": account.id}
        )

        for zone in zones:

            zone_data = {
                "zone_id": zone.id,
                "zone_name": zone.name,
                "status": zone.status,
                "security_rules": []
            }

            try:
                phase = _api(api_token, f"/zones/{zone.id}/rulesets/phases/http_request_firewall_managed/entrypoint")
                phase_rules = (phase.get("result") or {}).get("rules", [])
                zone_data["managed_waf_enabled"] = any(
                    rule.get("action") == "execute" and (rule.get("action_parameters") or {}).get("id") == MANAGED_WAF_ID
                    for rule in phase_rules
                )
                zone_data["managed_waf_phase_rules"] = phase_rules
            except Exception as error:
                zone_data["managed_waf_enabled"] = None
                zone_data["waf_check_error"] = str(error)

            # Get Cloudflare WAF/custom security rules
            try:
                rules = client.rulesets.list(
                    zone_id=zone.id
                )

                for ruleset in rules:

                    zone_data["security_rules"].append({
                        "id": ruleset.id,
                        "name": ruleset.name,
                        "kind": ruleset.kind,
                        "phase": ruleset.phase
                    })

            except Exception as e:

                zone_data["security_rules_error"] = str(e)

            account_data["zones"].append(zone_data)

        results.append(account_data)

    return results


if __name__ == "__main__":

    data = collect_cloudflare_data()

    output = PROJECT_ROOT / "data" / "cloudflare_raw.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")

    print(
        "Cloudflare accounts collected:",
        len(data)
    )

    print(f"Saved to {output}")
