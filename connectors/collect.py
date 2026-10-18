"""Collect provider security snapshots into the local data directory."""

import argparse
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUTS = {
    "aws": "aws_s3_security_raw.json",
    "azure": "azure_raw.json",
    "cisco": "cisco_raw.json",
    "cloudflare": "cloudflare_raw.json",
}


def collect(provider, credentials=None):
    if credentials is None:
        from connectors.provider_credentials import get
        credentials = get(provider)
    if provider == "aws":
        from connectors.aws_security_connector import collect_s3_security_data
        return collect_s3_security_data(credentials=credentials)
    if provider == "azure":
        from connectors.azure_connector import collect_azure_storage
        return collect_azure_storage(credentials=credentials)
    if provider == "cisco":
        from connectors.cisco_meraki import collect_cisco_security_data
        return collect_cisco_security_data(api_key=credentials.get("api_key"))
    if provider == "cloudflare":
        from connectors.cloudflare_connector import collect_cloudflare_data
        return collect_cloudflare_data(api_token=credentials.get("api_token"))
    raise ValueError(f"Unknown provider: {provider}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect read-only security snapshots from cloud providers.")
    parser.add_argument("providers", nargs="+", choices=tuple(OUTPUTS) + ("all",))
    args = parser.parse_args(argv)
    providers = list(OUTPUTS) if "all" in args.providers else list(dict.fromkeys(args.providers))
    failures = 0

    for provider in providers:
        try:
            records = collect(provider)
            output = PROJECT_ROOT / "data" / OUTPUTS[provider]
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(records, indent=2), encoding="utf-8")
            print(f"{provider}: collected {len(records)} resource(s) -> {output}")
        except Exception as error:
            failures += 1
            print(f"{provider}: collection failed: {error}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
