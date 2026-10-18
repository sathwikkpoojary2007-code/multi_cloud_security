"""Encrypted local storage for provider API credentials."""
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
KEY_PATH = DATA_DIR / "provider_credentials.key"
STORE_PATH = DATA_DIR / "provider_credentials.enc"


def _fernet():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with KEY_PATH.open("xb") as handle:
            handle.write(Fernet.generate_key())
    except FileExistsError:
        pass
    return Fernet(KEY_PATH.read_bytes())


def load_all():
    if not STORE_PATH.exists():
        return {}
    return json.loads(_fernet().decrypt(STORE_PATH.read_bytes()).decode("utf-8"))


def save(provider, values):
    providers = load_all()
    merged = providers.get(provider, {}).copy()
    merged.update({key: str(value).strip() for key, value in values.items() if value})
    providers[provider] = merged
    encrypted = _fernet().encrypt(json.dumps(providers).encode("utf-8"))
    temp = STORE_PATH.with_suffix(".tmp")
    temp.write_bytes(encrypted)
    os.replace(temp, STORE_PATH)


def get(provider):
    return load_all().get(provider) or {}


def statuses():
    values = load_all()
    required = {
        "aws": ("access_key_id", "secret_access_key"),
        "azure": ("subscription_id", "tenant_id", "client_id", "client_secret"),
        "cisco": ("api_key",),
        "cloudflare": ("api_token",),
    }
    configured = {name: all(values.get(name, {}).get(key) for key in fields) for name, fields in required.items()}
    configured["aws"] = configured["aws"] or bool(os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY")) or bool(os.environ.get("AWS_PROFILE"))
    configured["azure"] = configured["azure"] or bool(os.environ.get("AZURE_SUBSCRIPTION_ID"))
    configured["cisco"] = configured["cisco"] or bool(os.environ.get("MERAKI_DASHBOARD_API_KEY"))
    configured["cloudflare"] = configured["cloudflare"] or bool(os.environ.get("CLOUDFLARE_API_TOKEN"))
    return configured
