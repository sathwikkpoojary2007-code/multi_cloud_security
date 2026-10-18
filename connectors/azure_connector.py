
import os
import json
from pathlib import Path

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def collect_azure_storage(credentials=None):
    credentials = credentials or {}

    subscription_id = credentials.get("subscription_id") or os.environ.get("AZURE_SUBSCRIPTION_ID")

    if not subscription_id:
        raise ValueError(
            "AZURE_SUBSCRIPTION_ID is not configured"
        )

    credential = (ClientSecretCredential(tenant_id=credentials["tenant_id"], client_id=credentials["client_id"], client_secret=credentials["client_secret"])
                  if all(credentials.get(key) for key in ("tenant_id", "client_id", "client_secret"))
                  else DefaultAzureCredential())

    client = StorageManagementClient(
        credential,
        subscription_id
    )

    resources = []

    for account in client.storage_accounts.list():

        resource = {
            "provider": "azure",
            "resource_type": "storage_account",
            "resource_id": account.id,
            "name": account.name,
            "location": account.location,
            "public_network_access": account.public_network_access,
            "allow_blob_public_access": account.allow_blob_public_access,
            "https_traffic_only": account.enable_https_traffic_only,
            "minimum_tls_version": account.minimum_tls_version,
            "encryption": (
                account.encryption.key_source
                if account.encryption else None
            )
        }

        resources.append(resource)

    return resources

if __name__ == "__main__":

    data = collect_azure_storage()

    output = PROJECT_ROOT / "data" / "azure_raw.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")

    print("Azure resources collected:", len(data))
    print(f"Saved to {output}")
