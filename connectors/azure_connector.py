import os
import json
from pathlib import Path

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _get_azure_client(credentials=None):
    credentials = credentials or {}
    subscription_id = credentials.get("subscription_id") or os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        raise ValueError("AZURE_SUBSCRIPTION_ID is not configured")

    service_principal_fields = ("tenant_id", "client_id", "client_secret")
    has_sp = any(credentials.get(key) for key in service_principal_fields)
    if has_sp and not all(credentials.get(key) for key in service_principal_fields):
        raise ValueError("Azure service principal setup is incomplete. Provide tenant ID, client ID, and client secret together, or leave all three blank and configure DefaultAzureCredential on this host.")

    credential = (
        ClientSecretCredential(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
        )
        if has_sp else DefaultAzureCredential()
    )

    client = StorageManagementClient(credential, subscription_id)
    return client, subscription_id


def collect_single_azure_storage(account_name, resource_group=None, credentials=None):
    client, subscription_id = _get_azure_client(credentials)

    if account_name.startswith("/"):
        parts = account_name.strip("/").split("/")
        try:
            resource_group = parts[parts.index("resourceGroups") + 1]
            account_name = parts[parts.index("storageAccounts") + 1]
        except (ValueError, IndexError):
            pass

    account = None
    if resource_group:
        account = client.storage_accounts.get_properties(resource_group, account_name)
    else:
        for acc in client.storage_accounts.list():
            if acc.name.lower() == account_name.lower():
                account = acc
                break

    if not account:
        raise ValueError(f"Azure storage account '{account_name}' was not found in subscription {subscription_id}.")

    tls_val = getattr(account.minimum_tls_version, "value", account.minimum_tls_version)
    return {
        "provider": "azure",
        "resource_type": "storage_account",
        "resource_id": account.id,
        "name": account.name,
        "location": account.location,
        "public_network_access": account.public_network_access,
        "allow_blob_public_access": account.allow_blob_public_access,
        "https_traffic_only": account.enable_https_traffic_only,
        "minimum_tls_version": str(tls_val) if tls_val else "TLS1_2",
        "encryption": (
            account.encryption.key_source
            if account.encryption else None
        )
    }


def collect_azure_storage(credentials=None):
    client, _ = _get_azure_client(credentials)
    resources = []
    for account in client.storage_accounts.list():
        tls_val = getattr(account.minimum_tls_version, "value", account.minimum_tls_version)
        resource = {
            "provider": "azure",
            "resource_type": "storage_account",
            "resource_id": account.id,
            "name": account.name,
            "location": account.location,
            "public_network_access": account.public_network_access,
            "allow_blob_public_access": account.allow_blob_public_access,
            "https_traffic_only": account.enable_https_traffic_only,
            "minimum_tls_version": str(tls_val) if tls_val else "TLS1_2",
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
