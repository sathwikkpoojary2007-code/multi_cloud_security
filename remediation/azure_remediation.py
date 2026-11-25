"""Azure storage account security updates."""
import os
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient


def _client_for(resource_id, credentials):
    credentials = credentials or {}
    subscription_id = credentials.get("subscription_id") or os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        raise ValueError("Configure Azure subscription ID in Service Connections or AZURE_SUBSCRIPTION_ID environment variable.")

    service_principal_fields = ("tenant_id", "client_id", "client_secret")
    has_sp = any(credentials.get(k) for k in service_principal_fields)
    if has_sp and not all(credentials.get(k) for k in service_principal_fields):
        raise ValueError("Configure Azure tenant ID, client ID, and client secret together, or configure DefaultAzureCredential.")

    if has_sp:
        identity = ClientSecretCredential(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"]
        )
    else:
        identity = DefaultAzureCredential()

    client = StorageManagementClient(identity, subscription_id)
    parts = resource_id.strip("/").split("/")
    try:
        group = parts[parts.index("resourceGroups") + 1]
        name = parts[parts.index("storageAccounts") + 1]
    except (ValueError, IndexError):
        raise ValueError("Could not identify the Azure resource group and storage account from the resource ID.")
    return client, group, name


def secure_storage_account(resource_id, credentials):
    client, rg, name = _client_for(resource_id, credentials)
    result = client.storage_accounts.update(
        rg, name,
        {"allow_blob_public_access": False, "public_network_access": "Disabled",
         "enable_https_traffic_only": True, "minimum_tls_version": "TLS1_2"},
    )
    return {
        "status": "APPLIED",
        "resource_id": resource_id,
        "updated": ["allow_blob_public_access=False", "public_network_access=Disabled", "https_traffic_only=True", "minimum_tls_version=TLS1_2"],
        "public_network_access": getattr(result, "public_network_access", None)
    }
