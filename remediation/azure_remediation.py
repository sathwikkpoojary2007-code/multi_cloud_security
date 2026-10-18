"""Azure storage account security updates."""
from azure.identity import ClientSecretCredential
from azure.mgmt.storage import StorageManagementClient


def _client_for(resource_id, credentials):
    required = ("subscription_id", "tenant_id", "client_id", "client_secret")
    if not all(credentials.get(key) for key in required):
        raise ValueError("Configure Azure subscription and service principal credentials on the Service Connections page before changing Azure resources.")
    identity = ClientSecretCredential(tenant_id=credentials["tenant_id"], client_id=credentials["client_id"], client_secret=credentials["client_secret"])
    client = StorageManagementClient(identity, credentials["subscription_id"])
    parts = resource_id.strip("/").split("/")
    try:
        group = parts[parts.index("resourceGroups") + 1]
        name = parts[parts.index("storageAccounts") + 1]
    except (ValueError, IndexError):
        raise ValueError("Could not identify the Azure resource group and storage account.")
    return client, group, name


def secure_storage_account(resource_id, credentials):
    client, rg, name = _client_for(resource_id, credentials)
    result = client.storage_accounts.update(
        rg, name,
        {"allow_blob_public_access": False, "public_network_access": "Disabled",
         "enable_https_traffic_only": True, "minimum_tls_version": "TLS1_2"},
    )
    return {"status": "APPLIED", "resource_id": resource_id,
            "updated": ["allow_blob_public_access=False", "public_network_access=Disabled", "https_traffic_only=True", "minimum_tls_version=TLS1_2"],
            "public_network_access": getattr(result, "public_network_access", None)}
