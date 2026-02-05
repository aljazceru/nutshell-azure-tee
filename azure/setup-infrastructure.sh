#!/bin/bash
#
# Set up Azure infrastructure for Nutshell TEE deployment
#
# This script creates:
# - Resource Group
# - Key Vault (Premium SKU for HSM-backed keys)
# - Storage Account with blob container
# - Microsoft Azure Attestation provider
# - User-assigned Managed Identity
# - RBAC role assignments
#
set -e

# ============================================================================
# Configuration - MODIFY THESE VALUES
# ============================================================================
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-nutshell-tee}"
LOCATION="${LOCATION:-northeurope}"
KEY_VAULT_NAME="${KEY_VAULT_NAME:-kv-nutshell-tee}"
STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-stnutshelltee}"
ATTESTATION_PROVIDER="${ATTESTATION_PROVIDER:-attestnutshelltee}"
MANAGED_IDENTITY_NAME="${MANAGED_IDENTITY_NAME:-id-nutshell-tee}"

# ============================================================================
# Helper Functions
# ============================================================================

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

error() {
    log "ERROR: $*" >&2
    exit 1
}

# ============================================================================
# Main Setup
# ============================================================================

main() {
    log "=== Nutshell TEE Infrastructure Setup ==="
    log ""
    log "Configuration:"
    log "  Resource Group: $RESOURCE_GROUP"
    log "  Location: $LOCATION"
    log "  Key Vault: $KEY_VAULT_NAME"
    log "  Storage Account: $STORAGE_ACCOUNT"
    log "  Attestation Provider: $ATTESTATION_PROVIDER"
    log "  Managed Identity: $MANAGED_IDENTITY_NAME"
    log ""

    # Check Azure CLI
    if ! command -v az &> /dev/null; then
        error "Azure CLI not found. Install from https://docs.microsoft.com/cli/azure/install-azure-cli"
    fi

    # Check logged in
    if ! az account show &> /dev/null; then
        error "Not logged in to Azure. Run 'az login' first."
    fi

    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    log "Using subscription: $SUBSCRIPTION_ID"

    # ========================================================================
    # Phase 1: Resource Group
    # ========================================================================
    log ""
    log "=== Phase 1: Resource Group ==="

    if az group show --name "$RESOURCE_GROUP" &> /dev/null; then
        log "Resource group '$RESOURCE_GROUP' already exists"
    else
        log "Creating resource group..."
        az group create \
            --name "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --output none
        log "Resource group created"
    fi

    # ========================================================================
    # Phase 2: Key Vault
    # ========================================================================
    log ""
    log "=== Phase 2: Key Vault ==="

    if az keyvault show --name "$KEY_VAULT_NAME" &> /dev/null; then
        log "Key Vault '$KEY_VAULT_NAME' already exists"
    else
        log "Creating Key Vault (Premium SKU for HSM support)..."
        az keyvault create \
            --name "$KEY_VAULT_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --sku premium \
            --enable-rbac-authorization true \
            --output none
        log "Key Vault created"
    fi

    KV_ID=$(az keyvault show --name "$KEY_VAULT_NAME" --query id -o tsv)

    # ========================================================================
    # Phase 3: Storage Account
    # ========================================================================
    log ""
    log "=== Phase 3: Storage Account ==="

    if az storage account show --name "$STORAGE_ACCOUNT" &> /dev/null; then
        log "Storage account '$STORAGE_ACCOUNT' already exists"
    else
        log "Creating storage account..."
        az storage account create \
            --name "$STORAGE_ACCOUNT" \
            --resource-group "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --sku Standard_LRS \
            --kind StorageV2 \
            --output none
        log "Storage account created"
    fi

    # Create blob container (use key auth - more reliable than login which requires RBAC propagation)
    log "Creating blob container 'encfs'..."
    az storage container create \
        --account-name "$STORAGE_ACCOUNT" \
        --name encfs \
        --auth-mode key \
        --output none 2>/dev/null || log "Container 'encfs' already exists"

    # Create Azure Files share for Caddy ACME persistence
    log "Creating file share 'caddy'..."
    STORAGE_KEY=$(az storage account keys list \
        --resource-group "$RESOURCE_GROUP" \
        --account-name "$STORAGE_ACCOUNT" \
        --query '[0].value' -o tsv)
    az storage share create \
        --account-name "$STORAGE_ACCOUNT" \
        --account-key "$STORAGE_KEY" \
        --name caddy \
        --output none 2>/dev/null || log "File share 'caddy' already exists"

    STORAGE_ID=$(az storage account show --name "$STORAGE_ACCOUNT" --query id -o tsv)

    # ========================================================================
    # Phase 4: Attestation Provider
    # ========================================================================
    log ""
    log "=== Phase 4: Microsoft Azure Attestation ==="

    if az attestation show --name "$ATTESTATION_PROVIDER" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log "Attestation provider '$ATTESTATION_PROVIDER' already exists"
    else
        log "Creating attestation provider..."
        az attestation create \
            --name "$ATTESTATION_PROVIDER" \
            --resource-group "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --output none
        log "Attestation provider created"
    fi

    MAA_ENDPOINT="https://${ATTESTATION_PROVIDER}.${LOCATION}.attest.azure.net"

    # ========================================================================
    # Phase 5: Managed Identity
    # ========================================================================
    log ""
    log "=== Phase 5: Managed Identity ==="

    if az identity show --name "$MANAGED_IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log "Managed identity '$MANAGED_IDENTITY_NAME' already exists"
    else
        log "Creating managed identity..."
        az identity create \
            --name "$MANAGED_IDENTITY_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --output none
        log "Managed identity created"
    fi

    IDENTITY_PRINCIPAL=$(az identity show \
        --name "$MANAGED_IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query principalId -o tsv)

    IDENTITY_ID=$(az identity show \
        --name "$MANAGED_IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query id -o tsv)

    # ========================================================================
    # Phase 6: RBAC Role Assignments
    # ========================================================================
    log ""
    log "=== Phase 6: RBAC Role Assignments ==="

    # Key Vault Crypto Service Release User (for encfs key release)
    log "Assigning Key Vault Crypto Service Release User role..."
    az role assignment create \
        --role "Key Vault Crypto Service Release User" \
        --assignee "$IDENTITY_PRINCIPAL" \
        --scope "$KV_ID" \
        --output none 2>/dev/null || log "Role already assigned"

    # Key Vault Secrets User (for secrets)
    log "Assigning Key Vault Secrets User role..."
    az role assignment create \
        --role "Key Vault Secrets User" \
        --assignee "$IDENTITY_PRINCIPAL" \
        --scope "$KV_ID" \
        --output none 2>/dev/null || log "Role already assigned"

    # Storage Blob Data Contributor (for encfs blob access)
    log "Assigning Storage Blob Data Contributor role to managed identity..."
    az role assignment create \
        --role "Storage Blob Data Contributor" \
        --assignee "$IDENTITY_PRINCIPAL" \
        --scope "$STORAGE_ID" \
        --output none 2>/dev/null || log "Role already assigned"

    # Also grant current user blob access for uploads
    log "Assigning Storage Blob Data Contributor role to current user..."
    CURRENT_USER=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "")
    if [ -n "$CURRENT_USER" ]; then
        az role assignment create \
            --role "Storage Blob Data Contributor" \
            --assignee "$CURRENT_USER" \
            --scope "$STORAGE_ID" \
            --output none 2>/dev/null || log "Role already assigned"

        # Grant current user Key Vault Secrets Officer for secret management
        log "Assigning Key Vault Secrets Officer role to current user..."
        az role assignment create \
            --role "Key Vault Secrets Officer" \
            --assignee "$CURRENT_USER" \
            --scope "$KV_ID" \
            --output none 2>/dev/null || log "Role already assigned"

        # Grant current user Key Vault Crypto Officer for key management
        log "Assigning Key Vault Crypto Officer role to current user..."
        az role assignment create \
            --role "Key Vault Crypto Officer" \
            --assignee "$CURRENT_USER" \
            --scope "$KV_ID" \
            --output none 2>/dev/null || log "Role already assigned"
    else
        log "Warning: Could not get current user ID, skipping user role assignment"
    fi

    # ========================================================================
    # Summary
    # ========================================================================
    log ""
    log "=== Infrastructure Setup Complete ==="
    log ""
    log "Resources created:"
    log "  Resource Group: $RESOURCE_GROUP"
    log "  Key Vault: https://${KEY_VAULT_NAME}.vault.azure.net"
    log "  Storage Account: https://${STORAGE_ACCOUNT}.blob.core.windows.net"
    log "  Attestation: $MAA_ENDPOINT"
    log "  Managed Identity: $IDENTITY_ID"
    log ""
    log "Next steps:"
    log ""
    log "1. Generate and import encryption key:"
    log "   openssl rand -out keyfile.bin 32"
    log "   # Use importkey tool from confidential-sidecar-containers to import"
    log ""
    log "2. Create and upload encrypted filesystem:"
    log "   sudo ./create-encrypted-fs.sh"
    log "   az storage blob upload \\"
    log "     --account-name $STORAGE_ACCOUNT \\"
    log "     --container-name encfs \\"
    log "     --file encfs.img \\"
    log "     --name encfs.img \\"
    log "     --type page \\"
    log "     --auth-mode key"
    log ""
    log "3. Store application secrets:"
    log "   az keyvault secret set --vault-name $KEY_VAULT_NAME --name MINT-PRIVATE-KEY --value \"\$(openssl rand -hex 32)\""
    log "   az keyvault secret set --vault-name $KEY_VAULT_NAME --name MINT-SPARK-API-KEY --value \"<your-api-key>\""
    log "   az keyvault secret set --vault-name $KEY_VAULT_NAME --name MINT-SPARK-MNEMONIC --value \"<your-mnemonic>\""
    log ""
    log "4. Build and push container image:"
    log "   # Push to GitHub to trigger the build-tee.yml workflow"
    log "   # Or build locally:"
    log "   docker build -f Dockerfile.tee -t ghcr.io/<user>/nutshell-tee:latest ."
    log "   docker push ghcr.io/<user>/nutshell-tee:latest"
    log ""
    log "5. Deploy to Azure:"
    log "   NUTSHELL_IMAGE=ghcr.io/<user>/nutshell-tee:latest ./deploy.sh"
    log ""
}

main "$@"
