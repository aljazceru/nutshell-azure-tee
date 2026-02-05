#!/bin/bash
#
# Clean up all Azure infrastructure for Nutshell TEE deployment
#
# This script removes:
# - Container Group
# - Key Vault (with purge protection handling)
# - Storage Account
# - Attestation Provider
# - Managed Identity
# - Resource Group
#
set -e

# ============================================================================
# Configuration - Should match setup-infrastructure.sh
# ============================================================================
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-nutshell-tee}"
LOCATION="${LOCATION:-northeurope}"
KEY_VAULT_NAME="${KEY_VAULT_NAME:-kv-nutshell-tee}"
STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-stnutshelltee}"
ATTESTATION_PROVIDER="${ATTESTATION_PROVIDER:-attestnutshelltee}"
MANAGED_IDENTITY_NAME="${MANAGED_IDENTITY_NAME:-id-nutshell-tee}"
CONTAINER_GROUP_NAME="${CONTAINER_GROUP_NAME:-nutshell-tee}"

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

confirm() {
    local message="$1"
    read -p "$message [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# ============================================================================
# Cleanup Functions
# ============================================================================

delete_container_group() {
    log "Checking for container group '$CONTAINER_GROUP_NAME'..."
    if az container show --resource-group "$RESOURCE_GROUP" --name "$CONTAINER_GROUP_NAME" &> /dev/null; then
        log "Deleting container group..."
        az container delete \
            --resource-group "$RESOURCE_GROUP" \
            --name "$CONTAINER_GROUP_NAME" \
            --yes \
            --output none
        log "Container group deleted"
    else
        log "Container group not found, skipping"
    fi
}

delete_key_vault() {
    log "Checking for Key Vault '$KEY_VAULT_NAME'..."
    if az keyvault show --name "$KEY_VAULT_NAME" &> /dev/null; then
        log "Deleting Key Vault..."
        az keyvault delete \
            --name "$KEY_VAULT_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --output none
        log "Key Vault deleted"

        # Check if purge protection is enabled
        if az keyvault show-deleted --name "$KEY_VAULT_NAME" &> /dev/null; then
            if confirm "Key Vault is in soft-deleted state. Purge it permanently? (This cannot be undone)"; then
                log "Purging Key Vault..."
                az keyvault purge \
                    --name "$KEY_VAULT_NAME" \
                    --location "$LOCATION" \
                    --output none 2>/dev/null || log "Could not purge (purge protection may be enabled)"
            else
                log "Key Vault left in soft-deleted state (will be auto-purged after retention period)"
            fi
        fi
    else
        log "Key Vault not found, skipping"
    fi
}

delete_storage_account() {
    log "Checking for Storage Account '$STORAGE_ACCOUNT'..."
    if az storage account show --name "$STORAGE_ACCOUNT" &> /dev/null; then
        log "Deleting Storage Account..."
        az storage account delete \
            --name "$STORAGE_ACCOUNT" \
            --resource-group "$RESOURCE_GROUP" \
            --yes \
            --output none
        log "Storage Account deleted"
    else
        log "Storage Account not found, skipping"
    fi
}

delete_attestation_provider() {
    log "Checking for Attestation Provider '$ATTESTATION_PROVIDER'..."
    if az attestation show --name "$ATTESTATION_PROVIDER" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log "Deleting Attestation Provider..."
        az attestation delete \
            --name "$ATTESTATION_PROVIDER" \
            --resource-group "$RESOURCE_GROUP" \
            --yes \
            --output none
        log "Attestation Provider deleted"
    else
        log "Attestation Provider not found, skipping"
    fi
}

delete_managed_identity() {
    log "Checking for Managed Identity '$MANAGED_IDENTITY_NAME'..."
    if az identity show --name "$MANAGED_IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
        log "Deleting Managed Identity..."
        az identity delete \
            --name "$MANAGED_IDENTITY_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --output none
        log "Managed Identity deleted"
    else
        log "Managed Identity not found, skipping"
    fi
}

delete_resource_group() {
    log "Checking for Resource Group '$RESOURCE_GROUP'..."
    if az group show --name "$RESOURCE_GROUP" &> /dev/null; then
        log "Deleting Resource Group (this will remove all remaining resources)..."
        az group delete \
            --name "$RESOURCE_GROUP" \
            --yes \
            --output none
        log "Resource Group deleted"
    else
        log "Resource Group not found, skipping"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    log "=== Nutshell TEE Infrastructure Cleanup ==="
    log ""
    log "This will delete the following resources:"
    log "  Resource Group: $RESOURCE_GROUP"
    log "  Container Group: $CONTAINER_GROUP_NAME"
    log "  Key Vault: $KEY_VAULT_NAME"
    log "  Storage Account: $STORAGE_ACCOUNT"
    log "  Attestation Provider: $ATTESTATION_PROVIDER"
    log "  Managed Identity: $MANAGED_IDENTITY_NAME"
    log ""

    # Check Azure CLI
    if ! command -v az &> /dev/null; then
        error "Azure CLI not found"
    fi

    if ! az account show &> /dev/null; then
        error "Not logged in to Azure. Run 'az login' first."
    fi

    if ! confirm "Are you sure you want to delete ALL these resources?"; then
        log "Cleanup cancelled"
        exit 0
    fi

    log ""

    # Delete in order (most dependent first)
    delete_container_group
    delete_key_vault
    delete_storage_account
    delete_attestation_provider
    delete_managed_identity
    delete_resource_group

    log ""
    log "=== Cleanup Complete ==="
    log ""
    log "Note: If Key Vault had purge protection enabled, it may still exist"
    log "in a soft-deleted state. Check with:"
    log "  az keyvault list-deleted --query \"[?name=='$KEY_VAULT_NAME']\""
}

# Quick mode - delete just the resource group (faster but less verbose)
quick_cleanup() {
    log "=== Quick Cleanup (Resource Group Deletion) ==="
    log ""
    log "This will delete resource group '$RESOURCE_GROUP' and ALL resources within it."
    log ""

    if ! confirm "Are you sure?"; then
        log "Cleanup cancelled"
        exit 0
    fi

    delete_resource_group

    # Handle soft-deleted Key Vault
    if az keyvault show-deleted --name "$KEY_VAULT_NAME" &> /dev/null 2>&1; then
        if confirm "Key Vault '$KEY_VAULT_NAME' is soft-deleted. Purge it?"; then
            az keyvault purge --name "$KEY_VAULT_NAME" --location "$LOCATION" --output none 2>/dev/null || true
        fi
    fi

    log ""
    log "=== Quick Cleanup Complete ==="
}

# ============================================================================
# CLI
# ============================================================================

case "${1:-}" in
    --quick|-q)
        quick_cleanup
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Clean up all Azure infrastructure for Nutshell TEE deployment."
        echo ""
        echo "Options:"
        echo "  --quick, -q    Quick mode: just delete the resource group"
        echo "  --help, -h     Show this help message"
        echo ""
        echo "Environment variables:"
        echo "  RESOURCE_GROUP         Resource group name (default: rg-nutshell-tee)"
        echo "  KEY_VAULT_NAME         Key Vault name (default: kv-nutshell-tee)"
        echo "  STORAGE_ACCOUNT        Storage account name (default: stnutshelltee)"
        echo "  ATTESTATION_PROVIDER   MAA provider name (default: attestnutshelltee)"
        echo "  MANAGED_IDENTITY_NAME  Managed identity name (default: id-nutshell-tee)"
        echo "  CONTAINER_GROUP_NAME   Container group name (default: nutshell-tee)"
        ;;
    "")
        main
        ;;
    *)
        echo "Unknown option: $1"
        echo "Run '$0 --help' for usage"
        exit 1
        ;;
esac
