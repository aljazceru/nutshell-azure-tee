#!/bin/bash
#
# Deploy Nutshell TEE to Azure Confidential Containers
#
# Prerequisites:
# - Azure CLI installed and logged in
# - az confcom extension installed (az extension add --name confcom)
# - Docker Engine installed (NOT Podman - confcom requires real Docker for layer hashing)
# - All infrastructure created (Key Vault, Storage, MAA, Managed Identity)
# - Container image pushed to GHCR
# - Encryption key imported to Key Vault
# - Encrypted filesystem uploaded to Storage
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================================
# Configuration - MODIFY THESE VALUES
# ============================================================================
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-nutshell-tee}"
LOCATION="${LOCATION:-northeurope}"
KEY_VAULT_NAME="${KEY_VAULT_NAME:-kv-nutshell-tee}"
STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-stnutshelltee}"
ATTESTATION_PROVIDER="${ATTESTATION_PROVIDER:-attestnutshelltee}"
MANAGED_IDENTITY_NAME="${MANAGED_IDENTITY_NAME:-id-nutshell-tee}"
CONTAINER_GROUP_NAME="${CONTAINER_GROUP_NAME:-nutshell-tee}"
NUTSHELL_IMAGE="${NUTSHELL_IMAGE:-ghcr.io/YOUR_GITHUB_USER/nutshell-tee:latest}"
CADDY_IMAGE="${CADDY_IMAGE:-caddy:2}"
ENCFS_IMAGE="${ENCFS_IMAGE:-mcr.microsoft.com/aci/encfs:2.12}"
PIN_IMAGE_DIGESTS="${PIN_IMAGE_DIGESTS:-true}"

# DNS and HTTPS settings
DNS_NAME_LABEL="${DNS_NAME_LABEL:-}"  # Azure DNS label (alternative to CUSTOM_DOMAIN)
CUSTOM_DOMAIN="${CUSTOM_DOMAIN:-}"    # Custom domain (e.g., tee.freedom.cash)
ACME_EMAIL="${ACME_EMAIL:-}"          # Email for Let's Encrypt notifications (recommended)
CADDY_DEBUG="${CADDY_DEBUG:-}"        # Set to 1 to keep Caddy in debug idle mode
CADDY_FILE_SHARE="${CADDY_FILE_SHARE:-caddy}"
STORAGE_ACCOUNT_KEY="${STORAGE_ACCOUNT_KEY:-}"
ENCFS_KEY_ID="${ENCFS_KEY_ID:-encfs-key}"
ENCFS_KEY_TYPE="${ENCFS_KEY_TYPE:-RSA-HSM}"
ENCFS_READ_WRITE="${ENCFS_READ_WRITE:-true}"
ENCFS_LOG_LEVEL="${ENCFS_LOG_LEVEL:-}"
ENCFS_BLOB_SAS="${ENCFS_BLOB_SAS:-}"

# Optional: Registry credentials (for private GHCR repos or Docker Hub rate limits)
IMAGE_REGISTRY_SERVER="${IMAGE_REGISTRY_SERVER:-}"
IMAGE_REGISTRY_USERNAME="${IMAGE_REGISTRY_USERNAME:-}"
IMAGE_REGISTRY_PASSWORD="${IMAGE_REGISTRY_PASSWORD:-}"
DOCKERHUB_USERNAME="${DOCKERHUB_USERNAME:-}"
DOCKERHUB_TOKEN="${DOCKERHUB_TOKEN:-}"

# Derived values (MAA_ENDPOINT is fetched dynamically since it uses short region codes)
KEY_VAULT_ENDPOINT="https://${KEY_VAULT_NAME}.vault.azure.net"
STORAGE_ENDPOINT="https://${STORAGE_ACCOUNT}.blob.core.windows.net"

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

check_prerequisites() {
    log "Checking prerequisites..."

    # Check Azure CLI
    if ! command -v az &> /dev/null; then
        error "Azure CLI not found. Install from https://docs.microsoft.com/cli/azure/install-azure-cli"
    fi

    # Check logged in
    if ! az account show &> /dev/null; then
        error "Not logged in to Azure. Run 'az login' first."
    fi

    # Check confcom extension
    if ! az extension show --name confcom &> /dev/null; then
        log "Installing confcom extension..."
        az extension add --name confcom
    fi

    # Check Docker is available (not Podman - confcom requires real Docker)
    if ! command -v docker &> /dev/null; then
        error "Docker not found. Install Docker Engine (not Podman) for CCE policy generation."
    fi

    # Verify it's real Docker, not Podman emulation
    if docker --version 2>&1 | grep -qi podman; then
        error "Podman detected. The az confcom extension requires real Docker Engine for proper layer hash computation."
    fi

    # Check Docker daemon is running
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running. Start it with 'sudo systemctl start docker'"
    fi

    # Check resource group exists
    if ! az group show --name "$RESOURCE_GROUP" &> /dev/null; then
        error "Resource group '$RESOURCE_GROUP' not found. Create it first."
    fi

    log "Prerequisites OK (using Docker Engine)"
}

resolve_digest() {
    local image="$1"
    if [[ "$image" == *@sha256:* ]]; then
        echo "$image"
        return 0
    fi
    local repo="${image%%:*}"
    local digest
    digest=$(docker image inspect "$image" --format '{{join .RepoDigests "\n"}}' 2>/dev/null | awk -v repo="$repo" '$0 ~ "^"repo"@sha256:" {print $0; exit}')
    if [ -z "$digest" ]; then
        digest=$(docker image inspect "$image" --format '{{index .RepoDigests 0}}' 2>/dev/null || true)
    fi
    if [ -z "$digest" ]; then
        echo "$image"
        return 1
    fi
    echo "$digest"
    return 0
}

generate_salt() {
    # encfs key derivation expects hex-encoded salt
    openssl rand -hex 32
}

# ============================================================================
# Main Deployment
# ============================================================================

main() {
    log "=== Nutshell TEE Deployment ==="
    log "Resource Group: $RESOURCE_GROUP"
    log "Location: $LOCATION"
    log "Container Image: $NUTSHELL_IMAGE"
    log "Caddy Image: $CADDY_IMAGE"
    log "EncFS Image: $ENCFS_IMAGE"
    log "Pin Image Digests: $PIN_IMAGE_DIGESTS"
    log "Caddy File Share: $CADDY_FILE_SHARE"
    if [ -n "$CUSTOM_DOMAIN" ]; then
        log "Domain: $CUSTOM_DOMAIN"
    elif [ -n "$DNS_NAME_LABEL" ]; then
        log "Domain: ${DNS_NAME_LABEL}.${LOCATION}.azurecontainer.io"
    fi
    log ""

    if [ -z "$CUSTOM_DOMAIN" ] && [ -z "$DNS_NAME_LABEL" ]; then
        error "HTTPS requires CUSTOM_DOMAIN or DNS_NAME_LABEL to be set."
    fi

    if [ -z "$ACME_EMAIL" ]; then
        log "ACME_EMAIL not set; Caddy will use its default ACME account settings."
    fi

    check_prerequisites

    # Get managed identity resource ID
    log "Getting managed identity resource ID..."
    IDENTITY_ID=$(az identity show \
        --name "$MANAGED_IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query id -o tsv)

    if [ -z "$IDENTITY_ID" ]; then
        error "Managed identity '$MANAGED_IDENTITY_NAME' not found"
    fi
    log "Identity ID: $IDENTITY_ID"

    # Get MAA endpoint (uses short region codes like 'neu' not 'northeurope')
    log "Getting MAA endpoint..."
    MAA_ENDPOINT=$(az attestation show \
        --name "$ATTESTATION_PROVIDER" \
        --resource-group "$RESOURCE_GROUP" \
        --query attestUri -o tsv)

    if [ -z "$MAA_ENDPOINT" ]; then
        error "Attestation provider '$ATTESTATION_PROVIDER' not found"
    fi
    log "MAA endpoint: $MAA_ENDPOINT"

    # Storage account key (for Azure Files Caddy persistence)
    if [ -z "$STORAGE_ACCOUNT_KEY" ]; then
        log "Getting storage account key..."
        STORAGE_ACCOUNT_KEY=$(az storage account keys list \
            --resource-group "$RESOURCE_GROUP" \
            --account-name "$STORAGE_ACCOUNT" \
            --query '[0].value' -o tsv)
    fi

    if [ -z "$STORAGE_ACCOUNT_KEY" ]; then
        error "Failed to get storage account key for $STORAGE_ACCOUNT"
    fi

    # Ensure Caddy file share exists
    log "Ensuring Azure Files share '${CADDY_FILE_SHARE}' exists..."
    az storage share create \
        --account-name "$STORAGE_ACCOUNT" \
        --account-key "$STORAGE_ACCOUNT_KEY" \
        --name "$CADDY_FILE_SHARE" \
        --output none 2>/dev/null || log "File share '${CADDY_FILE_SHARE}' already exists"

    # Determine salt: prefer provided ENCFS_SALT, then encfs-salt.txt, else generate
    if [ -z "$ENCFS_SALT" ]; then
        if [ -f "$SCRIPT_DIR/encfs-salt.txt" ]; then
            ENCFS_SALT=$(tr -d '\r\n ' < "$SCRIPT_DIR/encfs-salt.txt")
            if [ -n "$ENCFS_SALT" ]; then
                log "Using ENCFS_SALT from $SCRIPT_DIR/encfs-salt.txt"
            fi
        fi
    fi

    if [ -z "$ENCFS_SALT" ]; then
        log "Generating encryption salt..."
        ENCFS_SALT=$(generate_salt)
        log "Salt: $ENCFS_SALT"
        log "Saving salt to $SCRIPT_DIR/encfs-salt.txt"
        echo "$ENCFS_SALT" > "$SCRIPT_DIR/encfs-salt.txt"
        log "IMPORTANT: Save this salt! You'll need it to recreate the encrypted filesystem."
    fi

    # Create sidecar configuration files
    log "Creating sidecar configurations..."

    # EncFS sidecar args
    if [ -n "$ENCFS_BLOB_SAS" ]; then
        ENCFS_BLOB_URL="${STORAGE_ENDPOINT}/encfs/encfs.img?${ENCFS_BLOB_SAS#\?}"
        ENCFS_BLOB_PRIVATE=false
    else
        ENCFS_BLOB_URL="${STORAGE_ENDPOINT}/encfs/encfs.img"
        ENCFS_BLOB_PRIVATE=true
    fi

    if [ "$ENCFS_KEY_TYPE" = "RSA-HSM" ]; then
        cat > /tmp/encfs-sidecar-args.json <<EOF
{
  "azure_filesystems": [
    {
      "mount_point": "/mnt/remote/mint",
      "azure_url": "${ENCFS_BLOB_URL}",
      "azure_url_private": ${ENCFS_BLOB_PRIVATE},
      "read_write": ${ENCFS_READ_WRITE},
      "key": {
        "kid": "${ENCFS_KEY_ID}",
        "kty": "${ENCFS_KEY_TYPE}",
        "authority": {
          "endpoint": "${MAA_ENDPOINT#https://}"
        },
        "akv": {
          "endpoint": "${KEY_VAULT_ENDPOINT#https://}"
        }
      },
      "key_derivation": {
        "salt": "${ENCFS_SALT}",
        "label": "encfs"
      }
    }
  ]
}
EOF
    else
        cat > /tmp/encfs-sidecar-args.json <<EOF
{
  "azure_filesystems": [
    {
      "mount_point": "/mnt/remote/mint",
      "azure_url": "${ENCFS_BLOB_URL}",
      "azure_url_private": ${ENCFS_BLOB_PRIVATE},
      "read_write": ${ENCFS_READ_WRITE},
      "key": {
        "kid": "${ENCFS_KEY_ID}",
        "kty": "${ENCFS_KEY_TYPE}",
        "authority": {
          "endpoint": "${MAA_ENDPOINT#https://}"
        },
        "akv": {
          "endpoint": "${KEY_VAULT_ENDPOINT#https://}"
        }
      }
    }
  ]
}
EOF
    fi

    # SKR sidecar args
    cat > /tmp/skr-sidecar-args.json <<EOF
{
  "certcache": {
    "endpoint": "${MAA_ENDPOINT}"
  },
  "akv_endpoint": "${KEY_VAULT_ENDPOINT}"
}
EOF

    # Base64 encode sidecar configurations
    log "Encoding sidecar configurations..."
    ENCFS_ARGS=$(base64 -w 0 /tmp/encfs-sidecar-args.json)
    SKR_ARGS=$(base64 -w 0 /tmp/skr-sidecar-args.json)

    # Generate CCE policy
    log "Generating CCE policy..."
    log "This will pull container images and compute their digests..."

    # Copy ARM template to temp location for policy generation
    cp "$SCRIPT_DIR/arm-template.json" /tmp/arm-template-deploy.json

    # Replace parameter references with actual image names (confcom can't resolve ARM parameters)
    sed -i "s|\[parameters('nutshellImage')\]|${NUTSHELL_IMAGE}|g" /tmp/arm-template-deploy.json
    sed -i "s|\[parameters('caddyImage')\]|${CADDY_IMAGE}|g" /tmp/arm-template-deploy.json
    sed -i "s|\[parameters('encfsImage')\]|${ENCFS_IMAGE}|g" /tmp/arm-template-deploy.json

    # Remove local cached images and pull fresh to ensure policy matches remote images
    log "Removing cached images and pulling fresh (linux/amd64)..."
    docker rmi mcr.microsoft.com/aci/skr:2.8 2>/dev/null || true
    docker rmi "$ENCFS_IMAGE" 2>/dev/null || true
    docker rmi "$CADDY_IMAGE" 2>/dev/null || true
    docker rmi "$NUTSHELL_IMAGE" 2>/dev/null || true

    # Pull with explicit platform to match Azure's architecture
    docker pull --platform linux/amd64 mcr.microsoft.com/aci/skr:2.8
    docker pull --platform linux/amd64 "$ENCFS_IMAGE"
    docker pull --platform linux/amd64 "$CADDY_IMAGE"
    docker pull --platform linux/amd64 "$NUTSHELL_IMAGE"

    if [ "$PIN_IMAGE_DIGESTS" = "true" ]; then
        log "Pinning image digests..."
        local encfs_digest caddy_digest nutshell_digest
        encfs_digest=$(resolve_digest "$ENCFS_IMAGE" || true)
        caddy_digest=$(resolve_digest "$CADDY_IMAGE" || true)
        nutshell_digest=$(resolve_digest "$NUTSHELL_IMAGE" || true)
        if [[ "$encfs_digest" == *@sha256:* ]]; then
            ENCFS_IMAGE="$encfs_digest"
        else
            log "Warning: could not resolve digest for ENCFS_IMAGE"
        fi
        if [[ "$caddy_digest" == *@sha256:* ]]; then
            CADDY_IMAGE="$caddy_digest"
        else
            log "Warning: could not resolve digest for CADDY_IMAGE"
        fi
        if [[ "$nutshell_digest" == *@sha256:* ]]; then
            NUTSHELL_IMAGE="$nutshell_digest"
        else
            log "Warning: could not resolve digest for NUTSHELL_IMAGE"
        fi
        log "Pinned NUTSHELL_IMAGE: $NUTSHELL_IMAGE"
        log "Pinned CADDY_IMAGE: $CADDY_IMAGE"
        log "Pinned ENCFS_IMAGE: $ENCFS_IMAGE"
    fi

    # Generate policy (this modifies the template in place)
    log "Running az confcom acipolicygen..."
    CONF_OUT=$(az confcom acipolicygen \
        -a /tmp/arm-template-deploy.json \
        --debug-mode \
        --approve-wildcards 2>&1 | tee /tmp/confcom.out)

    HOSTDATA_HASH=$(echo "$CONF_OUT" | grep -Eo '^[0-9a-f]{64}$' | tail -n1)
    if [ -n "$HOSTDATA_HASH" ]; then
        log "Hostdata hash: $HOSTDATA_HASH"
        echo "$HOSTDATA_HASH" > /tmp/encfs-hostdata.txt
        echo "$HOSTDATA_HASH" > "$SCRIPT_DIR/expected-hostdata.txt"

        # Update Key Vault release policy BEFORE deployment so encfs-sidecar can release key
        log "Updating Key Vault release policy..."
        cat > /tmp/encfs-release-policy.json <<EOF
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "${MAA_ENDPOINT}",
      "allOf": [
        { "claim": "x-ms-sevsnpvm-hostdata", "equals": "${HOSTDATA_HASH}" }
      ]
    }
  ]
}
EOF
        if az keyvault key set-attributes \
            --vault-name "$KEY_VAULT_NAME" \
            --name "$ENCFS_KEY_ID" \
            --policy @/tmp/encfs-release-policy.json > /dev/null 2>&1; then
            log "Key Vault release policy updated"
        else
            log "WARNING: Failed to update Key Vault release policy"
            log "You may need to manually run:"
            log "  az keyvault key set-attributes --vault-name $KEY_VAULT_NAME --name $ENCFS_KEY_ID --policy @/tmp/encfs-release-policy.json"
        fi
        rm -f /tmp/encfs-release-policy.json
    else
        log "WARNING: No hostdata hash extracted - Key Vault release policy not updated"
    fi

    # Verify policy was generated (check ccePolicy is not empty)
    POLICY_CHECK=$(jq -r '.resources[0].properties.confidentialComputeProperties.ccePolicy // empty' /tmp/arm-template-deploy.json)
    if [ -z "$POLICY_CHECK" ]; then
        error "CCE policy generation failed - policy is empty"
    fi

    # Verify policy doesn't contain parsing errors
    if echo "$POLICY_CHECK" | base64 -d 2>/dev/null | grep -q "not able to parse"; then
        error "CCE policy contains parsing errors. Ensure Docker (not Podman) is being used."
    fi

    log "CCE policy generated and verified"

    # Build deployment parameters
    DEPLOY_PARAMS=(
        containerGroupName="$CONTAINER_GROUP_NAME"
        location="$LOCATION"
        nutshellImage="$NUTSHELL_IMAGE"
        caddyImage="$CADDY_IMAGE"
        encfsImage="$ENCFS_IMAGE"
        storageAccountName="$STORAGE_ACCOUNT"
        storageAccountKey="$STORAGE_ACCOUNT_KEY"
        caddyFileShareName="$CADDY_FILE_SHARE"
        managedIdentityId="$IDENTITY_ID"
        encfsSidecarArgs="$ENCFS_ARGS"
        skrSidecarArgs="$SKR_ARGS"
        maaEndpoint="$MAA_ENDPOINT"
        dnsNameLabel="$DNS_NAME_LABEL"
        customDomain="$CUSTOM_DOMAIN"
        acmeEmail="$ACME_EMAIL"
        caddyDebug="$CADDY_DEBUG"
        encfsLogLevel="$ENCFS_LOG_LEVEL"
    )

    # Default Docker Hub credentials if provided and no registry override set
    if [ -z "$IMAGE_REGISTRY_SERVER" ] && [ -n "$DOCKERHUB_USERNAME" ] && [ -n "$DOCKERHUB_TOKEN" ]; then
        IMAGE_REGISTRY_SERVER="index.docker.io"
        IMAGE_REGISTRY_USERNAME="$DOCKERHUB_USERNAME"
        IMAGE_REGISTRY_PASSWORD="$DOCKERHUB_TOKEN"
    fi

    # Add registry credentials if provided
    if [ -n "$IMAGE_REGISTRY_SERVER" ]; then
        log "Using private registry: $IMAGE_REGISTRY_SERVER"
        DEPLOY_PARAMS+=(
            imageRegistryServer="$IMAGE_REGISTRY_SERVER"
            imageRegistryUsername="$IMAGE_REGISTRY_USERNAME"
            imageRegistryPassword="$IMAGE_REGISTRY_PASSWORD"
        )
    fi

    # Deploy ARM template
    log "Deploying to Azure..."
    DEPLOYMENT_OUTPUT=$(az deployment group create \
        --resource-group "$RESOURCE_GROUP" \
        --template-file /tmp/arm-template-deploy.json \
        --parameters "${DEPLOY_PARAMS[@]}" \
        --query properties.outputs -o json)

    # Get FQDN and IP
    PUBLIC_IP=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.containerIPv4Address.value // empty')

    if [ -z "$PUBLIC_IP" ]; then
        log "Getting container IP..."
        PUBLIC_IP=$(az container show \
            --resource-group "$RESOURCE_GROUP" \
            --name "$CONTAINER_GROUP_NAME" \
            --query ipAddress.ip -o tsv)
    fi

    # Determine the domain to use
    if [ -n "$CUSTOM_DOMAIN" ]; then
        MINT_DOMAIN="$CUSTOM_DOMAIN"
    elif [ -n "$DNS_NAME_LABEL" ]; then
        MINT_DOMAIN="${DNS_NAME_LABEL}.${LOCATION}.azurecontainer.io"
    else
        MINT_DOMAIN="$PUBLIC_IP"
    fi

    # Cleanup temp files
    rm -f /tmp/encfs-sidecar-args.json /tmp/skr-sidecar-args.json /tmp/arm-template-deploy.json

    log ""
    log "=== Deployment Complete ==="
    log ""
    log "Nutshell Mint URL: https://${MINT_DOMAIN}"
    log "IP Address: ${PUBLIC_IP}"
    log ""
    log "Test endpoints:"
    log "  curl https://${MINT_DOMAIN}/v1/info"
    log "  curl https://${MINT_DOMAIN}/v1/attestation/info"
    log "  curl https://${MINT_DOMAIN}/v1/attestation"
    log "  (If HTTPS isn't ready yet, wait a minute and check Caddy logs)"
    log ""
    log "View logs:"
    log "  az container logs --resource-group $RESOURCE_GROUP --name $CONTAINER_GROUP_NAME --container-name nutshell-mint"
    log "  az container logs --resource-group $RESOURCE_GROUP --name $CONTAINER_GROUP_NAME --container-name skr-sidecar"
    log "  az container logs --resource-group $RESOURCE_GROUP --name $CONTAINER_GROUP_NAME --container-name encfs-sidecar"
    log "  az container logs --resource-group $RESOURCE_GROUP --name $CONTAINER_GROUP_NAME --container-name caddy"
    log ""
}

# ============================================================================
# Additional Commands
# ============================================================================

show_status() {
    az container show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$CONTAINER_GROUP_NAME" \
        --query '{state:instanceView.state, ip:ipAddress.ip, events:instanceView.events[-3:]}' \
        -o json
}

show_logs() {
    local container="${1:-nutshell-mint}"
    az container logs \
        --resource-group "$RESOURCE_GROUP" \
        --name "$CONTAINER_GROUP_NAME" \
        --container-name "$container"
}

restart() {
    az container restart \
        --resource-group "$RESOURCE_GROUP" \
        --name "$CONTAINER_GROUP_NAME"
}

delete() {
    read -p "Delete container group '$CONTAINER_GROUP_NAME'? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        az container delete \
            --resource-group "$RESOURCE_GROUP" \
            --name "$CONTAINER_GROUP_NAME" \
            --yes
        log "Container group deleted"
    fi
}

generate_policy_only() {
    log "=== Generate CCE Policy Only ==="
    log "Container Image: $NUTSHELL_IMAGE"

    check_prerequisites

    # Copy ARM template
    cp "$SCRIPT_DIR/arm-template.json" /tmp/arm-template-policy.json
    sed -i "s|\[parameters('nutshellImage')\]|${NUTSHELL_IMAGE}|g" /tmp/arm-template-policy.json
    sed -i "s|\[parameters('caddyImage')\]|${CADDY_IMAGE}|g" /tmp/arm-template-policy.json
    sed -i "s|\[parameters('encfsImage')\]|${ENCFS_IMAGE}|g" /tmp/arm-template-policy.json

    # Pull images
    log "Pulling images (linux/amd64)..."
    docker pull --platform linux/amd64 mcr.microsoft.com/aci/skr:2.8
    docker pull --platform linux/amd64 "$ENCFS_IMAGE"
    docker pull --platform linux/amd64 "$CADDY_IMAGE"
    docker pull --platform linux/amd64 "$NUTSHELL_IMAGE"

    # Generate policy
    log "Generating CCE policy..."
    az confcom acipolicygen \
        -a /tmp/arm-template-policy.json \
        --debug-mode

    # Extract and decode policy for inspection
    POLICY_B64=$(jq -r '.resources[0].properties.confidentialComputeProperties.ccePolicy' /tmp/arm-template-policy.json)

    log ""
    log "=== Policy Generated ==="
    log "ARM template with policy: /tmp/arm-template-policy.json"
    log ""
    log "Decoding policy to /tmp/cce-policy-decoded.rego..."
    echo "$POLICY_B64" | base64 -d > /tmp/cce-policy-decoded.rego

    # Show container layer info
    log ""
    log "Container layers in policy:"
    echo "$POLICY_B64" | base64 -d | grep -o '"layers":\[[^]]*\]' | head -3

    # Check for errors
    if echo "$POLICY_B64" | base64 -d | grep -q "not able to parse"; then
        log ""
        log "WARNING: Policy contains parsing errors!"
    else
        log ""
        log "Policy looks valid (no parsing errors detected)"
    fi
}

# ============================================================================
# CLI
# ============================================================================

case "${1:-deploy}" in
    deploy)
        main
        ;;
    policy)
        generate_policy_only
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "${2:-nutshell-mint}"
        ;;
    restart)
        restart
        ;;
    delete)
        delete
        ;;
    *)
        echo "Usage: $0 {deploy|policy|status|logs [container]|restart|delete}"
        echo ""
        echo "Commands:"
        echo "  deploy   Deploy or update the container group (default)"
        echo "  policy   Generate CCE policy only (for debugging)"
        echo "  status   Show container group status"
        echo "  logs     Show container logs (default: nutshell-mint)"
        echo "  restart  Restart the container group"
        echo "  delete   Delete the container group"
        exit 1
        ;;
esac
