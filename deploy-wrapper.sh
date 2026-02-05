#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AZURE_DIR="${SCRIPT_DIR}/azure"
DEPLOY_SCRIPT="${AZURE_DIR}/deploy.sh"

RESOURCE_GROUP="${RESOURCE_GROUP:-rg-nutshell-tee}"
CONTAINER_GROUP_NAME="${CONTAINER_GROUP_NAME:-nutshell-tee}"
CUSTOM_DOMAIN="${CUSTOM_DOMAIN:-}"
DNS_NAME_LABEL="${DNS_NAME_LABEL:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
NUTSHELL_IMAGE="${NUTSHELL_IMAGE:-}"
CADDY_IMAGE="${CADDY_IMAGE:-}"
ENCFS_IMAGE="${ENCFS_IMAGE:-}"

POLICY_DIR_DEFAULT="${AZURE_DIR}/policies"
POLICY_PREFIX_DEFAULT="cce-policy"

usage() {
    cat <<EOF
Usage: $0 [deploy|export-policy] [options]

Commands:
  deploy           Deploy/update the container group, then export CCE policy (default)
  export-policy    Export current CCE policy from Azure without deploying

Options:
  --pin            Force PIN_IMAGE_DIGESTS=true for deploy
  --no-pin         Force PIN_IMAGE_DIGESTS=false for deploy
  --policy-dir DIR Output directory for exported policies (default: ${POLICY_DIR_DEFAULT})
  --policy-prefix  Filename prefix (default: ${POLICY_PREFIX_DEFAULT})
  --domain FQDN     Set CUSTOM_DOMAIN for HTTPS (e.g., nuttee.freedom.cash)
  --dns-label NAME  Set DNS_NAME_LABEL (alternative to CUSTOM_DOMAIN)
  --acme-email EMAIL  Set ACME_EMAIL for Let's Encrypt
  --nutshell-image IMG  Set NUTSHELL_IMAGE
  --caddy-image IMG     Set CADDY_IMAGE
  --encfs-image IMG     Set ENCFS_IMAGE
  --resource-group RG   Set RESOURCE_GROUP
  --container-group CG  Set CONTAINER_GROUP_NAME
  -h, --help       Show this help

Notes:
  - Uses RESOURCE_GROUP and CONTAINER_GROUP_NAME from env (defaults above).
  - Exports both base64 policy and decoded .rego.
EOF
}

export_policy() {
    local out_dir="$1"
    local prefix="$2"
    local ts
    ts="$(date -u +"%Y%m%d-%H%M%SZ")"

    mkdir -p "$out_dir"

    local b64_file="${out_dir}/${prefix}-${ts}.rego.b64"
    local rego_file="${out_dir}/${prefix}-${ts}.rego"

    az container show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$CONTAINER_GROUP_NAME" \
        --query "confidentialComputeProperties.ccePolicy" -o tsv > "$b64_file"

    if [ ! -s "$b64_file" ]; then
        echo "ERROR: Failed to read ccePolicy from ${CONTAINER_GROUP_NAME} in ${RESOURCE_GROUP}" >&2
        exit 1
    fi

    base64 -d "$b64_file" > "$rego_file"

    cp "$b64_file" "${out_dir}/${prefix}-latest.rego.b64"
    cp "$rego_file" "${out_dir}/${prefix}-latest.rego"

    # Also copy the expected hostdata if it exists
    local hostdata_file="${AZURE_DIR}/expected-hostdata.txt"
    if [ -f "$hostdata_file" ]; then
        cp "$hostdata_file" "${out_dir}/${prefix}-${ts}.hostdata"
        cp "$hostdata_file" "${out_dir}/${prefix}-latest.hostdata"
    fi

    echo "Exported CCE policy:"
    echo "  $b64_file"
    echo "  $rego_file"
    if [ -f "$hostdata_file" ]; then
        echo "  ${out_dir}/${prefix}-${ts}.hostdata"
    fi
}

cmd="${1:-deploy}"
shift || true

PIN_FLAG=""
POLICY_DIR="$POLICY_DIR_DEFAULT"
POLICY_PREFIX="$POLICY_PREFIX_DEFAULT"

while [ $# -gt 0 ]; do
    case "$1" in
        --pin)
            PIN_FLAG="true"
            ;;
        --no-pin)
            PIN_FLAG="false"
            ;;
        --policy-dir)
            POLICY_DIR="$2"
            shift
            ;;
        --policy-prefix)
            POLICY_PREFIX="$2"
            shift
            ;;
        --domain)
            CUSTOM_DOMAIN="$2"
            shift
            ;;
        --dns-label)
            DNS_NAME_LABEL="$2"
            shift
            ;;
        --acme-email)
            ACME_EMAIL="$2"
            shift
            ;;
        --nutshell-image)
            NUTSHELL_IMAGE="$2"
            shift
            ;;
        --caddy-image)
            CADDY_IMAGE="$2"
            shift
            ;;
        --encfs-image)
            ENCFS_IMAGE="$2"
            shift
            ;;
        --resource-group)
            RESOURCE_GROUP="$2"
            shift
            ;;
        --container-group)
            CONTAINER_GROUP_NAME="$2"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
    shift
done

case "$cmd" in
    deploy)
        env_args=()
        [ -n "$CUSTOM_DOMAIN" ] && env_args+=("CUSTOM_DOMAIN=$CUSTOM_DOMAIN")
        [ -n "$DNS_NAME_LABEL" ] && env_args+=("DNS_NAME_LABEL=$DNS_NAME_LABEL")
        [ -n "$ACME_EMAIL" ] && env_args+=("ACME_EMAIL=$ACME_EMAIL")
        [ -n "$NUTSHELL_IMAGE" ] && env_args+=("NUTSHELL_IMAGE=$NUTSHELL_IMAGE")
        [ -n "$CADDY_IMAGE" ] && env_args+=("CADDY_IMAGE=$CADDY_IMAGE")
        [ -n "$ENCFS_IMAGE" ] && env_args+=("ENCFS_IMAGE=$ENCFS_IMAGE")
        env_args+=("RESOURCE_GROUP=$RESOURCE_GROUP")
        env_args+=("CONTAINER_GROUP_NAME=$CONTAINER_GROUP_NAME")

        if [ -n "$PIN_FLAG" ]; then
            env_args+=("PIN_IMAGE_DIGESTS=$PIN_FLAG")
        fi

        env "${env_args[@]}" "$DEPLOY_SCRIPT" deploy
        export_policy "$POLICY_DIR" "$POLICY_PREFIX"
        ;;
    export-policy)
        export_policy "$POLICY_DIR" "$POLICY_PREFIX"
        ;;
    *)
        usage
        exit 1
        ;;
esac
