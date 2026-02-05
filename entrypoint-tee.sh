#!/bin/bash
set -e

echo "=== Nutshell TEE Entrypoint ==="

echo "Waiting for SKR sidecar to be ready..."

# Wait for SKR sidecar (max 60 seconds) - SKR listens on 8080
for i in {1..60}; do
    if curl -s http://localhost:8080/status > /dev/null 2>&1; then
        echo "SKR sidecar is ready"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "Warning: SKR sidecar not available after 60 seconds"
    fi
    sleep 1
done

# Wait for encrypted filesystem to be mounted (shared emptyDir)
ENCFS_MOUNT_PATH="${ENCFS_MOUNT_PATH:-/app/data/mint}"
ENCFS_WAIT_SECONDS="${ENCFS_WAIT_SECONDS:-180}"
ENCFS_REQUIRE_MOUNT="${ENCFS_REQUIRE_MOUNT:-true}"
ENCFS_WRITE_TEST="${ENCFS_WRITE_TEST:-true}"
ENCFS_REQUIRE_SENTINEL="${ENCFS_REQUIRE_SENTINEL:-true}"
ENCFS_REQUIRE_FUSE="${ENCFS_REQUIRE_FUSE:-false}"

is_encfs_ready() {
    if [ "$ENCFS_REQUIRE_SENTINEL" = "true" ]; then
        [ -f "$ENCFS_MOUNT_PATH/.persist-sentinel" ] || return 1
    fi
    if [ "$ENCFS_REQUIRE_FUSE" = "true" ]; then
        fs_type="$(stat -f -c %T "$ENCFS_MOUNT_PATH" 2>/dev/null || true)"
        case "$fs_type" in
            fuse*|fuse) ;;
            *) return 1 ;;
        esac
    fi
    if [ "$ENCFS_REQUIRE_SENTINEL" = "true" ]; then
        return 0
    fi
    mountpoint -q "$ENCFS_MOUNT_PATH" 2>/dev/null && return 0
    [ -f "$ENCFS_MOUNT_PATH/.persist-sentinel" ] && return 0
    return 1
}

echo "Waiting for encrypted filesystem at $ENCFS_MOUNT_PATH..."
for i in $(seq 1 "$ENCFS_WAIT_SECONDS"); do
    if is_encfs_ready; then
        echo "Encrypted filesystem is mounted"
        break
    fi
    if [ "$i" -eq "$ENCFS_WAIT_SECONDS" ]; then
        if [ "$ENCFS_REQUIRE_MOUNT" = "true" ]; then
            echo "ERROR: Encrypted filesystem not mounted after ${ENCFS_WAIT_SECONDS}s"
            exit 1
        fi
        echo "Warning: Encrypted filesystem not mounted after ${ENCFS_WAIT_SECONDS}s"
        echo "Continuing with local storage..."
    fi
    sleep 1
done

if [ "$ENCFS_WRITE_TEST" = "true" ] && is_encfs_ready; then
    TEST_FILE="$ENCFS_MOUNT_PATH/.encfs-write-test.$(date +%s)"
    echo "encfs write test $(date -u)" > "$TEST_FILE"
    sync
    rm -f "$TEST_FILE"
    sync
    echo "Encrypted filesystem write test succeeded"
fi

# Fetch secrets from Azure Key Vault using managed identity
echo "Fetching secrets from Azure Key Vault..."

# Get access token using managed identity
get_kv_token() {
    curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' \
        -H 'Metadata: true' | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4
}

fetch_secret() {
    local secret_name=$1
    local env_var=$2
    local kv_name="${KEY_VAULT_NAME:-kv-nutshell-tee}"
    local token=$(get_kv_token)

    if [ -z "$token" ]; then
        echo "Warning: Failed to get Key Vault token"
        return
    fi

    local result=$(curl -s "https://${kv_name}.vault.azure.net/secrets/${secret_name}?api-version=7.4" \
        -H "Authorization: Bearer ${token}" | grep -o '"value":"[^"]*"' | cut -d'"' -f4)

    if [ -n "$result" ]; then
        export "$env_var"="$result"
        echo "Successfully fetched $env_var"
    else
        echo "Warning: Failed to fetch $secret_name"
    fi
}

fetch_secret "MINT-PRIVATE-KEY" "MINT_PRIVATE_KEY"
fetch_secret "MINT-SPARK-API-KEY" "MINT_SPARK_API_KEY"
fetch_secret "MINT-SPARK-MNEMONIC" "MINT_SPARK_MNEMONIC"

# Set fixed environment variables (can be overridden by container env)
export MINT_DATABASE="${MINT_DATABASE:-/app/data/mint}"
export MINT_BACKEND_BOLT11_SAT="${MINT_BACKEND_BOLT11_SAT:-SparkWallet}"
export MINT_LISTEN_HOST="${MINT_LISTEN_HOST:-0.0.0.0}"
export MINT_LISTEN_PORT="${MINT_LISTEN_PORT:-3338}"
export MAA_ENDPOINT="${MAA_ENDPOINT:-}"

echo "Configuration:"
echo "  MINT_DATABASE: $MINT_DATABASE"
echo "  MINT_BACKEND_BOLT11_SAT: $MINT_BACKEND_BOLT11_SAT"
echo "  MINT_LISTEN_HOST: $MINT_LISTEN_HOST"
echo "  MINT_LISTEN_PORT: $MINT_LISTEN_PORT"
echo "  MAA_ENDPOINT: ${MAA_ENDPOINT:-<not configured>}"
echo "  MINT_PRIVATE_KEY: ${MINT_PRIVATE_KEY:+<set>}"
echo "  MINT_SPARK_API_KEY: ${MINT_SPARK_API_KEY:+<set>}"

echo "Starting Nutshell mint..."
exec "$@"
