# Azure Confidential Containers Deployment

Deploy Cashu Nutshell mint server as a confidential container on Azure Container Instances (ACI) with:
- AMD SEV-SNP hardware-based Trusted Execution Environment (TEE)
- Encrypted filesystem sidecar (1GB) for persistent SQLite database
- Secure Key Release (SKR) sidecar for secret injection
- Public HTTPS on ports 80/443 (Caddy sidecar)
- Remote attestation endpoint for wallet verification

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Azure Container Instance (Confidential)                   │
│                             SKU: Confidential                                │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌─────────────┐│
│  │  SKR Sidecar   │  │  EncFS Sidecar │  │     Caddy      │  │  Nutshell   ││
│  │  :9000         │  │                │  │   :80/:443     │  │   Mint      ││
│  └────────────────┘  └────────────────┘  └────────────────┘  │   :3338     ││
│                                                               └─────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
            │                   │
            ▼                   ▼
   Azure Key Vault      Azure Blob Storage
   (secrets + keys)     (encrypted filesystem)
```

## Prerequisites

- Azure CLI installed and logged in (`az login`)
- `az confcom` extension (`az extension add -n confcom`)
- Docker for building images
- GitHub account for GHCR image hosting

## Quick Start

### 1. Set up Azure Infrastructure

```bash
cd azure
./setup-infrastructure.sh
```

This creates:
- Resource Group: `rg-nutshell-tee`
- Key Vault: `kv-nutshell-tee` (Premium SKU)
- Storage Account: `stnutshelltee`
- Attestation Provider: `attestnutshelltee`
- Managed Identity: `id-nutshell-tee`
- Azure Files share: `caddy` (for ACME persistence)

### 2. Generate and Import Encryption Key

```bash
# Generate key
openssl rand -out keyfile.bin 32

# Import to Key Vault using importkey tool
# See: https://github.com/Azure/confidential-sidecar-containers
```

### 3. Create Encrypted Filesystem

```bash
sudo ./create-encrypted-fs.sh

# Upload to Azure
az storage blob upload \
  --account-name stnutshelltee \
  --container-name encfs \
  --file encfs.img \
  --name encfs.img \
  --type page \
  --auth-mode login
```

### 4. Store Application Secrets

```bash
# Generate mint private key
az keyvault secret set \
  --vault-name kv-nutshell-tee \
  --name MINT-PRIVATE-KEY \
  --value "$(openssl rand -hex 32)"

# Store Spark credentials (get these from your Spark provider)
az keyvault secret set \
  --vault-name kv-nutshell-tee \
  --name MINT-SPARK-API-KEY \
  --value "<your-api-key>"

az keyvault secret set \
  --vault-name kv-nutshell-tee \
  --name MINT-SPARK-MNEMONIC \
  --value "<your-mnemonic>"
```

### 5. Build and Push Container Images

Push to GitHub to trigger the workflow, or build locally:

```bash
cd ..
docker build -f Dockerfile.tee -t ghcr.io/<user>/nutshell-tee:latest .
docker push ghcr.io/<user>/nutshell-tee:latest

# Build Caddy sidecar image (runs as root; Caddyfile baked in)
docker build -f Dockerfile.caddy \
  --build-arg CADDY_DOMAIN=tee.freedom.cash \
  --build-arg ACME_EMAIL=you@example.com \
  -t ghcr.io/<user>/nutshell-caddy:latest .
docker push ghcr.io/<user>/nutshell-caddy:latest

This follows the recommended production pattern of baking the Caddyfile into
the image instead of mounting it at runtime. For confidential containers, this
also avoids policy/env restrictions that can block runtime env injection.
```

### 6. Deploy to Azure

Make sure your DNS A record points to the container IP, then set a custom domain
and ACME email for HTTPS:

```bash
CUSTOM_DOMAIN=tee.freedom.cash \
ACME_EMAIL=you@example.com \
NUTSHELL_IMAGE=ghcr.io/<user>/nutshell-tee:latest \
CADDY_IMAGE=ghcr.io/<user>/nutshell-caddy:latest ./deploy.sh
```

For a one-time deep debug run, set:
```
CADDY_DEBUG=1
```
This keeps the Caddy container alive for `az container exec` and prints
diagnostics to the logs.

If you want an Azure-generated FQDN instead of a custom domain, set `DNS_NAME_LABEL`
and omit `CUSTOM_DOMAIN`.

The mint still listens on port 3338 internally, but only ports 80/443 are exposed
publicly via Caddy.

First HTTPS access can take a minute while Caddy completes the ACME challenge.

The Caddyfile must reference a **domain name** (not an IP) and must match the
public FQDN used for the container group. If you use a custom domain, the
Caddyfile should use that custom name and the ACI DNS label should match that
FQDN.

### HTTPS + Let's Encrypt Rate Limits (Important)

Caddy stores ACME account + cert data under `/tmp/caddy-data`. In ACI that
directory is **ephemeral**, so every redeploy starts from scratch and will try
to register a brand‑new ACME account and re‑issue a certificate. This quickly
hits Let's Encrypt rate limits and yields browser errors like:

```
SSL_ERROR_INTERNAL_ERROR_ALERT
```

If you are rate‑limited:
- **Wait** until the retry time shown in the Caddy logs.
- Or **switch to a new domain** (different identifier set) if you must test now.

To avoid this in the future:
- Avoid frequent redeploys once HTTPS is working.
- Persist `/tmp/caddy-data` on a durable volume (Azure Files is configured by
  default in this repo) so Caddy can reuse the same ACME account and certificate
  between deployments.

You can inspect the exact rate‑limit retry time in `az container logs ... caddy`.

### Encrypted Filesystem Persistence (Must‑Do Steps)

This deployment uses a **page blob** with a LUKS2 header. It will *not* work
with block blobs. After each redeploy, the hostdata hash changes, which means
Key Vault **must** be updated to release the key again.

**Required steps on every redeploy:**
1. Deploy (prints hostdata hash).
2. Update the Key Vault key release policy with that hostdata.
3. Restart the container group.

If you skip step 2, encfs will fail with `403 Forbidden` (key release denied).

The mint entrypoint **waits for a sentinel file** created by the encfs sidecar
in the mounted filesystem. If the sentinel is missing, the mint will **fail**
instead of silently using emptyDir (non‑persistent storage).

### Image Digest Pinning + Hostdata

`deploy.sh` pins image digests by default after pulling and prints the
hostdata hash used for the Key Vault release policy. It also writes that hash to:

```
/tmp/encfs-hostdata.txt
```

You can feed this into `verify_attestation.py` to confirm the running mint
matches the expected policy/images.

### Caddy Persistence (Azure Files)

The deployment mounts an Azure Files share at `/tmp/caddy-data` so ACME account
and certificates survive redeploys. `deploy.sh` will create the share if it
doesn't exist.

Override defaults with:
```bash
CADDY_FILE_SHARE=your-share-name \
STORAGE_ACCOUNT=yourstorage \
STORAGE_ACCOUNT_KEY=yourkey \
./deploy.sh
```

## Deployment Commands

```bash
./deploy.sh deploy   # Deploy or update container group
./deploy.sh status   # Show container status
./deploy.sh logs     # View nutshell-mint logs
./deploy.sh logs skr-sidecar    # View SKR logs
./deploy.sh logs encfs-sidecar  # View EncFS logs
./deploy.sh logs caddy          # View Caddy logs
./deploy.sh restart  # Restart container group
./deploy.sh delete   # Delete container group
```

### Wrapper (deploy + export policy)

From repo root:

```bash
./deploy-wrapper.sh --pin         # Deploy with digest pinning + export CCE policy
./deploy-wrapper.sh --no-pin      # Deploy without pinning + export CCE policy
./deploy-wrapper.sh export-policy # Export current policy only
```

Example with domain + images:

```bash
./deploy-wrapper.sh --pin \
  --domain nuttee.freedom.cash \
  --acme-email you@example.com \
  --nutshell-image ghcr.io/YOUR_USER/nutshell-tee:latest \
  --caddy-image ghcr.io/YOUR_USER/nutshell-caddy:latest
```

## Cleanup

To remove all deployed Azure infrastructure:

```bash
# Full cleanup with confirmation for each resource
./cleanup.sh

# Quick cleanup (just deletes resource group)
./cleanup.sh --quick
```

This removes:
- Container Group
- Key Vault (with soft-delete/purge handling)
- Storage Account
- Attestation Provider
- Managed Identity
- Resource Group

## Remote Attestation

Wallets can verify the mint is running in a genuine TEE:

```bash
# Get attestation info
curl https://<mint-domain>/v1/attestation/info

# Get MAA token (only works in TEE)
curl https://<mint-domain>/v1/attestation
```

The MAA token is a signed JWT that can be verified against Microsoft Azure Attestation.

## Files

| File | Description |
|------|-------------|
| `setup-infrastructure.sh` | Creates all Azure resources |
| `cleanup.sh` | Removes all Azure resources |
| `create-encrypted-fs.sh` | Creates encrypted filesystem image |
| `deploy.sh` | Deploys container group to Azure |
| `arm-template.json` | ARM template for container group |
| `encfs-sidecar-args.json` | Encrypted filesystem configuration (template) |
| `skr-sidecar-args.json` | SKR sidecar configuration (template) |
| `importkeyconfig.json` | Key import configuration for HSM |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `RESOURCE_GROUP` | Azure resource group name |
| `LOCATION` | Azure region (must support confidential containers) |
| `KEY_VAULT_NAME` | Key Vault name |
| `STORAGE_ACCOUNT` | Storage account name |
| `ATTESTATION_PROVIDER` | MAA provider name |
| `MANAGED_IDENTITY_NAME` | Managed identity name |
| `NUTSHELL_IMAGE` | Container image to deploy |
| `CADDY_IMAGE` | Caddy sidecar image (reverse proxy for HTTPS) |
| `ENCFS_IMAGE` | EncFS sidecar image (override for debug builds) |
| `CADDY_DEBUG` | Set to `1` to keep Caddy running in debug idle mode for exec access |
| `CADDY_FILE_SHARE` | Azure Files share name for Caddy ACME persistence (default: `caddy`) |
| `STORAGE_ACCOUNT_KEY` | Storage account key (optional; deploy.sh will fetch if unset) |
| `PIN_IMAGE_DIGESTS` | Pin image digests after pull (default: `true`) |
| `ENCFS_KEY_ID` | Key Vault key name for EncFS (default: `encfs-key`) |
| `ENCFS_KEY_TYPE` | Key type for EncFS (`RSA-HSM` or `oct-HSM`) |
| `ENCFS_READ_WRITE` | Mount EncFS image read/write (`true`) or read-only (`false`) |
| `ENCFS_LOG_LEVEL` | EncFS sidecar log level (`trace`, `debug`, `info`, `warning`, `error`, `fatal`, `panic`) |
| `ENCFS_BLOB_SAS` | Optional SAS token for the EncFS blob (sets `azure_url_private` to `false`) |
| `DOCKERHUB_USERNAME` | Docker Hub username (to avoid pull rate limits) |
| `DOCKERHUB_TOKEN` | Docker Hub personal access token |
| `IMAGE_REGISTRY_SERVER` | Registry server override (e.g., `ghcr.io`, `index.docker.io`) |
| `IMAGE_REGISTRY_USERNAME` | Registry username |
| `IMAGE_REGISTRY_PASSWORD` | Registry password/token |

## Supported Regions

Azure Confidential Containers are available in:
- North Europe
- West Europe
- East US
- West US

## Cost Considerations

- **Confidential ACI**: Higher cost than standard ACI due to TEE hardware
- **Key Vault Premium**: Required for HSM-backed keys
- **Azure Attestation**: Free tier available
- **Storage**: Minimal cost for 1GB blob
