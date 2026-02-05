#!/bin/bash
#
# Create an encrypted filesystem image for Azure Confidential Containers
#
# Prerequisites:
# - cryptsetup installed
# - Root/sudo access (for loop devices)
# - keyfile.bin generated from importkey tool
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
SIZE_MB="${SIZE_MB:-1024}"
IMAGE_FILE="${IMAGE_FILE:-encfs.img}"
KEYFILE="${KEYFILE:-keyfile.bin}"

echo "=== Creating Encrypted Filesystem ==="
echo "Size: ${SIZE_MB}MB"
echo "Output: ${IMAGE_FILE}"
echo "Keyfile: ${KEYFILE}"

# Check for keyfile
if [ ! -f "$KEYFILE" ]; then
    echo "Error: Keyfile not found: $KEYFILE"
    echo ""
    echo "Generate a keyfile with:"
    echo "  openssl rand -out keyfile.bin 32"
    echo ""
    echo "Then import it to Key Vault using the importkey tool from:"
    echo "  https://github.com/Azure/confidential-sidecar-containers"
    exit 1
fi

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges for loop device operations."
    echo "Please run with sudo."
    exit 1
fi

# Create sparse file
echo ""
echo "Creating sparse file..."
dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=0 seek="$SIZE_MB" status=progress

# Set up loop device
echo ""
echo "Setting up loop device..."
LOOP_DEV=$(losetup --find --show "$IMAGE_FILE")
echo "Loop device: $LOOP_DEV"

cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -e /dev/mapper/encfs-temp ]; then
        cryptsetup close encfs-temp 2>/dev/null || true
    fi
    if [ -n "$LOOP_DEV" ]; then
        losetup -d "$LOOP_DEV" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Format with LUKS
echo ""
echo "Formatting with LUKS encryption..."
cryptsetup luksFormat --batch-mode --key-file "$KEYFILE" "$LOOP_DEV"

# Open encrypted volume
echo ""
echo "Opening encrypted volume..."
cryptsetup open "$LOOP_DEV" encfs-temp --key-file "$KEYFILE"

# Create ext4 filesystem
echo ""
echo "Creating ext4 filesystem..."
mkfs.ext4 -L nutshell-data /dev/mapper/encfs-temp

# Close volume
echo ""
echo "Closing encrypted volume..."
cryptsetup close encfs-temp

# Detach loop device (handled by trap)
echo ""
echo "=== Encrypted Filesystem Created Successfully ==="
echo ""
echo "File: $IMAGE_FILE"
echo "Size: $(du -h "$IMAGE_FILE" | cut -f1) (sparse, will grow to ${SIZE_MB}MB)"
echo ""
echo "Next steps:"
echo "1. Upload to Azure Blob Storage as a page blob:"
echo "   az storage blob upload \\"
echo "     --account-name <storage_account> \\"
echo "     --container-name encfs \\"
echo "     --file $IMAGE_FILE \\"
echo "     --name encfs.img \\"
echo "     --type page \\"
echo "     --auth-mode key"
echo ""
echo "2. Import the encryption key to Key Vault using the importkey tool"
echo "   (See README.md for detailed instructions)"
echo ""
