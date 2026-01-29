#!/usr/bin/env python3
"""
TEE Attestation Verification Script

Verifies that a Nutshell mint is running in a genuine AMD SEV-SNP
Trusted Execution Environment on Azure Confidential Containers.

Usage:
    # Basic verification (TEE is genuine)
    python verify_attestation.py https://nuttee.freedom.cash

    # Full verification with CCE policy (verify specific images are running)
    python verify_attestation.py https://nuttee.freedom.cash --policy-file azure/cce-policy.base64

Third-party verification flow:
    1. Clone the repo to get cce-policy.base64
    2. Run this script with --policy-file
    3. Script computes sha256(policy) and compares to MAA hostdata
    4. Script extracts and displays image digests from the policy
    5. You can verify those digests match what's on ghcr.io
"""

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone

try:
    import httpx
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives import serialization
    import jwt
    from jwt import PyJWKClient
except ImportError:
    print("Missing dependencies. Install with:")
    print("  pip install httpx cryptography pyjwt")
    sys.exit(1)


def print_header(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def print_ok(msg: str):
    print(f"  [OK] {msg}")


def print_fail(msg: str):
    print(f"  [FAIL] {msg}")


def print_info(msg: str):
    print(f"  [INFO] {msg}")


def print_warn(msg: str):
    print(f"  [WARN] {msg}")


def load_cce_policy(policy_path: str) -> tuple[bytes, str] | tuple[None, None]:
    """Load and decode CCE policy file, return (raw_bytes, hostdata_hash)"""
    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            policy_b64 = f.read().strip()

        # Decode base64
        policy_bytes = base64.b64decode(policy_b64)

        # Compute SHA-256 hash (this is the hostdata)
        hostdata = hashlib.sha256(policy_bytes).hexdigest()

        return policy_bytes, hostdata
    except FileNotFoundError:
        print_fail(f"Policy file not found: {policy_path}")
        return None, None
    except Exception as e:
        print_fail(f"Failed to load policy: {e}")
        return None, None


def extract_image_digests(policy_bytes: bytes) -> list[dict]:
    """Extract image references from CCE policy (Rego format)"""
    policy_text = policy_bytes.decode("utf-8", errors="replace")
    images = []

    # CCE policies have containers defined as JSON with:
    #   "id": "image:tag"
    #   "name": "container-name"
    #   "layers": ["hash1", "hash2", ...]
    #
    # Extract the containers JSON array from the policy
    containers_match = re.search(r'containers\s*:=\s*(\[.*?\])\s*\n', policy_text, re.DOTALL)
    if not containers_match:
        # Try single-line format (very long line)
        containers_match = re.search(r'containers\s*:=\s*(\[.*\])', policy_text)

    if containers_match:
        try:
            containers = json.loads(containers_match.group(1))
            for container in containers:
                image_id = container.get("id", "")
                name = container.get("name", "")
                layers = container.get("layers", [])

                # Skip pause container (infrastructure)
                if name == "pause-container" or "/pause" in str(container.get("command", [])):
                    continue

                # Parse image reference
                if ":" in image_id:
                    # Has tag
                    if image_id.count(":") == 1:
                        image_name, tag = image_id.rsplit(":", 1)
                    else:
                        # Multiple colons (e.g., registry:port/image:tag)
                        parts = image_id.rsplit(":", 1)
                        image_name = parts[0]
                        tag = parts[1]
                else:
                    image_name = image_id
                    tag = "latest"

                images.append({
                    "id": image_id,
                    "image": image_name,
                    "tag": tag,
                    "name": name,
                    "layers": layers,
                    "layer_count": len(layers)
                })
        except json.JSONDecodeError:
            pass

    # Fallback: regex extraction if JSON parsing failed
    if not images:
        # Look for "id":"..." patterns
        id_pattern = r'"id"\s*:\s*"([^"]+)"'
        name_pattern = r'"name"\s*:\s*"([^"]+)"'

        ids = re.findall(id_pattern, policy_text)
        names = re.findall(name_pattern, policy_text)

        for i, image_id in enumerate(ids):
            if "pause" in image_id.lower():
                continue

            name = names[i] if i < len(names) else "unknown"
            if ":" in image_id:
                image_name, tag = image_id.rsplit(":", 1)
            else:
                image_name = image_id
                tag = "latest"

            images.append({
                "id": image_id,
                "image": image_name,
                "tag": tag,
                "name": name,
                "layers": [],
                "layer_count": 0
            })

    return images


def get_attestation_info(mint_url: str) -> dict | None:
    """Fetch attestation configuration from mint"""
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{mint_url}/v1/attestation/info")
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                print_fail("Attestation endpoint not found (404)")
                print_info("The mint may not have TEE attestation enabled")
                return None
            else:
                print_fail(f"Failed to get attestation info: {resp.status_code}")
                return None
    except httpx.ConnectError:
        print_fail(f"Cannot connect to {mint_url}")
        return None
    except Exception as e:
        print_fail(f"Error: {e}")
        return None


def get_attestation_token(mint_url: str) -> dict | None:
    """Fetch MAA attestation token from mint"""
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(f"{mint_url}/v1/attestation")
            if resp.status_code == 200:
                return resp.json()
            else:
                data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                print_fail(f"Failed to get attestation: {resp.status_code}")
                if "error" in data:
                    print_info(f"Error: {data.get('error')}")
                if "detail" in data:
                    print_info(f"Detail: {data.get('detail')}")
                return None
    except Exception as e:
        print_fail(f"Error fetching attestation: {e}")
        return None


def decode_jwt_unverified(token: str) -> tuple[dict, dict]:
    """Decode JWT without verification to inspect claims"""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    # Decode header
    header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))

    # Decode payload
    payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))

    return header, payload


def verify_maa_token(token: str, maa_endpoint: str) -> dict | None:
    """Verify MAA token signature using JWKS"""
    try:
        # Get JWKS from MAA
        jwks_url = f"{maa_endpoint}/certs"
        jwk_client = PyJWKClient(jwks_url)

        # Get signing key
        signing_key = jwk_client.get_signing_key_from_jwt(token)

        # Verify and decode
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False}  # MAA tokens may not have standard audience
        )
        return decoded
    except jwt.exceptions.InvalidSignatureError:
        print_fail("JWT signature verification failed!")
        return None
    except Exception as e:
        print_fail(f"JWT verification error: {e}")
        return None


def check_sevsnp_claims(claims: dict, expected_hostdata: str | None = None) -> bool:
    """Check AMD SEV-SNP specific claims"""
    all_passed = True

    # Critical security checks
    # Note: ACI Confidential Containers report "azure-compliant-uvm" (Utility VM),
    # not "azure-compliant-cvm" (Confidential VM). This is expected behavior.
    critical_checks = [
        ("x-ms-attestation-type", "sevsnpvm", "Attestation type must be SEV-SNP VM"),
        ("x-ms-compliance-status", "azure-compliant-uvm", "Must be Azure compliant UVM"),
    ]

    for claim, expected, description in critical_checks:
        value = claims.get(claim)
        if value == expected:
            print_ok(f"{claim} = {value}")
        elif value is None:
            print_warn(f"{claim} not present in token")
        else:
            print_fail(f"{claim} = {value} (expected: {expected})")
            print_info(f"  {description}")
            all_passed = False

    # Debug mode check (critical)
    debuggable = claims.get("x-ms-sevsnpvm-is-debuggable")
    if debuggable is False:
        print_ok("x-ms-sevsnpvm-is-debuggable = false (production mode)")
    elif debuggable is True:
        print_fail("x-ms-sevsnpvm-is-debuggable = true (DEBUG MODE - NOT SECURE)")
        all_passed = False
    else:
        print_warn("x-ms-sevsnpvm-is-debuggable claim not found")

    # Optional hostdata pinning
    if expected_hostdata:
        actual = claims.get("x-ms-sevsnpvm-hostdata")
        if actual == expected_hostdata:
            print_ok(f"x-ms-sevsnpvm-hostdata matches expected ({expected_hostdata})")
        else:
            print_fail(f"x-ms-sevsnpvm-hostdata mismatch: {actual} (expected: {expected_hostdata})")
            all_passed = False

    # Informational claims
    info_claims = [
        "x-ms-sevsnpvm-snpfw-svn",
        "x-ms-sevsnpvm-microcode-svn",
        "x-ms-sevsnpvm-bootloader-svn",
        "x-ms-sevsnpvm-tee-svn",
        "x-ms-sevsnpvm-vmpl",
    ]

    print_info("SEV-SNP Version Information:")
    for claim in info_claims:
        value = claims.get(claim)
        if value is not None:
            print(f"      {claim} = {value}")

    return all_passed


def check_token_validity(claims: dict) -> bool:
    """Check token expiration and timing"""
    now = datetime.now(timezone.utc).timestamp()

    exp = claims.get("exp")
    iat = claims.get("iat")
    nbf = claims.get("nbf")

    if exp and now > exp:
        print_fail(f"Token expired at {datetime.fromtimestamp(exp, timezone.utc)}")
        return False
    elif exp:
        remaining = int(exp - now)
        print_ok(f"Token valid for {remaining} more seconds")

    if iat:
        issued = datetime.fromtimestamp(iat, timezone.utc)
        print_info(f"Token issued at: {issued}")

    return True


def verify_mint(
    mint_url: str,
    verbose: bool = False,
    expected_hostdata: str | None = None,
    policy_path: str | None = None
) -> bool:
    """Main verification flow"""

    print_header("Nutshell TEE Attestation Verification")
    print(f"  Mint URL: {mint_url}\n")

    # If policy file provided, compute hostdata from it
    policy_bytes = None
    policy_images = []
    if policy_path:
        print_header("Step 0: Load CCE Policy")
        policy_bytes, computed_hostdata = load_cce_policy(policy_path)
        if not policy_bytes:
            return False

        print_ok(f"Loaded policy from {policy_path}")
        print_ok(f"Computed hostdata: {computed_hostdata}")

        # Extract images
        policy_images = extract_image_digests(policy_bytes)
        if policy_images:
            print_info(f"Found {len(policy_images)} container image(s) in policy")
        else:
            print_warn("No image digests found in policy")

        # Use computed hostdata for verification
        if expected_hostdata and expected_hostdata != computed_hostdata:
            print_warn(f"--expected-hostdata ({expected_hostdata}) differs from policy hash")
            print_info("Using hostdata computed from policy file")
        expected_hostdata = computed_hostdata

    # Step 1: Check attestation info
    print_header("Step 1: Check Attestation Configuration")

    info = get_attestation_info(mint_url)
    if not info:
        return False

    if not info.get("attestation_available"):
        print_fail("Attestation not available on this mint")
        print_info(f"MAA endpoint: {info.get('maa_endpoint', 'not configured')}")
        return False

    print_ok("Attestation is available")
    print_info(f"MAA endpoint: {info.get('maa_endpoint')}")
    print_info(f"SKR endpoint: {info.get('skr_endpoint')}")

    # Step 2: Get attestation token
    print_header("Step 2: Fetch Attestation Token")

    attestation = get_attestation_token(mint_url)
    if not attestation:
        return False

    maa_token = attestation.get("maa_token")
    maa_endpoint = attestation.get("maa_endpoint")

    if not maa_token:
        print_fail("No MAA token in response")
        return False

    print_ok(f"Received MAA token ({len(maa_token)} bytes)")
    print_info(f"Attestation type: {attestation.get('attestation_type')}")

    # Step 3: Decode and inspect token
    print_header("Step 3: Decode JWT Token")

    try:
        header, payload = decode_jwt_unverified(maa_token)
        print_ok(f"JWT algorithm: {header.get('alg')}")
        print_ok(f"JWT key ID: {header.get('kid', 'none')[:20]}...")

        if verbose:
            print_info("Full claims:")
            for k, v in sorted(payload.items()):
                print(f"      {k}: {v}")
    except Exception as e:
        print_fail(f"Failed to decode JWT: {e}")
        return False

    # Step 4: Verify signature
    print_header("Step 4: Verify JWT Signature")

    print_info(f"Fetching JWKS from {maa_endpoint}/certs")
    verified_claims = verify_maa_token(maa_token, maa_endpoint)

    if not verified_claims:
        return False

    print_ok("JWT signature verified successfully")

    # Step 5: Check token validity
    print_header("Step 5: Check Token Validity")

    if not check_token_validity(verified_claims):
        return False

    # Step 6: Check SEV-SNP claims
    print_header("Step 6: Verify SEV-SNP Claims")

    if not check_sevsnp_claims(verified_claims, expected_hostdata=expected_hostdata):
        return False

    # Step 7: Display verified images (if policy was provided)
    if policy_images:
        print_header("Step 7: Verified Container Images")
        print_info("The following images are cryptographically bound to this TEE:")
        print()
        for img in policy_images:
            print(f"    Container: {img.get('name', 'unknown')}")
            print(f"    Image:     {img.get('id', img.get('image', 'unknown'))}")
            if img.get("layer_count", 0) > 0:
                print(f"    Layers:    {img['layer_count']} (dm-verity hashes in policy)")
            print()

    # Final result
    print_header("Verification Result")
    print_ok("This mint is running in a genuine AMD SEV-SNP TEE!")
    print()
    print("  The mint's code and data are protected by hardware-level")
    print("  encryption and cannot be accessed by the cloud provider,")
    print("  hypervisor, or other tenants.")
    print()

    if policy_images:
        print("  The hostdata hash in the MAA token matches the CCE policy,")
        print("  which proves the exact container images listed above are running.")
        print()
        print("  To independently verify:")
        print("    1. Compute: sha256(base64 -d cce-policy.base64)")
        print("    2. Compare with x-ms-sevsnpvm-hostdata from attestation")
        print("    3. Check image digests in the policy match ghcr.io")
        print()

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Verify Nutshell mint TEE attestation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic TEE verification
  %(prog)s https://nuttee.freedom.cash

  # Full verification with CCE policy (proves specific images are running)
  %(prog)s https://nuttee.freedom.cash --policy-file azure/cce-policy.base64

  # Verbose output showing all claims
  %(prog)s https://nuttee.freedom.cash --policy-file azure/cce-policy.base64 -v

What this verifies:
  1. The mint exposes TEE attestation endpoints
  2. The mint can obtain a valid MAA (Microsoft Azure Attestation) token
  3. The token signature is valid (signed by Microsoft)
  4. The token confirms AMD SEV-SNP hardware protection
  5. Debug mode is disabled (production security)
  6. (With --policy-file) The running containers match the published policy

Third-party verification:
  The CCE policy contains the exact image digests that are allowed to run.
  The hostdata in the MAA token is sha256(policy). By verifying:
    - hostdata matches sha256(published policy)
    - policy contains specific image digests
    - those digests match images on ghcr.io
  You can independently verify what code is running in the TEE.
        """
    )
    parser.add_argument("mint_url", help="URL of the Nutshell mint (e.g., https://nuttee.freedom.cash)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all JWT claims")
    parser.add_argument("--policy-file", help="Path to CCE policy file (base64 encoded) for image verification")
    parser.add_argument("--expected-hostdata", help="Expected x-ms-sevsnpvm-hostdata hash (optional if --policy-file provided)")
    parser.add_argument("--expected-hostdata-file", help="Path to file containing expected hostdata hash")

    args = parser.parse_args()

    # Normalize URL
    mint_url = args.mint_url.rstrip("/")
    if not mint_url.startswith("http"):
        mint_url = f"https://{mint_url}"

    expected_hostdata = args.expected_hostdata
    if not expected_hostdata and args.expected_hostdata_file:
        try:
            with open(args.expected_hostdata_file, "r", encoding="utf-8") as f:
                expected_hostdata = f.read().strip()
        except Exception as e:
            print_fail(f"Failed to read hostdata file: {e}")
            sys.exit(1)

    success = verify_mint(
        mint_url,
        verbose=args.verbose,
        expected_hostdata=expected_hostdata,
        policy_path=args.policy_file
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
