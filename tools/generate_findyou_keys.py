#!/usr/bin/env python3
"""
generate_findyou_keys.py — Find You P-224 EC Keypair Generator for HaleHound-CYD

Generates NIST P-224 (SECP224R1) elliptic curve keypairs for Apple FindMy
Offline Finding (OF) location tracking via the Find You module.

Outputs:
  findyou_keys.h   — PROGMEM C header with public key X-coordinates (28 bytes each)
  findyou_keys.json — Private keys for macless-haystack location retrieval
                      *** NEVER COMMIT THIS FILE ***

Based on Positive Security "Find You" research:
  https://github.com/positive-security/find-you
  Paper: "Who Can Find My Devices?" — TU Darmstadt, PoPETs 2021

Usage:
  python3 generate_findyou_keys.py --count 2000 --output-dir /path/to/HaleHound-CYD

Requirements:
  pip3 install cryptography
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP224R1,
        generate_private_key,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )
except ImportError:
    print("ERROR: 'cryptography' library required.")
    print("Install: pip3 install cryptography")
    sys.exit(1)


def generate_keypairs(count):
    """Generate P-224 EC keypairs. Returns list of (private_key_bytes, public_key_x_bytes)."""
    keys = []
    for i in range(count):
        priv = generate_private_key(SECP224R1())

        # Private key as raw 28-byte scalar
        priv_numbers = priv.private_numbers()
        priv_bytes = priv_numbers.private_value.to_bytes(28, byteorder="big")

        # Public key X-coordinate as 28 bytes
        pub_numbers = priv_numbers.public_numbers
        x_bytes = pub_numbers.x.to_bytes(28, byteorder="big")

        keys.append((priv_bytes, x_bytes))

        if (i + 1) % 200 == 0:
            print(f"  Generated {i + 1}/{count} keypairs...")

    return keys


def write_c_header(keys, output_path):
    """Write PROGMEM C header with public key X-coordinates."""
    count = len(keys)

    with open(output_path, "w") as f:
        f.write("// ═══════════════════════════════════════════════════════════════════════════\n")
        f.write("// findyou_keys.h — Find You P-224 Public Keys (PROGMEM)\n")
        f.write(f"// Auto-generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"// Keys: {count} × 28 bytes = {count * 28} bytes in flash (.rodata)\n")
        f.write("// Curve: NIST P-224 (SECP224R1)\n")
        f.write("//\n")
        f.write("// PUBLIC KEYS ONLY — safe to commit.\n")
        f.write("// Private keys are in findyou_keys.json — NEVER commit that file.\n")
        f.write("//\n")
        f.write("// Based on Positive Security \"Find You\" research:\n")
        f.write("//   https://github.com/positive-security/find-you\n")
        f.write("// ═══════════════════════════════════════════════════════════════════════════\n")
        f.write("\n")
        f.write("#ifndef FINDYOU_KEYS_H\n")
        f.write("#define FINDYOU_KEYS_H\n")
        f.write("\n")
        f.write("#include <Arduino.h>\n")
        f.write("#include <pgmspace.h>\n")
        f.write("\n")
        f.write(f"#define FINDYOU_KEY_COUNT {count}\n")
        f.write("#define FINDYOU_KEY_SIZE  28\n")
        f.write("\n")
        f.write(f"static const uint8_t FINDYOU_KEYS[{count}][28] PROGMEM = {{\n")

        for i, (_, pub_x) in enumerate(keys):
            hex_bytes = ", ".join(f"0x{b:02X}" for b in pub_x)
            comma = "," if i < count - 1 else ""
            f.write(f"    {{ {hex_bytes} }}{comma}\n")

        f.write("};\n")
        f.write("\n")
        f.write("#endif // FINDYOU_KEYS_H\n")

    print(f"  Written: {output_path} ({os.path.getsize(output_path)} bytes)")


def write_private_keys(keys, output_path):
    """Write private keys as JSON for macless-haystack retrieval."""
    key_data = []
    for i, (priv_bytes, pub_x) in enumerate(keys):
        key_data.append({
            "index": i,
            "private_key": priv_bytes.hex(),
            "public_key_x": pub_x.hex(),
            "mac_prefix": f"{pub_x[0] | 0xC0:02X}:{pub_x[1]:02X}:{pub_x[2]:02X}:{pub_x[3]:02X}:{pub_x[4]:02X}:{pub_x[5]:02X}",
        })

    output = {
        "generator": "HaleHound-CYD Find You keygen",
        "curve": "SECP224R1 (P-224)",
        "count": len(keys),
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "warning": "NEVER COMMIT THIS FILE — contains private keys for location retrieval",
        "keys": key_data,
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"  Written: {output_path} ({os.path.getsize(output_path)} bytes)")
    print(f"  *** THIS FILE CONTAINS PRIVATE KEYS — DO NOT COMMIT ***")


def main():
    parser = argparse.ArgumentParser(
        description="Generate P-224 EC keypairs for HaleHound-CYD Find You module"
    )
    parser.add_argument(
        "--count", type=int, default=2000,
        help="Number of keypairs to generate (default: 2000)"
    )
    parser.add_argument(
        "--output-dir", type=str, default=".",
        help="Output directory for generated files"
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    if not output_dir.exists():
        print(f"ERROR: Output directory does not exist: {output_dir}")
        sys.exit(1)

    header_path = output_dir / "findyou_keys.h"
    json_path = output_dir / "findyou_keys.json"

    print(f"[*] Generating {args.count} P-224 EC keypairs...")
    keys = generate_keypairs(args.count)

    print(f"\n[*] Writing C header (PROGMEM)...")
    write_c_header(keys, header_path)

    print(f"\n[*] Writing private keys (JSON)...")
    write_private_keys(keys, json_path)

    flash_kb = (args.count * 28) / 1024
    print(f"\n[+] Done! {args.count} keypairs generated.")
    print(f"    Flash cost: ~{flash_kb:.1f} KB ({args.count} × 28 bytes)")
    print(f"    Rotation period at 30s: ~{args.count * 30 / 3600:.1f} hours per full cycle")
    print(f"\n    Header:  {header_path}")
    print(f"    Private: {json_path}")
    print(f"\n    REMINDER: Add findyou_keys.json to .gitignore!")


if __name__ == "__main__":
    main()
