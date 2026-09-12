"""Utility script to generate sample .eml files for CyberTrace testing and investigation."""

import os
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tests.fixtures.generate_synthetic_eml import (
    create_clean_eml,
    create_phishing_obfuscated_eml,
    create_quishing_eml,
)


def main():
    samples_dir = ROOT_DIR / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    sample_files = {
        "clean_corporate.eml": create_clean_eml(),
        "spoofed_phishing.eml": create_phishing_obfuscated_eml(),
        "quishing_mfa.eml": create_quishing_eml(),
    }

    print(f"[*] Generating sample .eml files in {samples_dir}...")
    for filename, data in sample_files.items():
        dest = samples_dir / filename
        dest.write_bytes(data)
        print(f"    [+] Created: {dest.name} ({len(data):,} bytes)")

    print("[+] All sample emails generated successfully! Drag-and-drop them into the dashboard at http://127.0.0.1:8000/")


if __name__ == "__main__":
    main()
