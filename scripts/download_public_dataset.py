"""Automated Public Forensic Email Dataset Downloader for CyberTrace.

Fetches and extracts real-world raw email corpora (.eml / RFC 822 format)
from official open-source security archives (Apache SpamAssassin Public Corpus).
"""

import argparse
import io
import sys
import tarfile
from pathlib import Path
import httpx

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

ARCHIVES = {
    "spam": {
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
        "description": "Real-world Spam & Phishing email corpus (500 raw emails, ~1.18 MB)",
    },
    "ham": {
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "description": "Legitimate enterprise/personal email corpus (2,500 raw emails, ~1.61 MB)",
    },
}


def download_and_extract(corpus_type: str, limit: int = 50, output_dir: Path = None):
    if corpus_type not in ARCHIVES:
        print(f"[-] Unknown corpus type: {corpus_type}. Choose 'spam', 'ham', or 'both'.")
        return

    config = ARCHIVES[corpus_type]
    url = config["url"]
    dest_dir = output_dir or (ROOT_DIR / "data" / "public_corpus" / corpus_type)
    dest_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Downloading {corpus_type.upper()} corpus: {config['description']}")
    print(f"    URL: {url}")

    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        raw_archive = response.content

    print(f"[+] Download complete ({len(raw_archive):,} bytes). Extracting up to {limit} sample emails...")

    count = 0
    with tarfile.open(fileobj=io.BytesIO(raw_archive), mode="r:bz2") as tar:
        for member in tar.getmembers():
            if member.isfile() and not member.name.endswith(".txt") and not member.name.endswith("cmds"):
                file_obj = tar.extractfile(member)
                if file_obj is None:
                    continue
                content = file_obj.read()
                
                # Save as clean .eml file
                safe_name = f"{corpus_type}_{Path(member.name).name}.eml"
                out_path = dest_dir / safe_name
                out_path.write_bytes(content)
                count += 1
                if limit and count >= limit:
                    break

    print(f"[+] Successfully extracted {count} .eml files into: {dest_dir}")
    return dest_dir


def main():
    parser = argparse.ArgumentParser(description="Download public forensic email datasets for CyberTrace.")
    parser.add_argument(
        "--type",
        choices=["spam", "ham", "both"],
        default="spam",
        help="Type of corpus to download (spam, ham, or both). Default: spam.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=30,
        help="Maximum number of emails to extract (default: 30, set 0 for all).",
    )
    args = parser.parse_args()

    print("=" * 70)
    print(" CyberTrace // Public Forensic Email Dataset Ingestion Tool")
    print("=" * 70)

    limit = None if args.limit <= 0 else args.limit

    if args.type == "both":
        download_and_extract("spam", limit=limit)
        download_and_extract("ham", limit=limit)
    else:
        download_and_extract(args.type, limit=limit)

    print("\n[+] Done! You can now drag and drop these emails onto the CyberTrace Dashboard:")
    print("    URL: http://127.0.0.1:8000/")


if __name__ == "__main__":
    main()
