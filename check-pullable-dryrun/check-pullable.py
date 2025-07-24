#!/usr/bin/env python3
"""
check-pullable.py
------------------------

Quick-test a list of Docker/OCI images for “pullability”.

Usage
-----
    python3 check-pullable.py images.txt [--threads 4]

    # images.txt example:
    #   ubuntu:24.04
    #   nginx:1.27
    #   ghcr.io/your-org/private-app:2.1.0

Requirements
------------
* Python ≥ 3.8
* Docker CLI (20.10+) installed and daemon running
  (make sure you’ve `docker login`-ed to any private registries first)

Exit codes
----------
0  – every image is pullable  
1  – one or more images are **not** pullable  
2  – bad arguments / no images in list / Docker missing
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple


# ───────────────────────── helper functions ──────────────────────────
def manifest_inspect(image: str) -> Tuple[str, bool, str]:
    """
    Return (image, pullable?, stderr_message).

    `docker manifest inspect` is fast and requires only registry auth.
    A non-zero exit code means the image can't be pulled with current creds.
    """
    proc = subprocess.run(
        ["docker", "manifest", "inspect", image],
        capture_output=True,
        text=True,
    )
    ok = proc.returncode == 0
    return image, ok, proc.stderr.strip() if not ok else ""


def load_images(file_path: Path) -> List[str]:
    """
    Read non-empty, non-comment lines from the provided file.
    """
    with file_path.open() as fh:
        return [
            ln.strip()
            for ln in fh
            if ln.strip() and not ln.lstrip().startswith("#")
        ]


# ──────────────────────────── main logic ─────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check whether each Docker/OCI image in a text list is pullable."
    )
    parser.add_argument(
        "image_list",
        help="Path to text file (one `registry/name:tag` per line)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="Number of parallel checks (default: 1)",
    )
    args = parser.parse_args()

    # Validate Docker CLI presence
    if subprocess.run(["docker", "--version"], capture_output=True).returncode != 0:
        print("❌ Docker CLI not found or not in PATH.", file=sys.stderr)
        sys.exit(2)

    images = load_images(Path(args.image_list))
    if not images:
        print("❌ No images found in list – aborting.", file=sys.stderr)
        sys.exit(2)

    print(f"🔎 Checking {len(images)} image(s)…\n")

    failures: List[Tuple[str, str]] = []

    def check(image: str) -> None:
        img, ok, msg = manifest_inspect(image)
        if ok:
            print(f" ✅ {img}")
        else:
            print(f" ❌ {img}")
            failures.append((img, msg))

    if args.threads > 1:
        with cf.ThreadPoolExecutor(max_workers=args.threads) as pool:
            pool.map(check, images)
    else:
        for img in images:
            check(img)

    # Summary & exit status
    if failures:
        print(f"\n🚫 {len(failures)} image(s) could NOT be pulled:")
        for img, err in failures:
            # Show the first line of Docker’s error for brevity
            short_err = err.splitlines()[0] if err else "unknown error"
            print(f"  • {img} → {short_err}")
        sys.exit(1)
    else:
        print("\n🎉 All images appear pullable.")
        sys.exit(0)


if __name__ == "__main__":
    main()


