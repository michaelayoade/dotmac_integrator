"""Generate a complete hash-locked Poetry requirements file."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

if len(sys.argv) != 2 or not sys.argv[1].startswith("poetry=="):
    raise SystemExit("usage: generate.py poetry==X.Y.Z")
POETRY = sys.argv[1]

with tempfile.TemporaryDirectory() as tmp:
    report = Path(tmp) / "report.json"
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--quiet",
            "--report",
            str(report),
            POETRY,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    resolved = json.loads(report.read_text(encoding="utf-8"))["install"]

pins = sorted(
    ((item["metadata"]["name"], item["metadata"]["version"]) for item in resolved),
    key=lambda item: item[0].lower(),
)

print("# Hash-locked Poetry bootstrap — GENERATED, do not hand-edit.")
print("# Regenerate with .github/bootstrap/regenerate.sh.")
print(f"# Pinned installer: {POETRY}\n")
for name, version in pins:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url) as response:  # noqa: S310
        metadata = json.load(response)
    hashes = sorted(
        {
            item["digests"]["sha256"]
            for item in metadata["urls"]
            if item["packagetype"] in {"bdist_wheel", "sdist"}
        }
    )
    if not hashes:
        raise SystemExit(f"no distributions found for {name}=={version}")
    lines = [f"{name}=={version}", *(f"--hash=sha256:{value}" for value in hashes)]
    print(" \\\n+    ".join(lines))
