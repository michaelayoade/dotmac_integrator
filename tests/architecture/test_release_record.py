"""scripts/release_record.py: one image per version, exact descriptor bytes."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release_record.py"
DESCRIPTOR = ROOT / "deploy" / "companion" / "deploy-unit.toml"
DIGEST = "sha256:" + "ab" * 32
IMAGE = "registry.example.invalid/app@" + DIGEST
REVISION = "c" * 40


def _run(tmp: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    args = [
        sys.executable,
        "-I",
        str(SCRIPT),
        "--revision",
        REVISION,
        "--version",
        "0.1.0",
        "--descriptor",
        str(DESCRIPTOR),
        "--out",
        str(tmp / "out"),
        *extra,
    ]
    return subprocess.run(args, capture_output=True, text=True, check=False)


def test_record_carries_digest_revision_version_and_exact_bytes(tmp_path: Path) -> None:
    done = _run(tmp_path, "--image", IMAGE)
    assert done.returncode == 0, done.stderr
    record = json.loads((tmp_path / "out" / "release-record.json").read_text())
    raw = DESCRIPTOR.read_bytes()
    assert (tmp_path / "out" / "deploy-unit.toml").read_bytes() == raw
    assert record["deploy_unit_sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert record["image_ref"] == IMAGE
    assert record["image_digest"] == DIGEST
    assert record["source_revision"] == REVISION
    assert record["version"] == "0.1.0"


def test_exactly_one_image_per_version(tmp_path: Path) -> None:
    other = "registry.example.invalid/app@sha256:" + "cd" * 32
    two = _run(tmp_path, "--image", IMAGE, "--image", other)
    assert two.returncode == 2 and "exactly one" in two.stderr
    assert not (tmp_path / "out").exists()


def test_refuses_sentinel_tag_and_short_revision(tmp_path: Path) -> None:
    zero = "registry.example.invalid/app@sha256:" + "0" * 64
    assert _run(tmp_path, "--image", zero).returncode == 2
    assert (
        _run(tmp_path, "--image", "registry.example.invalid/app:latest").returncode == 2
    )
    short = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SCRIPT),
            "--image",
            IMAGE,
            "--revision",
            "abc",
            "--version",
            "1",
            "--descriptor",
            str(DESCRIPTOR),
            "--out",
            str(tmp_path / "o"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert short.returncode == 2


def test_workflow_uploads_the_record_without_new_triggers() -> None:
    text = (ROOT / ".github" / "workflows" / "release-image.yml").read_text()
    assert "release_record.py" in text and "release-record" in text
    assert "workflow_dispatch:" in text
    for trigger in ("\n  push:", "\n  pull_request", "\n  schedule:"):
        assert trigger not in text
    # No new credential: the record steps use no secret.
    block = text.split("Produce release record")[1].split("Summarise")[0]
    assert "secrets." not in block
