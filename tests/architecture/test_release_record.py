"""scripts/release_record.py: one image per version, exact descriptor and spec bytes."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release_record.py"
DESCRIPTOR = ROOT / "deploy" / "companion" / "deploy-unit.toml"
SPEC = ROOT / "deploy" / "companion" / "product.toml"
DIGEST = "sha256:" + "ab" * 32
IMAGE = "registry.example.invalid/app@" + DIGEST
REVISION = "c" * 40


def _run(
    out: Path, *extra: str, descriptor: Path = DESCRIPTOR
) -> subprocess.CompletedProcess[str]:
    args = [
        sys.executable,
        "-I",
        str(SCRIPT),
        "--revision",
        REVISION,
        "--version",
        "0.1.0",
        "--descriptor",
        str(descriptor),
        "--descriptor-name",
        "deploy/companion/deploy-unit.toml",
        "--out",
        str(out),
    ]
    return subprocess.run(
        args + list(extra), capture_output=True, text=True, check=False
    )


def test_record_carries_digest_revision_version_and_exact_bytes(tmp_path: Path) -> None:
    done = _run(tmp_path / "out", "--image", IMAGE, "--spec-pending")
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
    two = _run(tmp_path / "out", "--image", IMAGE, "--image", other, "--spec-pending")
    assert two.returncode == 2 and "exactly one" in two.stderr
    assert not (tmp_path / "out").exists()


def test_refuses_sentinel_tag_and_short_revision(tmp_path: Path) -> None:
    zero = "registry.example.invalid/app@sha256:" + "0" * 64
    assert _run(tmp_path / "a", "--image", zero, "--spec-pending").returncode == 2
    tag = "registry.example.invalid/app:latest"
    assert _run(tmp_path / "b", "--image", tag, "--spec-pending").returncode == 2
    bad = _run(tmp_path / "c", "--image", IMAGE, "--revision", "abc", "--spec-pending")
    assert bad.returncode == 2


def test_workflow_uploads_the_record_without_new_triggers() -> None:
    text = (ROOT / ".github" / "workflows" / "release-image.yml").read_text()
    assert "release_record.py" in text and "release-record" in text
    assert "workflow_dispatch:" in text
    for trigger in ("\n  push:", "\n  pull_request", "\n  schedule:"):
        assert trigger not in text
    block = text.split("Produce release record")[1]
    assert "secrets." not in block.split("upload-artifact")[0]


def test_pending_spec_is_recorded_as_absent(tmp_path: Path) -> None:
    assert not SPEC.exists(), "I3 landed: pass --product-toml and drop --spec-pending"
    done = _run(tmp_path / "out", "--image", IMAGE, "--spec-pending")
    assert done.returncode == 0, done.stderr
    record = json.loads((tmp_path / "out" / "release-record.json").read_text())
    assert record["product_toml_path"] is None
    assert record["product_toml_sha256"] is None
    assert record["product_toml_pending"] is True


def test_refuses_to_emit_while_spec_absent_unless_marked_pending(
    tmp_path: Path,
) -> None:
    done = _run(tmp_path / "out", "--image", IMAGE)
    assert done.returncode == 2 and "product.toml" in done.stderr
    assert not (tmp_path / "out").exists()


def test_pending_is_refused_once_the_spec_file_exists(tmp_path: Path) -> None:
    copy = tmp_path / "deploy" / "companion"
    copy.mkdir(parents=True)
    shutil.copy(DESCRIPTOR, copy / "deploy-unit.toml")
    (copy / "product.toml").write_text("schema = 'x'\n")
    done = _run(
        tmp_path / "out",
        "--image",
        IMAGE,
        "--spec-pending",
        descriptor=copy / "deploy-unit.toml",
    )
    assert done.returncode == 2 and "now exists" in done.stderr


def test_pending_is_only_for_companion_descriptors(tmp_path: Path) -> None:
    other = tmp_path / "deploy-unit.toml"
    shutil.copy(DESCRIPTOR, other)
    args = [sys.executable, "-I", str(SCRIPT), "--image", IMAGE, "--revision", REVISION]
    args += ["--version", "1", "--descriptor", str(other), "--spec-pending"]
    args += [
        "--descriptor-name",
        "deploy/deploy-unit.toml",
        "--out",
        str(tmp_path / "o"),
    ]
    done = subprocess.run(args, capture_output=True, text=True, check=False)
    assert done.returncode == 2
