"""Write the deploy release record for one published image.

The record is the product CI's statement of what was published: the image
digest and full reference, the full source revision, the version, the exact
bytes of the deploy descriptor with their sha256, and the path and sha256 of
the exact product.toml bytes the release was built from (the CI-bound copy when
CI rewrites it: the bytes Foundation validates). It is written next to a
byte-for-byte copy of the descriptor so a consumer can recompute the digest.

Refuses (exit 2) unless there is exactly ONE container image for the version
(the release catalogue allows one per product version), the digest is a
sha256, the revision is 40 hex, and the descriptor is the dotmac.deploy_unit/1
schema. A missing product.toml is refused, except for a companion descriptor (under
deploy/companion/) whose spec file does not exist yet and is declared with
--spec-pending: the record then says so explicitly. Needs no network and no
credential; it only reads the files it is given.

Usage:
    python scripts/release_record.py --image <repo>@sha256:<64-hex> \
        --revision <40-hex> --version <version> \
        --descriptor deploy/deploy-unit.toml --product-toml deploy/product.toml \
        --out release-record
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

_IMAGE = re.compile(r"(?P<repo>[^\s@]+)@(?P<digest>sha256:[0-9a-f]{64})")
_REVISION = re.compile(r"[0-9a-f]{40}")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}")
SCHEMA = "dotmac.deploy_unit/1"


class ReleaseRecordError(ValueError):
    """A refusal to describe a release the inputs do not prove."""


def build_record(
    *,
    images: list[str],
    revision: str,
    version: str,
    descriptor: bytes,
    descriptor_path: str = "deploy/deploy-unit.toml",
    product_toml: bytes | None = None,
    product_toml_path: str = "",
    spec_pending: bool = False,
) -> dict[str, str | bool | None]:
    if len(images) != 1:
        raise ReleaseRecordError(
            f"exactly one container image per product version, got {len(images)}"
        )
    match = _IMAGE.fullmatch(images[0])
    if match is None:
        raise ReleaseRecordError("image must be repo@sha256:<64 lowercase hex>")
    if set(match.group("digest")[7:]) == {"0"}:
        raise ReleaseRecordError("refusing the all-zero sentinel digest")
    if _REVISION.fullmatch(revision) is None or set(revision) == {"0"}:
        raise ReleaseRecordError("revision must be a non-zero 40-hex revision")
    if _VERSION.fullmatch(version) is None:
        raise ReleaseRecordError("version is not well formed")
    try:
        document = tomllib.loads(descriptor.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseRecordError(f"descriptor is not valid TOML: {exc}") from None
    if document.get("schema") != SCHEMA:
        raise ReleaseRecordError(f"descriptor schema must be {SCHEMA}")
    spec = document.get("spec")
    if product_toml is None:
        companion = descriptor_path.replace("\\", "/").startswith("deploy/companion/")
        if not (spec_pending and companion):
            raise ReleaseRecordError(
                "product.toml bytes are required (--spec-pending is only for a "
                "companion descriptor whose spec is not written yet)"
            )
    elif spec_pending:
        raise ReleaseRecordError("--spec-pending contradicts a supplied product.toml")
    elif product_toml_path != spec:
        raise ReleaseRecordError("product.toml is not the file the descriptor names")
    else:
        try:
            tomllib.loads(product_toml.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ReleaseRecordError(f"product.toml is not valid TOML: {exc}") from None
    return {
        "image_ref": images[0],
        "image_repository": match.group("repo"),
        "image_digest": match.group("digest"),
        "source_revision": revision,
        "version": version,
        "product": str(document.get("product", "")),
        "deploy_unit_path": "deploy-unit.toml",
        "deploy_unit_sha256": "sha256:" + hashlib.sha256(descriptor).hexdigest(),
        "product_toml_path": product_toml_path if product_toml is not None else None,
        "product_toml_sha256": (
            "sha256:" + hashlib.sha256(product_toml).hexdigest()
            if product_toml is not None
            else None
        ),
        "product_toml_pending": product_toml is None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", action="append", default=[], required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument(
        "--descriptor-name",
        help="repo-relative path of the descriptor (default: --descriptor as given)",
    )
    parser.add_argument("--product-toml", type=Path)
    parser.add_argument("--spec-pending", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        raw = args.descriptor.read_bytes()
        spec_bytes = args.product_toml.read_bytes() if args.product_toml else None
        spec_name = str(tomllib.loads(raw.decode("utf-8")).get("spec", ""))
        record = build_record(
            images=args.image,
            revision=args.revision,
            version=args.version,
            descriptor=raw,
            descriptor_path=args.descriptor_name or str(args.descriptor),
            product_toml=spec_bytes,
            product_toml_path=spec_name,
            spec_pending=args.spec_pending,
        )
        if args.spec_pending and (args.descriptor.parent / "product.toml").exists():
            raise ReleaseRecordError("--spec-pending but the spec file now exists")
    except (OSError, ReleaseRecordError) as exc:
        print(f"release record refused: {exc}", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "deploy-unit.toml").write_bytes(raw)
    if spec_bytes is not None:
        (args.out / "product.toml").write_bytes(spec_bytes)
    (args.out / "release-record.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"release record for {record['image_ref']} at {record['source_revision']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
