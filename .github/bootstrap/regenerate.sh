#!/usr/bin/env bash
# Regenerate the one Linux/Python bootstrap used by CI and the image.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"

if (( $# != 0 )); then
  echo "error: edit [tool.poetry].requires-poetry; this command takes no version" >&2
  exit 2
fi

pin="$(python3 "${REPO}/scripts/check_poetry_toolchain.py" --print-requirement)"
out="${HERE}/poetry-requirements-py312.txt"
docker run --rm -i --platform linux/amd64 python:3.12-slim \
  python - "${pin}" <"${HERE}/generate.py" >"${out}.tmp"
mv "${out}.tmp" "${out}"

echo "wrote ${out}"
echo "verify in a fresh Python 3.12 Linux venv with --require-hashes"
