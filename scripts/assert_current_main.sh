#!/usr/bin/env bash
# Fail unless the release run is on the EXACT current tip of protected main —
# not merely an ancestor of it.
#
# Used TWICE by .github/workflows/release-image.yml: once in `build` (a stale
# or side-branch dispatch cannot publish) and again in `publish`, AFTER the
# protected-environment approval wait and before anything irreversible happens.
# The second call is not redundant: a protected environment can sit pending for
# hours, and an approval is a decision about a SHA, not about a run id. Without
# it, commits landing during the wait are silently absent from a release that
# claims to be current, and the tag would point at a SHA that is no longer the
# tip.
#
# Extracted from inline YAML so the comparison is executable — and therefore
# testable — outside a workflow run: see
# tests/unit/test_release_lane.py, which drives it with a moved ref and also
# asserts both jobs still call it.
#
# Ported verbatim from dotmac_starter_mt scripts/assert_current_main.sh. The
# behaviour is identical on purpose: a release lane that reasons about main
# freshness differently from the fleet's other lanes is a lane whose guarantees
# have to be re-derived by every reader.
#
# Usage: assert_current_main.sh <run_sha> [<main_sha>]
#   run_sha   the SHA this run is executing (GITHUB_SHA in CI)
#   main_sha  optional; resolved from origin/main when omitted. Passing it
#             explicitly is what lets a test simulate a moved ref without a
#             network fetch or a fake remote.
set -euo pipefail

RUN_SHA="${1:?usage: assert_current_main.sh <run_sha> [<main_sha>]}"
MAIN_SHA="${2:-}"

if [ -z "${MAIN_SHA}" ]; then
  git fetch --no-tags origin main
  MAIN_SHA="$(git rev-parse origin/main)"
fi

if [ "${RUN_SHA}" != "${MAIN_SHA}" ]; then
  echo "::error::release run SHA ${RUN_SHA} is not the current protected main ${MAIN_SHA} — main moved (possibly during an approval wait). Re-dispatch on the current tip."
  exit 1
fi

echo "on current protected main: ${MAIN_SHA}"
