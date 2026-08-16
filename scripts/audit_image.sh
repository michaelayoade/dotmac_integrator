#!/usr/bin/env bash
#
# What the built image must be true of. Run by CI against the image it just
# built, and by `make image-audit` against a local one.
#
# Each check exists because the opposite is a real, shippable mistake:
#
#   root            a `USER root` added to install one debugging tool, never
#                   removed;
#   boot migration  an entrypoint that "just makes sure the schema is there",
#                   which races itself across replicas and needs owner
#                   credentials in the runtime environment;
#   drifted pins    an image built before a pin moved, or from a checkout
#                   rather than the published wheels;
#   leaked token    the registry credential surviving into image metadata or a
#                   layer, which `docker history` reads back.
#
# Nothing here needs a database. These are properties of the artefact.

set -euo pipefail

IMAGE="${1:?usage: audit_image.sh <image>}"
FAILURES=0

fail() { echo "FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "ok:   $*"; }

# ── 1. Not root ─────────────────────────────────────────────────────────────
uid="$(docker run --rm --entrypoint id "$IMAGE" -u)"
if [ "$uid" = "0" ]; then
  fail "the image runs as root (uid 0)"
else
  pass "runs as uid $uid"
fi

configured_user="$(docker image inspect --format '{{.Config.User}}' "$IMAGE")"
if [ -z "$configured_user" ]; then
  fail "no USER is configured; the runtime would be root wherever the platform does not override it"
else
  pass "USER is '$configured_user'"
fi

# ── 2. No migration on boot ─────────────────────────────────────────────────
entrypoint="$(docker image inspect --format '{{json .Config.Entrypoint}}' "$IMAGE")"
cmd="$(docker image inspect --format '{{json .Config.Cmd}}' "$IMAGE")"
if printf '%s%s' "$entrypoint" "$cmd" | grep -Eqi 'alembic|migrate|upgrade[[:space:]]+heads'; then
  fail "the default command migrates: entrypoint=$entrypoint cmd=$cmd"
else
  pass "the default command does not migrate"
fi

# Sensitivity proof (ADR-0018): the detector above is a grep, and a grep that
# matches nothing passes for the wrong reason. Proved against a planted string.
if printf '["python","-m","dotmac_integrator.migrate","upgrade","heads"]' \
   | grep -Eqi 'alembic|migrate|upgrade[[:space:]]+heads'; then
  pass "the boot-migration detector bites on a planted command"
else
  fail "the boot-migration detector does not bite; the check above proves nothing"
fi

# ── 3. The pins are what is installed ───────────────────────────────────────
for dist in dotmac-kernel dotmac-integration; do
  pinned="$(grep -E "^${dist} = \"" pyproject.toml | sed -E 's/.*"([^"]+)".*/\1/')"
  installed="$(docker run --rm --entrypoint python "$IMAGE" \
      -c "from importlib.metadata import version; print(version('${dist}'))")"
  if [ "$pinned" != "$installed" ]; then
    fail "$dist: pinned $pinned, image has $installed"
  else
    pass "$dist $installed matches the pin"
  fi
done

# ── 4. The registry credential is not in the image ──────────────────────────
if docker image inspect --format '{{json .Config.Env}}' "$IMAGE" \
   | grep -q 'FORGEJO_PASSWORD'; then
  fail "the registry password survived into image metadata"
else
  pass "no registry password in image metadata"
fi

if docker history --no-trunc "$IMAGE" | grep -q 'FORGEJO_PASSWORD='; then
  fail "the registry password survived into a layer command"
else
  pass "no registry password in the layer history"
fi

# ── 5. The application actually imports ─────────────────────────────────────
# A PYTHONPATH or a missing file would otherwise surface on the first request
# of the first deploy.
if docker run --rm --entrypoint python "$IMAGE" \
     -c "import dotmac_integrator.assembly, dotmac_integrator.migrate" >/dev/null; then
  pass "the application and its migration entry point import"
else
  fail "the application does not import inside the image"
fi

if [ "$FAILURES" -gt 0 ]; then
  echo "$FAILURES image check(s) failed" >&2
  exit 1
fi
echo "image audit passed"
