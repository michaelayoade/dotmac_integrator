# Deployment adapter

This directory is the whole of this assembly's deployment input.
`product.toml` is a `ProductDeploymentSpec.v1` descriptor; everything under
`rendered/` is generated from it and **must not be edited**.

Decision: the Starter's
`docs/adr/0070-deployment-is-a-stateless-versioned-foundation.md`. Sources and
the defect list: `docs/inventories/deployment-foundation-sources.md`.

## Why this repository is both a source and an adopter

The foundation's image contract is a port of this repository's. `Dockerfile`'s
fixed non-root UID/GID and `exec` PID 1, the one-shot `migrate` service with
`service_completed_successfully`, the owner/online credential split, the
readiness endpoint that actually returns 503, and `scripts/audit_image.sh` with
its sensitivity proof are all extraction sources (inventory § 4). None of that
changes here.

What this adapter adds is the three things that were missing or contradictory.

## What it fixes

| # | Defect | Now |
|---|---|---|
| D14 | `docker-compose.yml:18` reads `${INTEGRATOR_TAG:-latest}` while `release-image.yml:192-198,230` says it deploys BY DIGEST. No digest knob existed, so the workflow's own contract was unimplementable with the file it deploys. | `image.reference` is a digest and the schema refuses a tag. |
| D15 | compose defaults `ENVIRONMENT: production`, which makes `METRICS_TOKEN` prod-fatal (`settings.py:424-430`), and never sets it — the shipped defaults refuse to boot. | Every required material is declared, so a missing one is a render-time fact rather than a boot-time discovery. |
| §7 | No deployment engine, no backup, no ingress. | A gated deployment plan, a verified Postgres backup with a restore-proof window, and a warm-candidate Nginx site. |

It also adds resource limits, log rotation and a `pids_limit`, none of which the
existing compose file declares — one leak currently takes the host rather than
the container.

## What it does NOT do

- **It retires nothing.** `docker-compose.yml` remains the live path. It stops
  being the live path only when the rendered file has been proven equivalent on
  a named target, which has not happened and is not authorised here.
- **It does not deploy.** `dotmac-deploy deploy` is a dry run without
  `--execute`, and `--execute` additionally needs a host `Effects` provider that
  the foundation deliberately does not ship: the facility owns order, refusal
  and evidence; a provider owns how to talk to Docker and Postgres.
- **It does not declare egress.** `[egress] hosts = []` is a positive
  declaration, not an omission. Rule 32 puts provider hosts in the connector
  manifest, and `derive_runtime_policy` projects the installed set at boot — a
  second allowlist in a rendered file could be widened without installing a
  reviewed connector release, which is the thing `EgressDeclaration` refuses by
  accepting no installation-provided hosts.

## Working on it

```bash
dotmac-deploy -f deploy/product.toml validate
dotmac-deploy -f deploy/product.toml render -o deploy/rendered \
  --thresholds deploy/alerts/thresholds.json
dotmac-deploy -f deploy/product.toml render --check -o deploy/rendered \
  --thresholds deploy/alerts/thresholds.json      # CI runs this
dotmac-deploy -f deploy/product.toml plan          # gates marked; deploys nothing
```

Edit `product.toml` and re-render. Never edit a rendered file: `render --check`
fails on a single changed byte, which is the point — it is the check that would
have caught the host-side script drift recorded twice against a live Sub
staging host, where the running `deploy.sh` was traced to a commit that was not
the deployed release.

## Two files, two jobs

`alerts/ingress.rules.yml` is this product's own, hand-written, and stays.
`rendered/alerts.rules.yml` is the foundation's 64 common infrastructure alerts
plus the five domain alerts declared in `product.toml`. They do not overlap:
infrastructure belongs to the foundation, and worker leases, receipts and
retention belong here.

`alerts/thresholds.json` supplies the 34 numbers only this product can answer.
The rule is the one `ingress.rules.yml` already states in its header —
thresholds live in the deployment, never in the process.

## Re-derive at every pin bump

`migration.expected_heads` names the head of each composed lineage —
`0026_platform_audit_log` (kernel `0.1.0a68`) and `ig_0015_descriptor_contract`
(`dotmac-integration 0.1.0a17`). A release that changes either lineage changes
what this file must assert about it, exactly as rule 10 already requires of the
prerequisite bindings. A partial `upgrade heads` still exits 0, so this list is
the only thing that can see a lineage that silently did not advance.

This instruction is no longer only an instruction. It was written here and
followed by nobody: the pin moved `a13` -> `a17`, the `ig` lineage advanced four
revisions, and both this file and the test asserting it kept naming the `a13`
head. `test_the_declared_heads_are_the_installed_lineage_heads` now DERIVES both
heads from the installed wheels through `lineage.version_locations()`, so a pin
bump that forgets to re-derive fails in CI instead of at the deploy gate — where
the symptom is a correctly-migrated deployment failing `verify_heads`, which is
the reliable way to teach an operator to skip a gate.
