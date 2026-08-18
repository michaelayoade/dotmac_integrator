# ADR-0001: Enroll the Integrator in fleet engineering governance

- Status: Accepted
- Date: 2026-08-18

## Decision

`dotmac_integrator` executes independently released external connector plugins,
so it is enrolled in the required Dotmac engineering-conformance contract at
the immutable Governance revision recorded in
`.dotmac/standards-profile.json`. The CI workflow executes that same revision on
pull requests and `main`; a moving ref or candidate mode is not equivalent.

The declared local authority is deliberately narrow: `secret_loading.py` owns
materializing stored secret references at startup and explicit refresh into the
held in-process working set. Request paths consume held material and do not
dereference it. The `dotmac-integration` module remains the owner of connector
lifecycle, claims, retries, checkpoints, repair, and execution state.

The connector source ratchet is transitional inventory evidence. The permanent
runtime boundary is the Governance-owned package topology: independently
released `dotmac-connector-*` distributions may resolve in Poetry's `main`
group here, the named runtime host, and nowhere in a product repository.

## Consequences

- Removing the workflow, changing either immutable pin, or making enforcement
  optional fails locally and in CI.
- Integrator is the positive host canary for the connector-package rule; product
  repositories are the refusal canaries.
- This decision does not make the assembly a business-decision owner and does
  not authorize a provider branch in generic assembly source.
