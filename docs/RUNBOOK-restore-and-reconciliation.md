# Runbook — restore and reconciliation

Every alert in `deploy/alerts/ingress.rules.yml` links to a section here.

Two rules apply to everything below, and they are not stylistic.

**Correlate through the audit ledger, never through a metric label.** No metric
this deployment exports carries an endpoint key, a `provider_event_id`, a phone
number, message content or anything derived from a secret — the label
vocabularies in `telemetry.py` are closed sets and the renderer refuses
anything else. So when an alert tells you *that* something is wrong, the *which*
comes from the platform audit ledger and the `mod_intg` tables, both of which
have access control. If you find yourself wanting a label to identify a
customer, the answer is a query, not a new label.

**A replay is a decision, and it is recorded.** Every repair endpoint requires a
`reason` and there is no default. Write what you actually concluded; six months
from now that sentence is the only thing distinguishing a considered
intervention from a mistake.

---

## Orientation: what am I looking at?

```
GET /health/live          process is up
GET /health/ready         database reachable, mod_intg present
GET /health/composition   kernel + module versions actually loaded
GET /operations/health-report   the MODULE's verdict on what is stuck
GET /metrics              the facts the alerts fire on
```

`/operations/health-report` and `/metrics` answer different questions on
purpose. The health report is `dotmac_integration`'s own verdict — it is the
authority. `/metrics` adds the shapes a time series needs: per-state depths, and
the **age** of the oldest member of every backlog that can age. Start with the
report; use the ages to tell "a small backlog" from "one item stuck since
March", which the counts cannot distinguish.

---

## The worker stalled

*Alerts: `IntegratorWorkerDown`, `IntegratorWorkerStalled`,
`IntegratorWorkerNeverSwept`, `IntegratorSweepFailing`.*

The background loop reclaims leases whose holder died. It is the only pump in
the process today, and it is idempotent.

1. **Is this replica meant to sweep?** `WORKER_ENABLED=false` is a legitimate
   API-only deployment and exports `integrator_worker_running 0`. Check the
   replica's configuration before treating it as an incident.
2. **`IntegratorSweepFailing` with the loop alive** is the important case: the
   process is healthy, the task is running, and every sweep raises. The
   exception is in the application log (`lease sweep failed; continuing`) with a
   traceback. It is almost always the database — a permission change on
   `platform_api`, a connection limit, or a failover.
3. **`IntegratorWorkerNeverSwept`** means no sweep has ever completed since
   start. The timestamp gauge is absent rather than zero on purpose, so this is
   a separate alert rather than a very large duration.
4. **Manual reclaim while you fix it:**

   ```bash
   curl -XPOST http://<replica>/operations/leases/release-expired
   ```

   Safe to run repeatedly. It touches only leases that have ALREADY expired, and
   it does **not** reset `attempt_count` — the attempts genuinely happened, and
   pretending otherwise would let a permanently failing delivery retry forever.

---

## Expired leases

*Alert: `IntegratorLeasesExpired`.*

`integrator_delivery_lease_expired > 0` means a worker died holding a delivery.
The row is `in_flight` with `leased_until` in the past, and nothing will retry it
until it is reclaimed.

Distinguish it from `integrator_delivery_leased`, which counts LIVE leases —
work in progress, entirely healthy. Conflating the two is how a dead worker
looks busy.

Reclaim with the endpoint above. If the count returns immediately after each
sweep, the workers are not dying — they are being killed. Look at memory limits
and at how long provider calls are taking against `ExecutionPolicy.lease_seconds`.

---

## Queue lag

*Alert: `IntegratorQueueLag`.*

`integrator_delivery_oldest_due_age_seconds` is the age of the oldest delivery
whose next attempt is due and which no worker holds. The alert fires on this
rather than on `integrator_delivery_due` because a queue of one item stuck at the
head looks exactly like a healthy queue of one.

1. Check `integrator_worker_running` first — a stalled worker explains all of it.
2. Check `integrator_delivery_queue_depth{state="retryable"}`. A large retryable
   population with a growing age means a provider is failing and the backoff
   curve is doing its job; the fix is upstream, not here.
3. Do **not** replay to "unstick" it. A replay resets the attempt budget, which
   is correct for an operator's deliberate retry and wrong as a way to make a
   dashboard green.

---

## A stuck receipt

*Alert: `IntegratorReceiptStuck`.*

`integrator_receipt_oldest_unprocessed_age_seconds` counts from `received_at` for
any receipt that has not reached `processed` or `dead_letter`. An hour is a
customer waiting.

1. Find it — by age, in the ledger, not from a metric:

   ```sql
   SELECT id, state, attempt_count, error_code, received_at
     FROM mod_intg.inbox_receipts
    WHERE state NOT IN ('processed', 'dead_letter')
    ORDER BY received_at
    LIMIT 20;
   ```

2. `state = 'processing'` with a stale `received_at` means a worker took the
   claim and never settled it. `state = 'retryable'` with a rising
   `attempt_count` means the handler keeps failing — `error_code` is the
   connector's own vocabulary and is stored, never branched on.
3. Replay it once you know why:

   ```bash
   curl -XPOST http://<replica>/operations/receipts/<uuid>/replay \
        -H 'content-type: application/json' \
        -d '{"reason": "handler fixed in 1.4.2; reprocessing the backlog"}'
   ```

   A replay returns the receipt to `verified` and resets `attempt_count`. Only
   `dead_letter` and `retryable` receipts may be replayed.

---

## Reconciliation required

*Alert: `IntegratorReconciliationRequired`. This one pages.*

`reconciliation_required` is the answer a queue needs and usually does not have.
It means the effect may have **half-landed** at the provider: retrying risks
duplicating it, and dead-lettering it hides it. A human has to decide which.

1. Read the delivery's `error_code` and `error_detail`, and its
   `idempotency_key`.
2. **Ask the provider what it thinks happened**, using that idempotency key.
   This is the whole reason the key exists. Do not infer from our own state.
3. Then:
   - the provider never received it → replay;
   - the provider received and applied it → do **not** replay. Settle the row by
     replaying and letting the connector return `SUCCEEDED`, or leave it and
     record the decision in the audit trail;
   - the provider is unsure → escalate. Guessing here is how a customer is
     charged twice.
4. Whatever you conclude, put it in the `reason`. This is the single most
   valuable audit record this system produces.

---

## Dead letters

*Alert: `IntegratorDeadLetter`.*

The engine gave up after `ExecutionPolicy.max_attempts`. Nothing further will
happen without a person.

Replaying resets the attempt budget — deliberately, and unlike the source
system, where a replayed dead letter dead-lettered again on its first outcome and
the replay was a no-op that looked like an action. So a replay here is a real
second chance, and it is only a good idea once the cause is fixed.

**Note the retention interaction:** a `dead_letter` receipt is *refused* by the
payload purge precisely because it is still replayable. Its payload is being kept
past the retention period on purpose. Clearing dead letters is therefore also how
a retention backlog gets unblocked — see below.

---

## A stale checkpoint

*Alert: `IntegratorCheckpointStale`.*

A polling cursor has not advanced. The danger is not a double call but a
**silently skipped window**: the range between where the cursor is and where the
provider is now grows, and nothing polls it again.

1. Check whether the poll is running at all.
2. `mod_intg.polling_checkpoints.version` is an optimistic lock. Repeated
   `CheckpointConflict` means two workers are racing one cursor; that is the
   lock working, but it should not be a steady state.
3. Rewinding a cursor to re-poll a missed window is safe **only** because the
   inbox deduplicates on `(capability_binding_id, provider_event_id)`. Re-polled
   events that were already received return as duplicates rather than being
   processed twice.

---

## Signature rejections

*Alert: `IntegratorSignatureRejections`.*

The metric is `integrator_ingress_signature_verifications_total{outcome=...}` and
it carries **two** label values and nothing else. There is no endpoint key, no
request body and no sender in it, by construction.

A steady trickle is normal — scanners find webhook URLs. A burst is one of:

- a provider secret rotated on one side only. Check the installation's current
  configuration revision; secrets are stored as REFERENCES, so what you are
  checking is which reference is in use, never a value;
- a provider changed its signing scheme, which is the connector's problem;
- someone is probing.

To identify *which* endpoint, use the platform audit ledger. Adding a label to
answer this question would put the endpoint key into every dashboard, every
screenshot and every ticket that quotes one, permanently.

---

## Challenge refusals

*Alert: `IntegratorChallengeRefused`.*

A provider's verification handshake was refused. Almost always a webhook
configured to point at this deployment for a binding that does not exist,
is disabled, or was retired. Check the binding's state before assuming an
attack — the usual cause is a retirement where the provider-side configuration
was never removed.

---

## Unknown target

*Alert: `IntegratorUnknownTargetRefusals`.*

Inbound events arriving for no known binding. They are being **refused, not
queued** — there is no receipt, so there is nothing to replay later. If the
binding was disabled deliberately, remove the provider-side webhook too. If it
was disabled by accident, re-enable it and ask the provider to redeliver: our
deduplication makes a redelivery safe.

---

## Payload retention

*Alerts: `IntegratorPayloadRetentionNotConfigured`,
`IntegratorPayloadRetentionOverdue`.*

### What retention does

`dotmac_integration.retention` ages out a receipt's **content** and never its
**identity**. It rewrites `payload_json`, `headers_json` and the values inside
`consequence_json`, and touches no column that deduplication, ordering or outcome
comparison reads. `payload_digest`, `provider_event_id`, `capability_binding_id`,
`state` and `processed_at` all survive.

That is not tidiness. Providers redeliver for days, and a restored queue can
resurface a months-old event at any time. A **deleted** receipt is one whose
redelivery becomes a NEW event, and the product then answers the same customer
conversation twice. A **redacted** receipt still says "already received".

### `NotConfigured`

There is no default retention period and no default legal-policy owner, in code
or in the alert rules. Both are deliberate: a period baked into a library becomes
the fleet's data-retention posture without anyone deciding it.

To configure:

1. set `INTEGRATION_PAYLOAD_RETENTION_DAYS` and
   `INTEGRATION_RETENTION_LEGAL_POLICY_OWNER` for whatever runs the sweep;
2. uncomment the `integrator_payload_retention_period_seconds` recording rule in
   `deploy/alerts/ingress.rules.yml` and set it to the same number of seconds.

Until then the module refuses to purge and the alert says so. That is the
intended state, not a bug.

### `Overdue`

Content is being kept past its period. Either the sweep is not running, or every
candidate is being **refused** — and a refusal is a decision, not a failure. The
four reasons, each of which is a different way that purging would have destroyed
work in flight:

| refusal | what it means | how it clears |
| --- | --- | --- |
| `legal_hold` | somebody instructed us to keep this | release the hold, with a reason, when the matter closes |
| `leased` | a worker holds the claim right now | it clears itself, or the receipt is stuck — see "a stuck receipt" |
| `unresolved` | never reached an outcome, or is still replayable (`verified`, `retryable`, `dead_letter`) | resolve or dead-letter it, then clear the dead letters |
| `reconciliation_required` | may have half-landed; a human must still compare it against the payload | reconcile it — see above |

The counts by reason are written into the platform audit ledger by every sweep
that did something, alongside the ids it redacted and the legal-policy owner in
force at the time. They are deliberately not metric labels.

### Legal hold

A held receipt is never redacted, and the refusal is explicit. The hold is
enforced twice: the sweep will not select a held receipt, and the per-row UPDATE
carries `NOT EXISTS (active hold)` in its own WHERE clause, so a hold placed
*while* a sweep is running still wins.

Holds are released, never deleted — "was this ever held, and by whom?" is a
question asked after the hold is lifted. At most one hold may be active on a
receipt at a time, enforced by a partial unique index.

---

## Restoring from a backup

The one thing to know: **restore the whole `mod_intg` schema together, or
restore nothing.**

`inbox_receipts` is the deduplication ledger. Restoring the queue tables while
leaving the receipts behind — or restoring an older snapshot of the receipts —
resurrects every event in the gap as new. The provider will redeliver into that
gap, and each redelivery will look like a first delivery.

1. Restore as the owner role (`app_admin`). The online role cannot create a
   table, which is the contract working.
2. Run `python -m dotmac_integrator.migrate upgrade heads` — `heads` is plural,
   two lineages are composed, and never the bare `alembic` CLI (it resolves
   `version_locations` before `env.py` runs and exits 0 having applied nothing).
3. Verify `GET /health/ready` reports `schema_present`.
4. **Before starting workers**, reclaim leases: a restored snapshot contains
   `leased_until` values held by processes that no longer exist.
5. Expect a burst of duplicate redeliveries. That is the deduplication key doing
   its job; `receive_verified` returns `(existing, False)`.
6. If a restored receipt carries a redaction tombstone, it is a receipt whose
   content aged out legitimately. Do not treat it as corruption, and do not
   "repair" it by clearing the marker — that would put it back in the purge
   queue and change nothing else.
