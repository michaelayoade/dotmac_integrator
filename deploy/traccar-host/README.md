# Host-local Traccar Integrator profile

This profile runs the Traccar connector as a distinct `dotmac_integrator`
workload on the same physical host as ERP and Traccar. Co-location does not
merge identities: ERP never joins `dotmac_traccar_api`, never mounts these
secret files, and calls only the loopback-bound Integrator contract endpoint.

The released image must be built from this repository's reviewed committed lock.
The reviewed composition pins `dotmac-integration==0.1.0a20` and
`dotmac-connector-traccar==0.1.0a1`. Integration a20 publication is verified;
FreeRADIUS a1 is also artifact-verified, and the committed lock is reviewed.
Acceptance requires App record #941 merged, green recorded Starter main and
fresh full Integrator hosted CI. Supply the image by digest through
`INTEGRATOR_TRACCAR_IMAGE`; mutable tags are not an activation input.

## Runtime materials and typed parameters

`deploy/traccar-host/product.toml` is the authoritative deployment description
(`ProductDeploymentSpec.v1`), and its generated output is in
`deploy/traccar-host/rendered/`. `compose.yml` is a topology reference only, kept
for the external Traccar network and the host secret-file mounts that foundation
v0.2.0a2 cannot express; it is deleted at plan step P2.1, and a test holds it in
parity with the descriptor until then. The profile reads no environment file of
any kind: nothing an operator writes on the host supplies a value.

The descriptor splits values three ways:

- **Fixed values** are literals in `[roles.environment]`, never parameters:
  `ENVIRONMENT=production` (a missing value would skip the production checks),
  `INGRESS_ENABLED=false`, `SECRET_SCHEMES=file`, `SECRET_FILE_ROOT=/run/secrets`,
  `PRODUCT_PORT_ENABLED=false`, the query and contract-registry switches and the
  worker switch. The one published port is the loopback-bound contract endpoint.
- **Secret material is an OpenBao reference**, declared in `[runtime_materials]`
  by name only and resolved by the foundation at execution: `DATABASE_URL`,
  `MIGRATION_DATABASE_URL`, `BACKUP_DATABASE_URL`, `JWT_SECRET` and
  `METRICS_TOKEN`. The OpenBao reference for each is bound in the deployment UI;
  the one path already fixed is the Traccar service account,
  `secret/data/dotmac/traccar/erp-service`.
- **Everything else is a typed parameter entered in the deployment UI** at ship
  time: `DEPLOYMENT_ID`, `PLATFORM_ROOT_DOMAIN`, `PRODUCT_QUERY_CALLERS`,
  `PRODUCT_CONTRACT_REGISTRY_URL`, `PRODUCT_CONTRACT_REGISTRY_EXPECTED_DIGEST`,
  and the image `INTEGRATOR_TRACCAR_IMAGE` (an `image@sha256` digest).

**Activation fails closed.** Every material renders as `${NAME:?...}`, so any
unbound reference or unentered parameter stops the deploy before a container
starts. No material has a default.

## Secret projection

The host secret agent may read only
`secret/data/dotmac/traccar/erp-service`. Project its email and password fields
into the two files named by `TRACCAR_SERVICE_EMAIL_FILE` and
`TRACCAR_SERVICE_PASSWORD_FILE`. Project the independent ERP contract-registry
credential into `ERP_CONTRACT_REGISTRY_API_KEY_FILE`. All three host files must
be owned by the deployment operator and mode `0400`. They are projected
secret-agent files mounted read-only; the profile never reads them as
environment.

The Compose profile mounts each file as a read-only secret into the Integrator
API only. It does not pass an OpenBao token into the container. Configure the
Traccar installation's declared secret bindings with these references:

- `service_email`: `file:///run/secrets/traccar/service_email`
- `service_password`: `file:///run/secrets/traccar/service_password`

The non-secret connector URL is `http://traccar:8082`; the connector manifest,
not this generic host assembly, declares that provider egress boundary.

## Validate and render without activation

Run these from the repository root. They need no secret value and no host file:

```bash
dotmac-deploy -f deploy/traccar-host/product.toml validate
dotmac-deploy -f deploy/traccar-host/product.toml render --check \
  -o deploy/traccar-host/rendered --thresholds deploy/alerts/thresholds.json
docker compose -f deploy/traccar-host/compose.yml --profile traccar \
  config --no-interpolate
```

After a descriptor edit, regenerate with `render` (without `--check`) and commit
the result. The rendered files are generated; do not edit them.

Before any production `up`, verify all of the following:

- `dotmac_traccar_api` already exists and contains Traccar plus only the
  Integrator API from this profile;
- `dotmac_erp_app`, worker, and beat are absent from that network;
- the Integrator image reference contains `@sha256:` and matches the approved
  release evidence;
- `/api/devices` still reports zero real devices;
- Traccar `8082` and PostgreSQL `5432` have no public binding, while GPS103
  `5001` remains the only public tracker ingress;
- the ERP runtime has neither the two Traccar files nor permission to read the
  backing OpenBao path.

This profile is a descriptor only. Committing it does not create networks,
materialize secrets, configure a connector installation, or start containers.
