# Host-local Traccar Integrator profile

This profile runs the Traccar connector as a distinct `dotmac_integrator`
workload on the same physical host as ERP and Traccar. Co-location does not
merge identities: ERP never joins `dotmac_traccar_api`, never mounts these
secret files, and calls only the loopback-bound Integrator contract endpoint.

The released image must be built from this repository's committed lock, which
pins `dotmac-integration==0.1.0a18` and
`dotmac-connector-traccar==0.1.0a1`. Supply the image by digest through
`INTEGRATOR_TRACCAR_IMAGE`; mutable tags are not an activation input.

## Secret projection

The host secret agent may read only
`secret/data/dotmac/traccar/erp-service`. Project its email and password fields
into the two files named by `TRACCAR_SERVICE_EMAIL_FILE` and
`TRACCAR_SERVICE_PASSWORD_FILE`. Project the independent ERP contract-registry
credential into `ERP_CONTRACT_REGISTRY_API_KEY_FILE`. All three host files must
be owned by the deployment operator and mode `0400`.

The Compose profile mounts each file as a read-only secret into the Integrator
API only. It does not pass an OpenBao token into the container. Configure the
Traccar installation's declared secret bindings with these references:

- `service_email`: `file:///run/secrets/traccar/service_email`
- `service_password`: `file:///run/secrets/traccar/service_password`

The non-secret connector URL is `http://traccar:8082`; the connector manifest,
not this generic host assembly, declares that provider egress boundary.

## Render and verify without activation

```bash
docker compose --env-file /etc/dotmac/integrator-traccar.env \
  -f deploy/traccar-host/compose.yml --profile traccar config
```

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
