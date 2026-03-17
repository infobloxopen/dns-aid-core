# Provider Publishers

DNS-AID includes a provider-managed publishing layer for environments where agent endpoints are created by a cloud control plane rather than by the agent process itself.

The publisher APIs live under `dns_aid.sdk.publishers` and revolve around a shared async interface:

```python
from dns_aid.sdk.publishers import AgentRecordPublisher

await publisher.publish(service)
await publisher.unpublish(service)
await publisher.sync()
```

## Components

- `AppHubPublisher` publishes `_agents` records for AppHub discovered services into Google Cloud DNS.
- `LatticePublisher` publishes `_agents` records for VPC Lattice services into Infoblox NIOS.
- `DiscoveryValidationHarness` performs a bootstrap flow using only the published DNS records.

## Installation

Install the optional dependencies needed for the provider you are using:

```bash
pip install -e ".[cloud-dns,apphub]"
pip install -e ".[nios,publishers]"
```

## AppHub Publisher

`AppHubPublisher` reconciles AppHub discovered services with `functionalType=AGENT` into a private `_agents` zone in Cloud DNS.

Published SVCB fields:

- `connect-class=apphub-psc`
- `connect-meta=<AppHub canonical service name or discovered service fallback>`
- `enroll-uri=<psc-base-url>/.well-known/agent-connect`

Capabilities are read from AppHub extended metadata when present. Missing capability metadata does not block publishing.

### Environment

```bash
export GOOGLE_CLOUD_PROJECT="my-project"
export APPHUB_LOCATION="us-central1"
export APPHUB_DOMAIN="corp.internal"
export CLOUD_DNS_MANAGED_ZONE="agents-private"
```

Optional metadata overrides:

```bash
export APPHUB_CAPABILITIES_METADATA_KEY="apphub.googleapis.com/agentProperties"
export APPHUB_CAPABILITIES_METADATA_PATH="a2a.capabilities"
export APPHUB_SERVICE_NAME_METADATA_KEY="apphub.googleapis.com/agentProperties"
export APPHUB_SERVICE_NAME_METADATA_PATH="serviceName"
export APPHUB_CONNECT_META_METADATA_KEY="apphub.googleapis.com/agentConnect"
export APPHUB_CONNECT_META_METADATA_PATH="serviceName"
export APPHUB_ENROLLMENT_METADATA_KEY="apphub.googleapis.com/agentConnect"
export APPHUB_ENROLLMENT_METADATA_PATH="pscBaseUrl"
```

### Running

Run a single reconciliation cycle:

```bash
python -m dns_aid.sdk.publishers.apphub
```

Set `APPHUB_RUN_FOREVER=1` to keep polling with `APPHUB_POLL_INTERVAL_SECONDS`.

## VPC Lattice Publisher

`LatticePublisher` reconciles VPC Lattice services into Infoblox NIOS instead of Route 53. Route 53 does not support the private-use SVCB keys DNS-AID needs for `connect-class`, `connect-meta`, and `enroll-uri`.

Published SVCB fields:

- `connect-class=lattice`
- `connect-meta=<VPC Lattice service ARN>`
- `enroll-uri=https://<service-fqdn>/.well-known/agent-connect`

TTL behavior:

- `300` seconds when the service has a truthy stable tag
- `30` seconds otherwise

### Environment

```bash
export LATTICE_DOMAIN="corp.internal"
export LATTICE_PROTOCOL="mcp"
export LATTICE_STABLE_TAG_KEY="stable"
export NIOS_HOST="nios.example.com"
export NIOS_USERNAME="admin"
export NIOS_PASSWORD="secret"
```

### Running

Startup reconcile:

```bash
python -m dns_aid.sdk.publishers.lattice
```

EventBridge / CloudTrail event handling:

```bash
cat event.json | python -m dns_aid.sdk.publishers.lattice
```

The handler accepts `CreateService`, `UpdateService`, `DeleteService`, `TagResource`, and `UntagResource` events. Startup always performs a full reconcile so drift is corrected even if an event was missed.

### DNS Prerequisite

If workloads resolve the private agent zone from Route 53, Route 53 Resolver forwarding must send that zone to the authoritative NIOS infrastructure. Without that forwarding path, the Lattice-published `_agents` records will exist in NIOS but will not resolve inside the VPCs that need them.

## Discovery Harness

`DiscoveryValidationHarness` exercises the bootstrap path using only published DNS records:

- AppHub path: resolve `_agents.<domain>`, read `connect-class=apphub-psc`, call `enroll-uri`, validate `connect-meta`.
- Lattice path: resolve `_agents.<domain>`, read `connect-class=lattice`, call `enroll-uri`, and verify the ARN in `connect-meta` via the supplied Lattice lookup callback.

This repo includes hermetic tests for both paths using generated zone data and mocks. Real cloud validation remains an environment-specific workflow because it requires enabled AppHub, Cloud DNS, VPC Lattice, and NIOS infrastructure.
