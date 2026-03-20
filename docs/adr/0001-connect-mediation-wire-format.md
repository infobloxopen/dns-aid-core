# ADR 0001: Connection Mediation Wire Format

## Status

Accepted

## Date

2026-03-19

## Context

DNS-AID needs to publish connection-mediation metadata for internal service meshes
and managed-enrollment flows such as AWS VPC Lattice and GCP AppHub PSC.

The proposed wire shape adds three private-use SVCB parameters:

- `connect-class`
- `connect-meta`
- `enroll-uri`

This introduces a protocol-level compatibility question:

- some authoritative DNS systems can store private-use SVCB keys natively
- some public-cloud DNS backends cannot
- once published, changing the wire shape requires record republishing and
  discoverer/parser coordination

The project also needs an explicit scope decision on whether internal-first
deployment targets are acceptable for this feature.

## Decision

DNS-AID will keep `connect-class`, `connect-meta`, and `enroll-uri` as
first-class DNS-AID SVCB parameters.

This decision carries the following constraints:

1. The target deployment model for these keys is internal-first.
   `connect-*` publishing is allowed to rely on authoritative backends that can
   store private-use SVCB parameters natively, specifically Infoblox NIOS and
   Google Cloud DNS.
2. Route 53 and Cloudflare are not required to support the `connect-*` keys in
   the first release of this feature.
3. The provider-runtime work may proceed in `dns-aid-core`, but protocol and
   backend changes must remain reviewable separately from cloud orchestration.
4. Introducing the new private-use keys requires a documented record migration:
   zones adopting this feature must republish affected records so the new
   `key65406`, `key65407`, and `key65408` values appear on the wire.
5. The next release that ships these keys must include an explicit version bump
   and release-note language calling out:
   - the new DNS wire parameters
   - internal/backend support expectations
   - the republish requirement for adopters

## Consequences

### Positive

- keeps mediation data in DNS where the discoverer already expects transport and
  endpoint metadata
- avoids introducing a second pointer document just to recover information that
  is small, routing-critical, and needed before connection bootstrap
- matches the current implementation shape and existing provider test coverage

### Negative

- backend interoperability is intentionally narrower than the rest of DNS-AID
- public-cloud DNS support remains uneven until those providers support
  private-use SVCB keys or DNS-AID adds an alternate representation
- release management must treat these keys as a protocol-visible change

## Follow-up Requirements

- keep the parser and serializer logic quoted-string safe
- document the backend support matrix anywhere the new keys are advertised
- ensure provider PRs link back to this ADR when adding new `connect-*`
  behavior
