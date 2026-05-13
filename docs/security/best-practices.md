# Security Best Practices

dns-aid-core ships with **permissive defaults** so it works against the
real-world public internet, where DNSSEC adoption is partial, DANE TLSA is
rare, and mTLS is mostly internal. Every hardening below is **opt-in**.

This document is paired with [owasp-maestro-mapping.md](owasp-maestro-mapping.md),
which enumerates the OWASP MAESTRO threats each flag addresses.

## Operator personas

There are two operator roles that benefit from this document:

- **Publishing operators** — own the zone the agent records live under
- **Calling operators** — run the SDK that invokes agents

The two sides cooperate: a publisher signals what's mandatory via the SVCB
record; a caller decides how strict to be when consuming records.

## Publishing-side recommendations

If you operate the zone where agents are published, the following practices
maximize the trust signal callers can act on.

### Publish DNSSEC

Sign the zone hosting `_agents.{your-domain}`. Without DNSSEC, the SVCB and
DANE primitives below have no authenticated chain of trust — a recursive
resolver between the caller and your zone could substitute records freely.
Mitigates OWASP MAESTRO **T37** (Agent Registry Poisoning) and **T9** (Identity
Spoofing).

### Publish DANE TLSA records

For each agent endpoint, publish a `TLSA` record at `_{port}._tcp.{target}`.
Selector `1` (SubjectPublicKeyInfo) + matching type `1` (SHA-256) is the
common shape. This binds the runtime TLS certificate to the DNS-published
key fingerprint, defeating attackers who have a valid WebPKI cert for the
hostname. Mitigates OWASP MAESTRO **T47** (Rogue Server) and **T7.1**
(Agent Impersonation).

### Declare `mandatory=` for keys that matter

Per RFC 9460 §8, listing a SvcParamKey in `mandatory=` means clients that
don't implement it MUST skip the record. dns-aid-core enforces this on the
consumption side: if any key you list is unknown to the client SDK, the
record is discarded with a structured warning. Use this to fail closed:

```text
chat._mcp._agents.example.com. SVCB 1 svc.example.com.
    alpn="mcp" port=443
    cap="https://example.com/cap/chat-v1.json"
    cap-sha256="..."
    mandatory="alpn,port,cap-sha256"
```

A caller that doesn't understand `cap-sha256` will refuse to use this record
rather than silently downgrading. Mitigates **T7.6** (Fallback Downgrade).

### Set a realistic TTL

The SDK's freshness re-verification (see caller side below) re-resolves
records older than the configured budget. If you operate a high-churn zone,
keep TTLs short and the caller's freshness budget short. If your records are
stable, longer TTLs reduce DNS load.

### Sign records (`sig=`) when DNSSEC isn't available

The `sig=` SvcParamKey carries a JWS-signed payload that validates the
record independently of DNSSEC. Useful for zones that haven't enabled
DNSSEC yet. Keys are published at `/.well-known/dns-aid-jwks.json`.

## Calling-side recommendations

The SDKConfig flags below control how strictly the SDK enforces the
substrate's trust claims at invocation time.

### Threat-to-flag matrix

| MAESTRO threat | What it is | Flag |
|---|---|---|
| **T47 / T7.1 / T9** — Rogue server / impersonation | Endpoint serves a cert that doesn't match the DNS-published key | `prefer_dane=True` (try DANE) or `require_dane=True` (refuse when TLSA absent) |
| **T37** — Registry poisoning | Caller accepts unsigned / bogus DNS answers | `require_dnssec=True` |
| **BV-9** — TOCTOU verify→invoke | Record changes between discovery and use | `verify_freshness_seconds=N` |
| **BV-2** — Tool description poisoning (rug pull) | Publisher rotates cap-doc after trust established | `verify_freshness_seconds=N` (the same freshness check compares cap_sha256 and detects rotation) |

### Recommended profiles

**Default (permissive — matches today's behavior)**

```python
from dns_aid.sdk import SDKConfig
config = SDKConfig()  # all hardening off
```

Use when callers are on the public internet and zones aren't guaranteed to
have DNSSEC or DANE deployed. The substrate still verifies what it can; you
just don't refuse on what isn't there.

**Standard hardening — opportunistic when present, no fail-closed**

```python
config = SDKConfig(
    prefer_dane=True,           # use TLSA when it's there; WebPKI fallback otherwise
    verify_freshness_seconds=300,  # re-verify discoveries older than 5 minutes
)
```

Use for production callers where the cost of the extra DNS lookup is
acceptable. TLSA-publishing zones get the cert-pinning benefit; legacy zones
keep working.

**Strict hardening — for high-assurance deployments**

```python
config = SDKConfig(
    require_dane=True,          # refuse endpoints without TLSA
    require_dnssec=True,        # refuse unsigned / bogus answers
    verify_freshness_seconds=60,
)
```

Use only when you control or trust the zones you're calling AND those zones
are committed to DNSSEC + DANE. This will refuse to invoke a large portion
of the public internet, which is the point.

## Environment variables

All `SDKConfig` flags above can be set via environment variable for
deployments where the calling process is launched by an orchestrator and
doesn't construct the config directly:

| Variable | Type | Purpose |
|---|---|---|
| `DNS_AID_PREFER_DANE` | bool | Prefer DANE when TLSA is present |
| `DNS_AID_REQUIRE_DANE` | bool | Refuse when TLSA is absent |
| `DNS_AID_REQUIRE_DNSSEC` | bool | Refuse on bogus / unsigned answers |
| `DNS_AID_VERIFY_FRESHNESS_SECONDS` | int | Re-verify stale discoveries |

## Operational hygiene

- **Backend credentials**: never log them, never check them into version
  control, prefer per-environment vault-mounted secrets. dns-aid-core's
  publisher abstractions accept credentials at construction time and do not
  emit them in any log or telemetry field. (Mitigates **T22** — Service
  Account Exposure.)
- **HSM/TPM where supported**: for high-assurance publishers, generate the
  signing key in an HSM or TPM. The dns-aid-core publisher does not enforce
  HSM use today; it's a deployment decision.
- **Network exposure**: registrar / publisher services should be reachable
  only from the corp network or a hardened ingress, not the public internet.
- **Log redaction**: when shipping telemetry to an external sink, validate
  that nothing in the auth handlers' headers (Bearer tokens, API keys) is
  serialized.

## Mapping to canonical sources

See [owasp-maestro-mapping.md](owasp-maestro-mapping.md) for the full
threat-by-threat status across T1-T47 + BV-1 through BV-12.

The threat-model authors whose work this builds on are cited there.
