# DNS-AID Architecture

## Overview

DNS-AID implements the IETF draft-mozleywilliams-dnsop-bandaid-02 protocol for
DNS-based agent discovery. This document covers the key architectural decisions.

---

## Metadata Resolution Strategy

Agent metadata is resolved through a **priority-based strategy** aligned with
the BANDAID specification. Understanding this hierarchy is critical — it
explains why certain fields (description, use_cases, category) may appear as
`null` in the directory even when they exist in DNS TXT records.

### The Three Metadata Sources

| Source | Data Format | Rich Metadata | Authority Level |
|--------|-------------|---------------|-----------------|
| **Cap URI** (SVCB `cap=` param) | JSON document at URI | Full (description, use_cases, category, capabilities, version) | Authoritative |
| **HTTP Index** (`/.well-known/agent-index.json`) | JSON document | Full | Authoritative |
| **TXT Record** (`capabilities=...`) | Key-value strings | Minimal (capabilities + version only) | Fallback |

### Resolution Priority

```
Agent discovered via SVCB record
│
├─ SVCB has cap= parameter?
│  YES → Fetch capability document from cap URI
│        Parse: capabilities, version, description, use_cases, category
│        Set capability_source = "cap_uri"
│
├─ cap URI missing or fetch failed?
│  → Query TXT record for capabilities= field
│    Parse: capabilities only
│    Set capability_source = "txt_fallback"
│
└─ No TXT record either?
   → capabilities = [], capability_source = "none"
```

### Why TXT Records Don't Carry Rich Metadata

The `dns-aid publish` CLI writes description, use_cases, and category to the
TXT record for **human readability** (useful when running `dig TXT`). However,
the discoverer intentionally does NOT parse those fields from TXT because:

1. **BANDAID spec compliance** — The draft specifies that rich metadata should
   come from the capability document (cap URI) or HTTP index, not TXT records.
   TXT records are a lightweight fallback for basic capabilities only.

2. **DNS size constraints** — TXT records have practical size limits (~255 bytes
   per string, ~4KB total). Capability documents have no such limitation and
   can carry arbitrarily rich metadata.

3. **Structured vs. flat data** — A JSON capability document can represent
   nested structures (use_cases as arrays, descriptions with formatting).
   TXT key-value pairs cannot.

### Endpoint Source Tracking

Similarly, the endpoint URL source is tracked:

```
SVCB record found?
├─ YES → endpoint from SVCB target + port
│        Set endpoint_source = "dns_svcb"
│        │
│        └─ .well-known/agent.json has endpoints.{protocol}?
│           YES → append path to endpoint
│                 Set endpoint_source = "dns_svcb_enriched"
│
├─ HTTP index has endpoint with path?
│  YES → use HTTP index endpoint
│        Set endpoint_source = "http_index"
│
└─ NO  → endpoint from HTTP index URL field
         Set endpoint_source = "http_index_fallback"
```

### Custom SVCB Parameters (BANDAID)

The BANDAID draft defines custom SVCB parameters:

| Parameter | SVCB Key | Purpose |
|-----------|----------|---------|
| `cap` | `cap_uri` | URI to capability descriptor document |
| `capsha256` | `cap_sha256` | Integrity hash of capability document |
| `bap` | `bap` | BANDAID Application Protocols (e.g., `mcp,a2a`) |
| `policy` | `policy_uri` | URI to agent policy document |
| `realm` | `realm` | Multi-tenant scope / authorization realm |

**Note:** AWS Route 53 does not currently support custom SVCB parameter names.
These must be encoded using the RFC 9460 generic `keyNNNNN` wire format for
Route 53 compatibility. This is tracked as a known interoperability issue.

---

## Discovery Modes

### Pure DNS Discovery

```
1. Query TXT _index._agents.{domain} → list of agent:protocol pairs
2. For each agent: Query SVCB _{name}._{protocol}._agents.{domain}
   → extract endpoint, port, ALPN + BANDAID custom params (cap, bap, policy, realm)
3. For each agent: If cap URI present → fetch capability document (primary)
   → capabilities, version, description, use_cases, category
4. For each agent: If no cap URI or fetch failed → query TXT for capabilities= (fallback)
```

### HTTP Index Discovery

```
1. Fetch GET https://{domain}/.well-known/agent-index.json
2. Parse JSON → extract agents with full metadata
3. For each agent: Verify SVCB record exists in DNS
   - Found → endpoint_source = "dns_svcb" (authoritative)
   - Not found → endpoint_source = "http_index_fallback"
```

### Future Enhancement: HTTP Index Fallback in DNS Mode

Currently the two discovery modes are independent — pure DNS never consults the
HTTP index and vice versa. Per the BANDAID draft, the HTTP well-known endpoint
is a complementary discovery mechanism. A future enhancement should add an
HTTP index fallback to the DNS discovery path:

```
(after step 4 in Pure DNS Discovery)
5. If no cap URI and TXT provided only basic capabilities →
   fetch /.well-known/agent-index.json as metadata enrichment
   → backfill description, use_cases, category from HTTP index
   Set capability_source = "http_index_enrichment"
```

This would allow DNS-discovered agents to get rich metadata even when their
SVCB records lack a `cap` parameter, without requiring a full switch to HTTP
Index Discovery mode.

---

## Tier 1: Execution Telemetry SDK

The SDK wraps agent invocations with telemetry capture, enabling performance
monitoring, agent ranking, community-wide ranking queries, and observability export.

### SDK Architecture

```
AgentClient.invoke(agent, method, arguments)
│
├─ ProtocolHandler (MCP / A2A / HTTPS)
│  └─ httpx.AsyncClient → agent endpoint
│     └─ Measures: latency, TTFB, status, cost headers, TLS version
│
├─ SignalCollector (in-memory)
│  └─ Records InvocationSignal per call
│  └─ Computes per-agent scorecards
│
├─ SignalStore (optional, PostgreSQL)
│  └─ Persists signals when persist_signals=True
│
├─ AgentRanker
│  └─ Weighted composite: 40% reliability + 30% latency + 15% cost + 15% freshness
│  └─ Pluggable strategies (LatencyFirst, ReliabilityFirst, WeightedComposite)
│
└─ TelemetryManager (optional, OpenTelemetry)
   └─ Spans: dns-aid.invoke with agent/protocol/status attributes
   └─ Metrics: duration histogram, count/error counters, cost counter
```

### Signal Flow

```
dns_aid.invoke(agent)
    → AgentClient.invoke()
        → ProtocolHandler.invoke() → RawResponse (timing + status)
        → SignalCollector.record() → InvocationSignal (enriched)
        → SignalStore.save()       → PostgreSQL (if persist_signals=True)
        → HTTP Push (thread)       → POST to telemetry API (if http_push_url set)
        → TelemetryManager.emit() → OTEL span + metrics (if otel_enabled=True)
    → InvocationResult (data + signal)
```

### HTTP Telemetry Push (Optional)

The SDK can optionally push telemetry signals to an external collection endpoint via `http_push_url`:

```
SDK invoke() → InvocationSignal
     │
     └─ HTTP POST (daemon thread) → configured http_push_url
```

**Key design decisions:**
- Uses `threading.Thread` with `daemon=True` for true fire-and-forget (survives event loop teardown)
- POST runs in background thread to avoid blocking invoke() calls
- Failures are logged but never raise exceptions
- Disabled by default (`http_push_url=None`); configure via `SDKConfig` or `DNS_AID_SDK_HTTP_PUSH_URL` env var

### Protocol Handlers

| Protocol | Handler | Transport | Method Mapping |
|----------|---------|-----------|----------------|
| MCP | `MCPProtocolHandler` | JSON-RPC 2.0 / HTTPS | `tools/list`, `tools/call` |
| A2A | `A2AProtocolHandler` | JSON-RPC 2.0 / HTTPS | `tasks/send`, `tasks/get` |
| HTTPS | `HTTPSProtocolHandler` | REST / HTTPS | Method appended to URL path |

### Endpoint Path Resolution

DNS SVCB records provide host + port but no HTTP path. The discoverer now
enriches endpoints by fetching `.well-known/agent.json` from each agent's
target host:

```
DNS SVCB → booking.example.com:443    (host + port)
.well-known/agent.json → endpoints.mcp = "/mcp"
Result → https://booking.example.com:443/mcp
         endpoint_source = "dns_svcb_enriched"
```

Enrichment runs concurrently for all discovered agents, deduplicates by host,
and gracefully skips hosts that don't serve `.well-known/agent.json`.

---

## Community Rankings (Optional)

The SDK can fetch community-wide telemetry rankings when a telemetry API is configured:

```
AgentClient.fetch_rankings(fqdns, limit)
    │
    └─ GET {telemetry_api_url}/rankings
       │
       └─ Returns pre-computed composite scores based on aggregated telemetry
```

This enables orchestrators to select agents based on community-observed
reliability and latency, not just cost. Requires `telemetry_api_url` to be
configured in `SDKConfig`.

### LangGraph Integration Pattern

The following LangGraph pattern illustrates how competitive agent selection could work (conceptual — no built-in LangGraph integration is shipped with dns-aid-core):

```
┌──────────┐   ┌────────────┐   ┌────────┐   ┌────────┐   ┌────────┐
│ discover │──▶│fetch_costs │──▶│  rank  │──▶│ select │──▶│ invoke │
│(DNS-AID) │   │(tools/list)│   │(telem.)│   │ (best) │   │        │
└──────────┘   └────────────┘   └────────┘   └────────┘   └────────┘
```

This pattern can be implemented with any orchestrator (LangGraph, LangChain, custom).

---

## JWS Signature Verification

DNS-AID provides application-layer signature verification as an alternative to
DNSSEC for environments where DNSSEC cannot be enabled.

### Problem

DNSSEC adoption is ~30% globally. Many enterprises can't enable DNSSEC due to:
- Legacy DNS infrastructure
- Split-horizon DNS configurations
- Managed DNS providers without DNSSEC support

### Solution: JWS (JSON Web Signature)

Publishers sign DNS record content with a private key. Discoverers verify using
a public key fetched from `.well-known/dns-aid-jwks.json`.

```
┌─────────────────────────────────────────────────────────────────┐
│                        PUBLISHER                                │
│                                                                 │
│  1. Generate EC P-256 keypair (once)                           │
│     └─ dns-aid keys generate --output ./keys/                  │
│                                                                 │
│  2. Publish JWKS to web server                                 │
│     └─ https://example.com/.well-known/dns-aid-jwks.json       │
│                                                                 │
│  3. Sign record payload when publishing                        │
│     └─ dns-aid publish --sign --private-key ./keys/private.pem │
│                                                                 │
│  4. SVCB record includes sig= parameter                        │
│     └─ SVCB 1 target. alpn="mcp" port=443 sig="eyJhbGci..."   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DISCOVERER                                │
│                                                                 │
│  1. Query SVCB record                                          │
│     └─ Extract sig= parameter                                  │
│                                                                 │
│  2. Fetch JWKS from domain                                     │
│     └─ GET https://example.com/.well-known/dns-aid-jwks.json   │
│                                                                 │
│  3. Verify JWS signature against public key                    │
│     └─ Check: algorithm, expiration, payload integrity         │
│                                                                 │
│  4. Result                                                     │
│     └─ Valid? Trust record                                     │
│     └─ Invalid? Reject or warn                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Signed Payload Structure

The JWS payload contains the canonical representation of the DNS record:

```json
{
  "fqdn": "_payment._mcp._agents.example.com",
  "target": "payment.example.com",
  "port": 443,
  "alpn": "mcp",
  "iat": 1704067200,
  "exp": 1704153600
}
```

### JWKS Document Format

```json
// GET https://example.com/.well-known/dns-aid-jwks.json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "dns-aid-2024",
      "use": "sig",
      "x": "base64url-encoded-x-coordinate",
      "y": "base64url-encoded-y-coordinate"
    }
  ]
}
```

### Verification Priority

```
┌─────────────────────────────────────────────────┐
│            Verification Decision Tree           │
├─────────────────────────────────────────────────┤
│                                                 │
│  DNSSEC available and valid?                    │
│  ├─ YES → Trust (strongest, chain to DNS root) │
│  │                                              │
│  └─ NO → JWS sig= present in SVCB?             │
│          ├─ YES → Fetch JWKS, verify signature │
│          │        ├─ Valid → Trust             │
│          │        └─ Invalid → Reject/Warn     │
│          │                                      │
│          └─ NO → No verification available     │
│                  ├─ Strict mode → Reject       │
│                  └─ Default → Warn but allow   │
└─────────────────────────────────────────────────┘
```

### Usage: Three Interfaces

**Python Library:**
```python
from dns_aid.core.jwks import generate_keypair, export_jwks, sign_record
from dns_aid import publish, discover

# Generate keys
private_key, public_key = generate_keypair()
jwks_json = export_jwks(public_key, kid="dns-aid-2024")

# Publish with signature
await publish(
    name="payment",
    domain="example.com",
    protocol="mcp",
    endpoint="payment.example.com",
    sign=True,
    private_key_path="./keys/private.pem",
)

# Discover with verification
agents = await discover("example.com", verify_signatures=True)
```

**CLI:**
```bash
# Generate keypair
dns-aid keys generate --output ./keys/

# Export JWKS (host at .well-known/dns-aid-jwks.json)
dns-aid keys export-jwks --key ./keys/public.pem --output jwks.json

# Publish with signature
dns-aid publish payment example.com mcp payment.example.com \
    --sign --private-key ./keys/private.pem

# Discover with verification
dns-aid discover example.com --verify-signatures
```

**MCP Server:**
```json
// Tools available via MCP
{
  "name": "publish_agent_to_dns",
  "arguments": {
    "name": "payment",
    "domain": "example.com",
    "sign": true,
    "private_key_path": "./keys/private.pem"
  }
}
```

### Security Model

| Component | Trust Source |
|-----------|--------------|
| Private key | Publisher keeps secret |
| Public key (JWKS) | HTTPS certificate of domain |
| Signature validity | Cryptographic verification (ES256) |

**Trust anchor**: If you trust `https://example.com` (valid TLS cert), you trust
their JWKS, and therefore their signed DNS records.

This is weaker than DNSSEC (which has cryptographic chain to DNS root) but
significantly easier to deploy for organizations without DNSSEC capability.

---

## Backend API: get_record() Method

All DNS backends now implement `get_record()` for direct API-based record lookup:

```python
async def get_record(
    self,
    zone: str,
    name: str,
    record_type: str,
) -> dict | None:
    """
    Get a specific DNS record by querying the backend API directly.

    Returns:
        Record dict with name, fqdn, type, ttl, values if found, None otherwise
    """
```

### Implementation by Backend

| Backend | Method |
|---------|--------|
| Route53 | `list_resource_record_sets` API with StartRecordName filter |
| Cloudflare | `/zones/{id}/dns_records` API with name+type filter |
| Infoblox BloxOne | `/dns/record` API with `_filter` parameter |
| DDNS | DNS query to configured server (not public resolver) |
| Mock | In-memory dict lookup |

This enables reliable reconciliation state-checking without depending on
public DNS resolver support for SVCB records.
