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
│
└─ NO  → endpoint from HTTP index URL field
         Set endpoint_source = "http_index_fallback"
```

### Custom SVCB Parameters (BANDAID v0.4.8)

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

### Crawler Pipeline

```
DNS/HTTP Discovery → AgentRecord → DiscoveredAgent → Repository → Database → API
     ↑                    ↑              ↑               ↑
  discoverer.py      models.py      base.py        repository.py
                                  submission.py    lambda_handler.py
```

---

## Database Schema

See `alembic/versions/` for migration history:
- `e2058c20b856` — Baseline schema (domains, agents, crawl_history)
- `2e439fab6e3b` — BANDAID v0.4.8 columns (cap_uri, cap_sha256, bap,
  policy_uri, realm, endpoint_source, capability_source)
