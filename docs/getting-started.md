# Getting Started with DNS-AID

This guide will walk you through installing, configuring, and testing DNS-AID.

> **Version 0.6.0** - Adds DNSSEC enforcement (`require_dnssec=True`), DANE full certificate matching (`verify_dane_cert=True`), Sigstore release signing, Route53/Cloudflare SVCB custom param demotion to TXT, and environment variable documentation.

## Prerequisites

- Python 3.11 or higher
- One of the following DNS backends:
  - **Cloudflare** (recommended for beginners - free tier available)
  - AWS account with Route 53 access
  - Infoblox UDDI account with API key
  - Any RFC 2136 compliant DNS server (BIND, Windows DNS, PowerDNS, etc.)
- A domain with a hosted zone in your DNS provider

## Installation

### Option 1: Install from source (recommended for testing)

```bash
# Clone the repository
git clone https://github.com/infobloxopen/dns-aid-core.git
cd dns-aid

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with all dependencies
pip install -e ".[all]"
```

### Option 2: Install specific components

```bash
pip install -e "."              # Core library only
pip install -e ".[cli]"         # Core + CLI
pip install -e ".[mcp]"         # Core + MCP server
pip install -e ".[route53]"     # Core + Route 53 backend
pip install -e ".[cloudflare]"  # Core + Cloudflare backend
pip install -e ".[infoblox]"    # Core + Infoblox BloxOne backend
pip install -e ".[ddns]"        # Core + RFC 2136 Dynamic DNS backend
```

## Quick Test (No AWS needed)

Test with the mock backend:

```bash
# Run unit tests
pytest tests/unit/ -v

# Test CLI help
dns-aid --help

# Test MCP server help
dns-aid-mcp --help
```

## AWS Route 53 Setup

### 1. Configure AWS Credentials

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

Or use AWS CLI:
```bash
aws configure
```

### 2. Verify Zone Access

```bash
dns-aid zones
```

Expected output:
```
Available DNS zones (route53):

┌─────────────────────────────┬────────────────┬─────────┬────────┐
│ Domain                      │ Zone ID        │ Records │ Type   │
├─────────────────────────────┼────────────────┼─────────┼────────┤
│ yourdomain.com              │ Z1234567890ABC │ 5       │ Public │
└─────────────────────────────┴────────────────┴─────────┴────────┘
```

### 3. Set Test Zone

```bash
export DNS_AID_TEST_ZONE="yourdomain.com"
```

## Infoblox UDDI Setup

Infoblox UDDI is Infoblox's cloud-native DDI platform. Follow these steps to configure DNS-AID with Infoblox UDDI.

### 1. Get Your API Key

1. Log in to [Infoblox Cloud Portal](https://csp.infoblox.com)
2. Navigate to **Administration** → **API Keys**
3. Click **Create API Key**
4. Select appropriate permissions (DNS read/write)
5. Copy the API key (it's only shown once!)

### 2. Configure Environment Variables

```bash
# Required: Your Infoblox UDDI API key
export INFOBLOX_API_KEY="your-api-key-here"

# Optional: DNS view name (default: "default")
export INFOBLOX_DNS_VIEW="default"

# Optional: Custom API URL (rarely needed)
# export INFOBLOX_BASE_URL="https://csp.infoblox.com"
```

### 3. Identify Your Zone and View

In the Infoblox Portal:
1. Go to **DNS** → **Authoritative Zones**
2. Find your zone (e.g., `example.com`)
3. Note which **DNS View** it belongs to (visible in the zone details)

> **Important**: Zones exist within DNS Views. If your zone is in a view other than
> "default", you must set `INFOBLOX_DNS_VIEW` to match.

### 4. Set Test Zone

```bash
export INFOBLOX_TEST_ZONE="your-zone.com"
```

### 5. Verify Connection (Python)

```python
import asyncio
from dns_aid.backends.infoblox import InfobloxBloxOneBackend

async def verify_connection():
    backend = InfobloxBloxOneBackend()

    # List zones to verify API access
    zones = await backend.list_zones()
    print(f"Found {len(zones)} zones:")
    for zone in zones[:5]:  # Show first 5
        print(f"  - {zone['name']}")

    # Check if your test zone exists
    exists = await backend.zone_exists("your-zone.com")
    print(f"\nTest zone exists: {exists}")

    await backend.close()

asyncio.run(verify_connection())
```

### Infoblox UDDI Limitations & BANDAID Compliance

> **⚠️ Important**: Infoblox UDDI is **not fully compliant** with the
> [BANDAID draft](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-bandaid/).
>
> Infoblox UDDI SVCB only supports "alias mode" (priority 0) and lacks support for required
> SVC parameters (`alpn`, `port`, `mandatory`). The BANDAID draft requires ServiceMode
> SVCB records (priority > 0) with these parameters.
>
> **For full compliance, use Route 53 or another RFC 9460-compliant provider.**
>
> DNS-AID stores `alpn` and `port` in TXT records as a fallback, but this is a
> workaround, not a standard-compliant solution.

### Verifying Records

Since Infoblox UDDI zones may be private (not publicly resolvable), verify records via API instead of `dig`:

```python
async with InfobloxBloxOneBackend() as backend:
    async for record in backend.list_records("your-zone.com"):
        if "_agents" in record["fqdn"]:
            print(f"{record['type']}: {record['fqdn']}")
```

## DDNS Setup (RFC 2136)

DDNS (Dynamic DNS) works with any DNS server supporting RFC 2136, including BIND9, Windows DNS, PowerDNS, and Knot DNS. This is ideal for on-premise infrastructure without vendor-specific APIs.

### 1. Create a TSIG Key

On your DNS server (BIND9 example):

```bash
# Generate a TSIG key
tsig-keygen -a hmac-sha256 dns-aid-key > /etc/bind/dns-aid-key.conf
```

This creates a key file like:
```
key "dns-aid-key" {
    algorithm hmac-sha256;
    secret "YourBase64SecretHere==";
};
```

### 2. Configure Your DNS Zone

Add the key to your zone configuration:

```
include "/etc/bind/dns-aid-key.conf";

zone "example.com" {
    type master;
    file "/var/lib/bind/example.com.zone";
    allow-update { key "dns-aid-key"; };
};
```

### 3. Configure Environment Variables

```bash
# Required
export DDNS_SERVER="ns1.example.com"
export DDNS_KEY_NAME="dns-aid-key"
export DDNS_KEY_SECRET="YourBase64SecretHere=="

# Optional
export DDNS_KEY_ALGORITHM="hmac-sha256"  # default
export DDNS_PORT="53"                     # default
```

### 4. Set Test Zone

```bash
export DNS_AID_TEST_ZONE="example.com"
```

### 5. Verify Connection (Python)

```python
import asyncio
from dns_aid.backends.ddns import DDNSBackend

async def verify_connection():
    backend = DDNSBackend()

    # Check if zone exists
    exists = await backend.zone_exists("example.com")
    print(f"Zone exists: {exists}")

asyncio.run(verify_connection())
```

### DDNS Advantages

- **Universal**: Works with BIND, Windows DNS, PowerDNS, Knot, and any RFC 2136 server
- **Full BANDAID compliance**: Supports ServiceMode SVCB with all parameters
- **No vendor lock-in**: Standard protocol, no proprietary APIs
- **On-premise friendly**: Perfect for enterprise internal DNS

### DDNS Troubleshooting

#### "TSIG key not configured" error
- Ensure `DDNS_KEY_NAME` and `DDNS_KEY_SECRET` are set
- Check the key secret is base64 encoded

#### "DDNS update failed: NOTAUTH"
- The zone doesn't permit updates with your key
- Check `allow-update` in your zone configuration

#### "DDNS update failed: REFUSED"
- DNS server refused the update
- Verify TSIG key name and secret match the server configuration

#### Connection timeout
- Check firewall rules allow TCP/UDP port 53 (or your configured port)
- Verify the DNS server is reachable: `dig @ns1.example.com example.com SOA`

## Cloudflare Setup (Recommended for Beginners)

Cloudflare is the easiest way to get started with DNS-AID thanks to its free tier and simple API. Perfect for demos, workshops, and quick prototyping.

### 1. Add Your Domain to Cloudflare

If you don't already have a domain on Cloudflare:

1. Log into [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Click **"Add a Site"**
3. Enter your domain name
4. Select **Free plan**
5. Cloudflare will scan your existing DNS records
6. Update your domain's nameservers to the ones Cloudflare provides

### 2. Create an API Token

1. Go to **My Profile** → **API Tokens** → **Create Token**
2. Use the **"Edit zone DNS"** template, or create custom with:
   - **Permissions**: Zone → DNS → Edit
   - **Zone Resources**: Include → Specific zone → your-domain.com
3. Click **Continue to Summary** → **Create Token**
4. **Copy the token immediately** (shown only once!)

### 3. Configure Environment Variables

```bash
# Required: Your Cloudflare API token
export CLOUDFLARE_API_TOKEN="your-api-token-here"

# Optional: Zone ID (auto-discovered from domain if not set)
# export CLOUDFLARE_ZONE_ID="your-zone-id"
```

### 4. Set Test Zone

```bash
export DNS_AID_TEST_ZONE="your-domain.com"
```

### 5. Verify Connection (Python)

```python
import asyncio
from dns_aid.backends.cloudflare import CloudflareBackend

async def verify_connection():
    backend = CloudflareBackend()

    # List zones to verify API access
    zones = await backend.list_zones()
    print(f"Found {len(zones)} zones:")
    for zone in zones:
        print(f"  - {zone['name']} (Status: {zone['status']})")

    await backend.close()

asyncio.run(verify_connection())
```

### 6. Quick CLI Test

```bash
# Publish a test agent (auto-creates index)
dns-aid publish \
    --name test-agent \
    --domain $DNS_AID_TEST_ZONE \
    --protocol mcp \
    --endpoint mcp.$DNS_AID_TEST_ZONE \
    --backend cloudflare

# Verify it was created
dig _test-agent._mcp._agents.$DNS_AID_TEST_ZONE TXT +short

# View the agent index
dns-aid index list $DNS_AID_TEST_ZONE --backend cloudflare

# Clean up (auto-removes from index)
dns-aid delete \
    --name test-agent \
    --domain $DNS_AID_TEST_ZONE \
    --protocol mcp \
    --backend cloudflare \
    --force
```

### Cloudflare Advantages

- **Free tier**: DNS hosting is free for unlimited domains
- **Simple setup**: Just an API token, no IAM policies or TSIG keys
- **Full BANDAID compliance**: Supports ServiceMode SVCB with all parameters
- **Global anycast**: Fast DNS resolution worldwide
- **Great documentation**: Well-documented REST API

### Cloudflare Troubleshooting

#### "API token not configured" error
- Ensure `CLOUDFLARE_API_TOKEN` is set (not `CLOUDFLARE_TOKEN`)
- Check the token value isn't wrapped in extra quotes

#### "400 Bad Request" on API calls
- Verify your API token has DNS edit permissions
- Check the token hasn't expired

#### "No zone found for domain" error
- Ensure the domain is added to your Cloudflare account
- Check the domain status is "Active" in Cloudflare dashboard
- Verify the API token has access to that specific zone

## End-to-End Test

### Step 1: Publish an Agent

```bash
dns-aid publish \
  --name test-agent \
  --domain $DNS_AID_TEST_ZONE \
  --protocol mcp \
  --endpoint mcp.$DNS_AID_TEST_ZONE \
  --capability demo \
  --capability test \
  --ttl 300
```

Expected output:
```
Publishing agent to DNS...

✓ Agent published successfully!

  FQDN: _test-agent._mcp._agents.yourdomain.com
  Endpoint: https://mcp.yourdomain.com:443

  Records created:
    • SVCB _test-agent._mcp._agents.yourdomain.com
    • TXT _test-agent._mcp._agents.yourdomain.com

Verify with:
  dig _test-agent._mcp._agents.yourdomain.com SVCB
  dig _test-agent._mcp._agents.yourdomain.com TXT
```

### Step 2: Verify DNS Records

```bash
# Using DNS-AID
dns-aid verify _test-agent._mcp._agents.$DNS_AID_TEST_ZONE

# Using dig (external verification)
dig _test-agent._mcp._agents.$DNS_AID_TEST_ZONE SVCB +short
dig _test-agent._mcp._agents.$DNS_AID_TEST_ZONE TXT +short
```

### Step 3: Discover Agents

```bash
# Discover via DNS (default)
dns-aid discover $DNS_AID_TEST_ZONE

# Or discover via HTTP index (ANS-compatible, richer metadata)
dns-aid discover $DNS_AID_TEST_ZONE --use-http-index
```

Expected output:
```
Discovering agents at yourdomain.com...

Found 1 agent(s) at yourdomain.com:

┌────────────┬──────────┬────────────────────────────────┬─────────────┐
│ Name       │ Protocol │ Endpoint                       │ Capabilities│
├────────────┼──────────┼────────────────────────────────┼─────────────┤
│ test-agent │ mcp      │ https://mcp.yourdomain.com:443 │ demo, test  │
└────────────┴──────────┴────────────────────────────────┴─────────────┘
```

### Step 4: List All Records

```bash
dns-aid list $DNS_AID_TEST_ZONE
```

### Step 5: View Agent Index

The agent index (`_index._agents.{domain}`) provides efficient single-query discovery:

```bash
# List agents in the index
dns-aid index list $DNS_AID_TEST_ZONE
```

Expected output:
```
Agent index for yourdomain.com:

┌────────────┬──────────┬─────────────────────────────────────────────┐
│ Name       │ Protocol │ FQDN                                        │
├────────────┼──────────┼─────────────────────────────────────────────┤
│ test-agent │ mcp      │ _test-agent._mcp._agents.yourdomain.com     │
└────────────┴──────────┴─────────────────────────────────────────────┘

Total: 1 agent(s) in index
```

> **Note:** The index is automatically updated when you publish or delete agents.
> Use `--no-update-index` to skip index updates if needed.

## HTTP Index Discovery (ANS-Compatible)

DNS-AID supports HTTP-based agent discovery for compatibility with ANS-style systems. This provides richer metadata (descriptions, model cards, costs) while still validating endpoints via DNS.

### HTTP Index Endpoint

The HTTP index is served at: `https://_index._aiagents.{domain}/index-wellknown`

### Using HTTP Index Discovery

```bash
# CLI with HTTP index
dns-aid discover example.com --use-http-index

# Compare outputs
dns-aid discover example.com --json              # DNS only
dns-aid discover example.com --use-http-index --json  # HTTP index
```

### Python Library

```python
from dns_aid import discover

# Pure DNS discovery (default)
result = await discover("example.com")

# HTTP index discovery (richer metadata)
result = await discover("example.com", use_http_index=True)

for agent in result.agents:
    print(f"{agent.name}: {agent.endpoint_url}")
    if agent.description:
        print(f"  Description: {agent.description}")
```

### When to Use Each Method

| Scenario | Use |
|----------|-----|
| Maximum decentralization | DNS (default) |
| Rich metadata upfront | HTTP index |
| Offline/cached discovery | DNS |
| ANS compatibility | HTTP index |
| Minimal network round trips | DNS |

### Step 6: Clean Up

```bash
dns-aid delete --name test-agent --domain $DNS_AID_TEST_ZONE --protocol mcp --force
```

> The delete command automatically removes the agent from the index.

## Agent Index Management

DNS-AID provides automatic index management. The `_index._agents.{domain}` TXT record lists all agents at a domain, enabling efficient single-query discovery.

### Automatic Index Updates

By default, `publish` and `delete` commands automatically update the index:

```bash
# First agent - index created automatically
dns-aid publish --name chat --domain example.com --protocol mcp --endpoint chat.example.com
# ✓ Created index at _index._agents.example.com (1 agent)

# Second agent - index updated automatically
dns-aid publish --name billing --domain example.com --protocol a2a --endpoint billing.example.com
# ✓ Updated index at _index._agents.example.com (2 agents)

# Delete agent - removed from index automatically
dns-aid delete --name chat --domain example.com --protocol mcp --force
# ✓ Updated index at _index._agents.example.com (1 agent)
```

### Skip Index Updates

For internal or test agents that shouldn't be indexed:

```bash
dns-aid publish --name internal-bot --domain example.com --protocol mcp \
  --endpoint internal.example.com --no-update-index
```

### Index Commands

```bash
# List agents in the index
dns-aid index list example.com

# Sync index with actual DNS records (discover and rebuild)
dns-aid index sync example.com
```

### Index Format

The index is stored as a TXT record:
```
_index._agents.example.com. TXT "agents=chat:mcp,billing:a2a,support:https"
```

## Using the Python Library

```python
import asyncio
from dns_aid import publish, discover, verify

async def main():
    # Publish an agent
    result = await publish(
        name="my-agent",
        domain="yourdomain.com",
        protocol="mcp",
        endpoint="mcp.yourdomain.com",
        capabilities=["chat", "code-review"],
    )
    print(f"Published: {result.agent.fqdn}")

    # Discover agents
    discovery = await discover("yourdomain.com")
    for agent in discovery.agents:
        print(f"Found: {agent.name} at {agent.endpoint_url}")

    # Verify an agent
    verification = await verify("_my-agent._mcp._agents.yourdomain.com")
    print(f"Security Score: {verification.security_score}/100")

asyncio.run(main())
```


## JWS Signatures

JWS (JSON Web Signature) provides application-layer verification when DNSSEC isn't available (~70% of domains). Signatures are embedded in SVCB records and verified against a JWKS published at `.well-known/dns-aid-jwks.json`.

### Generate Keys

```bash
# Generate EC P-256 keypair
dns-aid keys generate --output ./keys/

# Export public keys as JWKS (host at .well-known/)
dns-aid keys export-jwks --output .well-known/dns-aid-jwks.json
```

### Publish with Signature

```bash
# Sign record with private key
dns-aid publish \
    --name payment \
    --domain example.com \
    --protocol mcp \
    --endpoint mcp.example.com \
    --sign \
    --private-key ./keys/private.pem
```

The SVCB record will include a `sig=` parameter with the JWS.

### Verify on Discovery

```bash
# Verify signature against JWKS
dns-aid discover example.com --verify-signature
```

### Python SDK

```python
from dns_aid.core.jws import generate_keypair, sign_record, verify_signature

# Generate keypair
private_key, public_key = generate_keypair()

# Sign a record
signature = sign_record(
    private_key=private_key,
    fqdn="_payment._mcp._agents.example.com",
    target="mcp.example.com",
    port=443,
)

# Verify (fetches JWKS from .well-known/dns-aid-jwks.json)
is_valid = await verify_signature(
    domain="example.com",
    signature=signature,
    fqdn="_payment._mcp._agents.example.com",
    target="mcp.example.com",
    port=443,
)
```

### Verification Priority

```
1. DNSSEC available and valid? → Trust (strongest)
2. No DNSSEC but JWS sig valid? → Trust (application-layer)
3. Neither? → Warn but allow (strict mode rejects)
```

---

## SDK: Agent Invocation & Telemetry

The Tier 1 SDK adds invocation with telemetry capture, agent ranking, and optional OpenTelemetry export.

### Quick Invocation

```python
import asyncio
import dns_aid

async def main():
    # Discover agents
    result = await dns_aid.discover("example.com", protocol="mcp")
    agent = result.agents[0]

    # Invoke and capture telemetry
    resp = await dns_aid.invoke(agent, method="tools/list")
    print(f"Success: {resp.success}")
    print(f"Latency: {resp.signal.invocation_latency_ms:.0f}ms")
    print(f"Data:    {resp.data}")

asyncio.run(main())
```

### Rank Multiple Agents

```python
import dns_aid

result = await dns_aid.discover("example.com", protocol="mcp")
ranked = await dns_aid.rank(result.agents, method="tools/list")

for r in ranked:
    print(f"{r.agent_fqdn}: score={r.composite_score:.1f}")
```

### Advanced: Connection Reuse & DB Persistence

```python
from dns_aid.sdk import AgentClient, SDKConfig

config = SDKConfig(
    persist_signals=True,      # Store signals in PostgreSQL
    otel_enabled=True,         # Export to OpenTelemetry
    caller_id="my-app",
)

async with AgentClient(config=config) as client:
    # Reuse HTTP connection across calls
    for agent in agents:
        await client.invoke(agent, method="tools/list")

    # Rank all invoked agents
    ranked = client.rank()
```

### Telemetry API

When the API server is running, telemetry data is available at:

```bash
# Global stats
curl http://localhost:8000/api/v1/telemetry/stats

# Agent rankings
curl http://localhost:8000/api/v1/telemetry/rankings

# Signal history
curl http://localhost:8000/api/v1/telemetry/signals?limit=10

# Per-agent scorecard
curl http://localhost:8000/api/v1/telemetry/agents/{fqdn}/scorecard
```

To enable HTTP telemetry push to a custom collection endpoint:

```python
config = SDKConfig(
    http_push_url="https://your-telemetry-server.example.com/signals"
)
```

Or via environment variable:
```bash
export DNS_AID_SDK_HTTP_PUSH_URL="https://your-telemetry-server.example.com/signals"
```

## Using the MCP Server

### Start the Server

```bash
# Stdio transport (for Claude Desktop)
dns-aid-mcp

# HTTP transport (for remote access)
dns-aid-mcp --transport http --port 8000
```

### Test Health Endpoints (HTTP mode)

```bash
# Start server in background
dns-aid-mcp --transport http --port 8000 &

# Test endpoints
curl http://localhost:8000/health
curl http://localhost:8000/ready
curl http://localhost:8000/
```

### Claude Desktop Integration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dns-aid": {
      "command": "dns-aid-mcp"
    }
  }
}
```

Restart Claude Desktop, then ask:
- "Discover agents at example.com"
- "Publish my agent to DNS"

### MCP Agent Proxying

The MCP server can now proxy tool calls to discovered agents:

```
You: "What tools does the booking agent at example.com have?"
Claude: [uses list_agent_tools] "The booking-agent has 3 tools: search_flights,
        book_flight, and get_booking_status..."

You: "Search for flights from NYC to London on March 15"
Claude: [uses call_agent_tool] "I found 5 flights: AA100 departing 8am,
        BA178 departing 10am..."
```

Available MCP tools for agent proxying:
- `list_agent_tools`: List available tools from a discovered agent
- `call_agent_tool`: Call a specific tool on a discovered agent

### Discovery Transparency

Each discovered agent includes transparency fields showing how data was resolved:

| Field | Value | Meaning |
|-------|-------|---------|
| `endpoint_source` | `dns_svcb` | Endpoint resolved via DNS SVCB lookup (proper BANDAID flow) |
| | `http_index_fallback` | DNS lookup failed, using HTTP index data only |
| | `direct` | Endpoint was explicitly provided |
| `capability_source` | `cap_uri` | Capabilities fetched from SVCB `cap` URI document |
| | `txt_fallback` | Capabilities from DNS TXT record |
| | `none` | No capabilities found |

Agent name and protocol are extracted from the FQDN in the HTTP index — no separate `protocols` field needed. The FQDN is the single source of truth.

Capabilities are resolved with priority: SVCB `cap` URI → capability document → TXT record fallback. The HTTP index also includes capabilities inline per agent.

### BANDAID Custom SVCB Parameters

Per the IETF draft, SVCB records can carry custom parameters for richer agent metadata:

```bash
# Publish with BANDAID custom SVCB parameters
dns-aid publish \
    --name booking \
    --domain example.com \
    --protocol mcp \
    --endpoint mcp.example.com \
    --capability travel --capability booking \
    --cap-uri https://mcp.example.com/.well-known/agent-cap.json \
    --cap-sha256 dGVzdGhhc2g \
    --bap "mcp/1,a2a/1" \
    --policy-uri https://example.com/agent-policy \
    --realm production
```

| Parameter | CLI Flag | Description |
|-----------|----------|-------------|
| `cap` | `--cap-uri` | URI to capability document (rich JSON metadata) |
| `cap-sha256` | `--cap-sha256` | SHA-256 digest for integrity verification |
| `bap` | `--bap` | Supported protocols with versions (comma-separated) |
| `policy` | `--policy-uri` | URI to agent policy document |
| `realm` | `--realm` | Multi-tenant scope identifier |

**Discovery priority:** When discovering agents, DNS-AID fetches capabilities from the `cap` URI first, falling back to TXT record capabilities if the fetch fails. The `capability_source` field shows the source: `cap_uri` or `txt_fallback`.

### Live Demo with Claude Desktop

Try it now with our live demo agent:

```
You: "Discover agents at example.com"
Claude: [uses discover_agents_via_dns] "Found 1 agent: booking-agent (MCP protocol)
        at https://booking.example.com/mcp"

You: "What tools does the booking agent have?"
Claude: [uses list_agent_tools] "The booking-agent has these tools: ..."
```

## Running the Full Demo

```bash
# Set your zone
export DNS_AID_TEST_ZONE="yourdomain.com"

# Run interactive demo
python examples/demo_full.py
```

## Troubleshooting

### Route 53 Issues

#### "Zone not found" error
- Verify AWS credentials: `aws sts get-caller-identity`
- Check zone exists: `dns-aid zones`
- Ensure correct region: `export AWS_DEFAULT_REGION=us-east-1`

#### DNS records not appearing
- Wait for propagation (up to 60 seconds for Route 53)
- Check TTL settings
- Verify with `dig` directly

### Infoblox UDDI Issues

#### "No zone found for domain" error
- Verify `INFOBLOX_DNS_VIEW` matches your zone's view
- Check zone name spelling (with or without trailing dot)
- Ensure API key has DNS permissions

#### "401 Unauthorized" error
- Regenerate your API key in the Cloud Portal
- Ensure the key hasn't expired
- Check `INFOBLOX_API_KEY` is set correctly

#### "400 Bad Request" on zone lookup
- The DNS view name may be incorrect
- Check available views in the Infoblox Portal under DNS → Views

#### Records created but can't dig them
- Infoblox UDDI zones may be private (not publicly resolvable)
- Verify records via API instead:
  ```python
  async for rec in backend.list_records("zone.com"):
      print(rec)
  ```

### MCP Server Issues

#### MCP server not connecting
- Check if server is running: `ps aux | grep dns-aid-mcp`
- Test health endpoint: `curl http://localhost:8000/health`
- Check Claude Desktop logs

## Environment Variables Reference

### Core Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DNS_AID_BACKEND` | Yes (if no `backend=` arg) | — | DNS backend: `route53`, `cloudflare`, `infoblox`, `ddns`, `mock` |
| `DNS_AID_SVCB_STRING_KEYS` | No | `0` | Set `1` to emit human-readable SVCB param names instead of keyNNNNN |
| `DNS_AID_FETCH_ALLOWLIST` | No | — | Comma-separated hostnames to bypass SSRF protection (testing only) |

### SDK Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DNS_AID_HTTP_PUSH_URL` | No | — | Optional endpoint to push telemetry signals |
| `DNS_AID_TELEMETRY_API_URL` | No | — | Optional endpoint to fetch community rankings |
| `DNS_AID_DIRECTORY_API_URL` | No | — | Optional endpoint to query agent directory |

### Backend-Specific Variables

| Variable | Backend | Description |
|----------|---------|-------------|
| `AWS_REGION` | route53 | AWS region for Route 53 API calls |
| `INFOBLOX_API_KEY` | infoblox | BloxOne DDI API key |
| `INFOBLOX_DNS_VIEW` | infoblox | DNS view name (default: `default`) |
| `CLOUDFLARE_API_TOKEN` | cloudflare | Cloudflare API token with DNS edit permissions |

## Experimental Models

The following modules define forward-looking data models for `.well-known/agent.json`
enrichment. They are **defined but not yet wired** into `discover()` or `publish()`:

- `dns_aid.core.agent_metadata` — `AgentMetadata` schema (identity, connection, auth, capabilities, contact)
- `dns_aid.core.capability_model` — `CapabilitySpec` with machine-readable `Action` descriptors (intent, semantics, tags)

These models are available for import and experimentation but are not part of the
stable public API. They will be integrated in a future release once the
`.well-known/agent.json` enrichment pipeline is finalized.

## Next Steps

- Read the [API Reference](api-reference.md)
- Explore [examples/](../examples/)
- Review the [IETF draft specification](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-bandaid/)
