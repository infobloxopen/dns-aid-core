# DNS-AID

[![CI](https://github.com/infobloxopen/dns-aid-core/actions/workflows/ci.yml/badge.svg)](https://github.com/infobloxopen/dns-aid-core/actions/workflows/ci.yml)
[![CodeQL](https://github.com/infobloxopen/dns-aid-core/actions/workflows/codeql.yml/badge.svg)](https://github.com/infobloxopen/dns-aid-core/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/infobloxopen/dns-aid-core/badge)](https://scorecard.dev/viewer/?uri=github.com/infobloxopen/dns-aid-core)
[![Coverage](https://img.shields.io/badge/coverage-80%25-green)](https://github.com/infobloxopen/dns-aid-core/actions/workflows/ci.yml)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-blue)](https://github.com/infobloxopen/dns-aid-core/releases/latest)
[![Sigstore](https://img.shields.io/badge/signed-Sigstore-purple)](https://github.com/infobloxopen/dns-aid-core/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)

**DNS-based Agent Identification and Discovery**

Reference implementation for [IETF draft-mozleywilliams-dnsop-dnsaid-01](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/).

DNS-AID enables AI agents to discover each other via DNS, using the internet's existing naming infrastructure instead of centralized registries or hardcoded URLs.

> **New to DNS-AID?** Check out the [Getting Started Guide](docs/getting-started.md) for step-by-step setup and testing instructions.

## Quick Start

```bash
# Basic installation
pip install dns-aid

# With CLI support
pip install dns-aid[cli]

# With MCP server for AI agents
pip install dns-aid[mcp]

# With a specific backend
pip install dns-aid[route53]      # AWS Route 53
pip install dns-aid[cloudflare]   # Cloudflare DNS
pip install dns-aid[infoblox]     # Infoblox BloxOne (cloud)
pip install dns-aid[nios]         # Infoblox NIOS (on-prem)
pip install dns-aid[ddns]         # RFC 2136 Dynamic DNS (BIND, PowerDNS)

# Everything
pip install dns-aid[all]
```

### Configure

```bash
# Interactive setup wizard (recommended for first-time users)
dns-aid init

# Or configure manually
cp .env.example .env   # All variables documented, uncomment what you need
```

The CLI, MCP server, and examples load `.env` automatically. Set your backend, credentials, domain, and log level in one place. See [`.env.example`](.env.example) for all options.

```bash
# Verify your environment is correctly configured
dns-aid doctor
dns-aid doctor --domain example.com    # test agent discovery for your domain
```

### Python Library

```python
import dns_aid

# Publish your agent to DNS
await dns_aid.publish(
    name="my-agent",
    domain="example.com",
    protocol="mcp",
    endpoint="agent.example.com",
    capabilities=["chat", "code-review"]
)

# Discover agents at a domain (pure DNS - default)
agents = await dns_aid.discover("example.com")
for agent in agents:
    print(f"{agent.name}: {agent.endpoint_url}")

# Discover via HTTP index (ANS-compatible, richer metadata)
agents = await dns_aid.discover("example.com", use_http_index=True)

# Verify an agent's DNS records
result = await dns_aid.verify("_my-agent._mcp._agents.example.com")
print(f"Security Score: {result.security_score}/100")

# Run environment diagnostics (programmatic access)
from dns_aid.doctor import run_checks
report = run_checks(domain="example.com")
print(f"{report.pass_count} passed, {report.fail_count} failed")
```

### Try Without Cloud Credentials

No AWS/Cloudflare/Infoblox/NIOS account? Use the built-in BIND9 playground:

```bash
# Start local DNS server
docker compose -f tests/integration/bind/docker-compose.yml up -d

# Copy pre-configured environment
cp .env.example .env
# Uncomment the "Docker Playground" section in .env

# Publish and discover agents locally
dns-aid publish my-agent --domain test.dns-aid.local --backend ddns
dns-aid discover test.dns-aid.local --backend ddns

# Clean up
docker compose -f tests/integration/bind/docker-compose.yml down
```

See the [Getting Started Guide](docs/getting-started.md#docker-playground-zero-credential-setup) for full details.

## CLI Usage

```bash
# First-time setup wizard
dns-aid init

# Diagnose environment (Python, deps, DNS, backends, .env)
# Use --domain to test agent discovery for your domain
dns-aid doctor --domain example.com

# Publish an agent to DNS
dns-aid publish \
    --name my-agent \
    --domain example.com \
    --protocol mcp \
    --endpoint agent.example.com \
    --capability chat \
    --capability code-review

# Publish with DNS-AID custom SVCB parameters
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

# Discover agents at a domain (pure DNS - default)
dns-aid discover example.com

# Discover with filters
dns-aid discover example.com --protocol mcp --name chat

# Discover via HTTP index (ANS-compatible, richer metadata)
dns-aid discover example.com --use-http-index

# Output as JSON
dns-aid discover example.com --json

# Verify DNS records
dns-aid verify _my-agent._mcp._agents.example.com

# List DNS-AID records in a zone
dns-aid list example.com

# List available zones (Route 53)
dns-aid zones

# Delete an agent
dns-aid delete --name my-agent --domain example.com --protocol mcp

# Index Management
# List agents in a domain's index record
dns-aid index list example.com

# Sync index with actual DNS records (useful for repair)
dns-aid index sync example.com

# Publish without updating the index (for internal agents)
dns-aid publish --name internal-bot --domain example.com --protocol mcp --no-update-index

```

### Agent Index Records

DNS-AID automatically maintains an index record at `_index._agents.{domain}` for efficient discovery:

```
_index._agents.example.com. TXT "agents=chat:mcp,billing:a2a,support:https"
```

**Benefits:**
- Single DNS query discovers all agents at a domain
- Crawlers can efficiently index domains
- Explicit list of published agents (no guessing)

The index is updated automatically when you `publish` or `delete` agents. Use `--no-update-index` to opt out for internal agents.

### HTTP Index Discovery (ANS-Compatible)

DNS-AID also supports HTTP-based agent discovery for compatibility with ANS-style systems. This provides richer metadata (descriptions, model cards, capabilities, costs) while still validating endpoints via DNS.

**Endpoint patterns tried (in order):**
1. `https://index.aiagents.{domain}/index-wellknown` (demo-friendly, no underscores)
2. `https://_index._aiagents.{domain}/index-wellknown` (ANS-style)
3. `https://{domain}/.well-known/agents-index.json` (well-known path)

**Capability Document endpoint:**
- `https://index.aiagents.{domain}/cap/{agent-name}` — returns a capability document JSON per agent

```bash
# Fetch HTTP index directly
curl https://index.aiagents.example.com/index-wellknown

# Fetch capability document for a specific agent
curl https://index.aiagents.example.com/cap/booking-agent

# CLI with HTTP index
dns-aid discover example.com --use-http-index
```

```python
# Python with HTTP index
agents = await dns_aid.discover("example.com", use_http_index=True)
```

| Discovery Method | When to Use |
|-----------------|-------------|
| **DNS (default)** | Maximum decentralization, offline caching, minimal round trips |
| **HTTP Index** | Rich metadata upfront, ANS compatibility, model cards, capabilities, direct endpoints |

**FQDN as Source of Truth:** The HTTP index only needs to provide each agent's FQDN (e.g., `_booking._mcp._agents.example.com`). Agent name and protocol are extracted from the FQDN — no separate `protocols` field needed. DNS SVCB lookup then resolves the authoritative endpoint.

**Discovery Transparency:** Each discovered agent includes source fields showing how data was resolved:

| Field | Values | Description |
|-------|--------|-------------|
| `endpoint_source` | `dns_svcb`, `http_index_fallback`, `direct` | How the endpoint was resolved |
| `capability_source` | `cap_uri`, `txt_fallback`, `none` | How capabilities were discovered |

**Capability Resolution:** Capabilities are resolved with the following priority:
1. **SVCB `cap` URI** → fetch capability document (JSON with capabilities, version, description)
2. **TXT record fallback** → `capabilities=chat,support` from DNS TXT record
3. **HTTP Index inline** → capabilities embedded in the index JSON response

## MCP Server

DNS-AID includes an MCP (Model Context Protocol) server that allows AI agents like Claude to publish and discover other agents.

### Running the MCP Server

```bash
# Run with stdio transport (default - for Claude Desktop, etc.)
dns-aid-mcp

# Run with HTTP transport
dns-aid-mcp --transport http --port 8000
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `publish_agent_to_dns` | Publish an AI agent to DNS (auto-updates index) |
| `discover_agents_via_dns` | Discover AI agents at a domain (supports `use_http_index` for ANS-compatible discovery) |
| `list_agent_tools` | List available tools on a discovered MCP agent |
| `call_agent_tool` | Call a tool on a discovered MCP agent (proxy requests) |
| `verify_agent_dns` | Verify DNS-AID records and security |
| `list_published_agents` | List all agents in a domain |
| `delete_agent_from_dns` | Remove an agent from DNS (auto-updates index) |
| `list_agent_index` | List agents in domain's index record |
| `sync_agent_index` | Sync index with actual DNS records |
| `diagnose_environment` | Run environment diagnostics (deps, DNS, backends). Optional `domain` param for discovery check |

### Claude Desktop Integration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dns-aid": {
      "command": "dns-aid-mcp"
    }
  }
}
```

Then Claude can discover and connect to AI agents:

> "Find available agents at example.com"
>
> "Publish my chat agent to DNS at mycompany.com"
>
> "Discover agents at example.com and search for flights from SFO to JFK"

#### Live Demo

Try the live demo with Claude Desktop:

```json
{
  "mcpServers": {
    "dns-aid": {
      "command": "python",
      "args": ["-m", "dns_aid.mcp.server"]
    }
  }
}
```

Then ask Claude to discover and use the booking agent:

> "Discover agents at example.com using HTTP index, find a booking agent, and search for flights from SFO to JFK on March 15th 2026"

Claude will:
1. Call `discover_agents_via_dns` → finds booking-agent at `https://booking.example.com/mcp`
2. Call `list_agent_tools` → sees search_flights, get_flight_details, check_availability, create_reservation
3. Call `call_agent_tool` → searches for flights and returns results

## How It Works

DNS-AID uses SVCB records (RFC 9460) to advertise AI agents:

```
_chat._a2a._agents.example.com. 3600 IN SVCB 1 chat.example.com. alpn="a2a" port=443 mandatory="alpn,port"
_chat._a2a._agents.example.com. 3600 IN TXT "capabilities=chat,assistant" "version=1.0.0"
```

**DNS-AID Custom SVCB Parameters:** Per the IETF draft, SVCB records can carry additional custom parameters for richer agent metadata:

```
_booking._mcp._agents.example.com. SVCB 1 mcp.example.com. alpn="mcp" port=443 \
    cap="https://mcp.example.com/.well-known/agent-cap.json" \
    cap-sha256="dGVzdGhhc2g" bap="mcp/1,a2a/1" \
    policy="https://example.com/agent-policy" realm="production"
```

| Parameter | Purpose |
|-----------|---------|
| `cap` | URI to capability document (rich JSON metadata) |
| `cap-sha256` | SHA-256 digest of capability descriptor for integrity verification |
| `bap` | Supported bulk agent protocols with versioning |
| `policy` | URI to agent policy document |
| `realm` | Multi-tenant scope identifier |

> **Note:** Route 53 and Cloudflare do not support private-use SVCB SvcParamKeys (`key65400`–`key65405`).
> DNS-AID automatically demotes these parameters to TXT records with a `dnsaid_` prefix (e.g.,
> `dnsaid_realm=production`), preserving all metadata without data loss. BIND/DDNS (RFC 2136)
> backends natively support custom SVCB params — no demotion needed.

This allows any DNS client to discover agents without proprietary protocols or central registries.

### Discovery Flow (DNS-AID Draft Aligned)

```
  Agent A                        DNS                           Agent B
     │                            │                               │
     │  "Find agents at           │                               │
     │   salesforce.com"          │                               │
     │                            │                               │
  ┌──┴──────────────────────────────────────────────────────────────┐
  │  Step 1: Fetch HTTP Index (primary)                             │
  │  ──────────────────────────────────                             │
  │  GET https://index.aiagents.salesforce.com/index-wellknown      │
  │  Response: [{"fqdn":"_chat._a2a._agents.salesforce.com",...}]   │
  │                                                                 │
  │  Fallback: Query TXT Index via DNS                              │
  │  Query: _index._agents.salesforce.com TXT                       │
  │  Response: "agents=chat:a2a,billing:mcp"                        │
  └──┬──────────────────────────────────────────────────────────────┘
     │                            │                               │
  ┌──┴──────────────────────────────────────────────────────────────┐
  │  Step 2: Query SVCB per agent                                   │
  │  ────────────────────────────                                   │
  │  Query: _chat._a2a._agents.salesforce.com SVCB                  │
  │  Response: SVCB 1 chat.salesforce.com. alpn="a2a" port=443      │
  │            cap="https://chat.salesforce.com/.well-known/cap.json"│
  │  (DNSSEC validated)                                             │
  └──┬──────────────────────────────────────────────────────────────┘
     │                            │                               │
  ┌──┴──────────────────────────────────────────────────────────────┐
  │  Step 2b: Fetch Capability Document (if cap URI present)        │
  │  ───────────────────────────────────────────────────            │
  │  GET https://chat.salesforce.com/.well-known/cap.json           │
  │  Response: {"capabilities":["chat","support"],"version":"1.0"}  │
  │  (cap_sha256 integrity verified)                                │
  └──┬──────────────────────────────────────────────────────────────┘
     │                            │                               │
  ┌──┴──────────────────────────────────────────────────────────────┐
  │  Step 3: TXT Capabilities (fallback if no cap document)         │
  │  ──────────────────────────────────────────────────             │
  │  Query: _chat._a2a._agents.salesforce.com TXT                   │
  │  Response: "capabilities=chat,support" "version=1.0.0"          │
  └──┬──────────────────────────────────────────────────────────────┘
     │                            │                               │
     ├────────────────────────────────────────────────────────────►│
     │  Connect to https://chat.salesforce.com:443                │
```

**Index Resolution Priority:** HTTP index endpoint → TXT index record → common name probing.
**Capability Resolution Priority:** SVCB `cap` URI → capability document → TXT record fallback.
Each discovered agent includes `endpoint_source` and `capability_source` showing which path was used.

## Security: DNSSEC and DANE

DNS-AID relies on DNSSEC and DANE for end-to-end trust, as specified in the [IETF draft](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/) Section 4.4.1.

### DNSSEC (Mandatory for Public Zones)

All DNS-AID discovery records **MUST** be signed with DNSSEC. Resolvers consuming DNS-AID data must treat unsigned or DNSSEC-bogus responses as failures.

```bash
# Verify DNSSEC and security posture for an agent
dns-aid verify _chat._a2a._agents.example.com
```

### DANE/TLSA (Recommended)

Where DNS-AID endpoints rely on TLS, DANE TLSA records **SHOULD** be used to bind endpoint certificates to DNSSEC-validated names. This removes reliance on external PKI (certificate authorities) and provides cryptographic proof that the TLS certificate belongs to the intended agent endpoint.

**Recommended TLSA profile** (per IETF draft Section 5.2.3):

```
_443._tcp.agent-svc.example.com. 1800 IN TLSA 3 1 1 (
    <SHA-256 hash of endpoint certificate SPKI>
)
```

| Field | Value | Meaning |
|-------|-------|---------|
| Usage | 3 | DANE-EE (end entity, no CA chain needed) |
| Selector | 1 | SubjectPublicKeyInfo (public key only) |
| Matching Type | 1 | SHA-256 digest |

**Full DANE certificate verification:**

```python
# Advisory check (TLSA record exists?)
result = await dns_aid.verify("_chat._a2a._agents.example.com")
print(result.dane_valid)  # True/False/None

# Full certificate matching (connect + compare cert against TLSA)
result = await dns_aid.verify(
    "_chat._a2a._agents.example.com",
    verify_dane_cert=True
)
print(result.dane_note)   # Detailed verification status
```

> **Note:** DANE is only meaningful when DNSSEC is also validated. Without DNSSEC, an attacker could spoof both the TLSA record and the endpoint certificate.

### Security Score

The `verify` command returns a security score (0–100) based on:

| Check | Points | Requirement Level |
|-------|--------|-------------------|
| DNS record exists | 20 | Required |
| SVCB record valid | 20 | Required |
| DNSSEC validated | 30 | MUST (public zones) |
| DANE/TLSA verified | 15 | SHOULD |
| Endpoint reachable | 15 | Operational |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DNS-AID ARCHITECTURE                             │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────────────┐
│   AI Agents     │     │   Developers    │     │   Infrastructure Ops    │
│  (Claude, etc.) │     │                 │     │                         │
└────────┬────────┘     └────────┬────────┘     └────────────┬────────────┘
         │                       │                           │
         │ MCP Protocol          │ CLI                       │ CLI / API
         ▼                       ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         DNS-AID TOOLKIT                                 │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐ │
│  │   MCP Server    │  │      CLI        │  │     Python Library      │ │
│  │                 │  │                 │  │                         │ │
│  │ • publish_agent │  │ • dns-aid       │  │ • dns_aid.publish()     │ │
│  │ • discover_     │  │   publish       │  │ • dns_aid.discover()    │ │
│  │   agents        │  │ • dns-aid       │  │ • dns_aid.verify()      │ │
│  │ • verify_agent  │  │   discover      │  │                         │ │
│  │ • list_agents   │  │ • dns-aid       │  │                         │ │
│  │                 │  │   verify        │  │                         │ │
│  └────────┬────────┘  └────────┬────────┘  └────────────┬────────────┘ │
│           │                    │                        │              │
│           └────────────────────┴────────────────────────┘              │
│                                │                                       │
│                                ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                        CORE ENGINE                              │  │
│  │                                                                 │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │  │
│  │  │  Publisher  │  │ Discoverer  │  │      Validator          │ │  │
│  │  │             │  │             │  │                         │ │  │
│  │  │ Create SVCB │  │ Query DNS   │  │ • DNSSEC validation     │ │  │
│  │  │ Create TXT  │  │ Parse SVCB  │  │ • DANE/TLSA check       │ │  │
│  │  │             │  │ Return      │  │ • Endpoint health       │ │  │
│  │  │             │  │ endpoints   │  │                         │ │  │
│  │  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘ │  │
│  │         │                │                      │              │  │
│  └─────────┴────────────────┴──────────────────────┴──────────────┘  │
│                             │                                        │
└─────────────────────────────┼────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                          DNS BACKEND ABSTRACTION                                  │
│                                                                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Route53  │ │ Infoblox │ │ Infoblox │ │   DDNS   │ │Cloudflare│ │   Mock   │  │
│  │  (AWS)   │ │   UDDI   │ │   NIOS   │ │ (RFC2136)│ │          │ │ (Testing)│  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │
│       │            │            │            │            │            │         │
└───────┴────────────┴────────────┴────────────┴────────────┴────────────┴─────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       DNS INFRASTRUCTURE                                │
│                                                                         │
│   Authoritative DNS servers hosting _agents.{domain} zones              │
│   with SVCB, TXT, and TLSA records secured by DNSSEC                   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Choosing the Right Interface

DNS-AID provides three interfaces. Choose based on your use case:

### Python Library

**Best for:** Application developers building agent discovery into their code.

```python
import dns_aid

# Integrate directly into your Python application
agents = await dns_aid.discover("example.com", protocol="mcp")
```

| Use Case | Example |
|----------|---------|
| Building an AI agent that discovers other agents | Agent mesh applications |
| Embedding discovery into existing Python apps | Adding DNS-AID to a Flask/FastAPI service |
| Automated pipelines and scripts | CI/CD, scheduled publishing |
| Unit testing with mock backend | Testing without real DNS |

### CLI Tool

**Best for:** Operators, DevOps, and quick manual operations.

```bash
dns-aid discover example.com --protocol mcp
```

| Use Case | Example |
|----------|---------|
| Manual publishing/discovery | Testing a new agent deployment |
| Shell scripts and automation | `cron` jobs, deployment scripts |
| Debugging and troubleshooting | Checking DNS records exist |
| Zone management | Listing agents, bulk operations |

### MCP Server

**Best for:** AI assistants (Claude, etc.) that need DNS-AID capabilities.

```bash
dns-aid-mcp  # Claude can now use DNS-AID tools
```

| Use Case | Example |
|----------|---------|
| Claude Desktop integration | "Find agents at salesforce.com" |
| AI-driven infrastructure | Agent self-registration and discovery |
| Natural language DNS management | "Publish my chat agent to DNS" |
| Environment diagnostics | "Check if my DNS-AID setup is working" |
| Building agentic workflows | Multi-agent orchestration |

### Decision Matrix

| You want to... | Use |
|----------------|-----|
| Build discovery into your Python app | **Python Library** |
| Run ad-hoc commands from terminal | **CLI** |
| Automate with shell scripts | **CLI** |
| Enable Claude/AI to manage DNS-AID | **MCP Server** |
| Test without real DNS | **Python Library** (with MockBackend) |
| Debug DNS record issues | **CLI** (`dns-aid verify`) |

## DNS Backends

DNS-AID supports multiple DNS backends:

| Backend | Description | Status |
|---------|-------------|--------|
| Route 53 | AWS Route 53 | ✅ Production |
| Infoblox UDDI | Infoblox Universal DDI (cloud) | ✅ Production |
| Infoblox NIOS | Infoblox NIOS (on-prem WAPI) | ✅ Production |
| DDNS | RFC 2136 Dynamic DNS (BIND, etc.) | ✅ Production |
| Cloudflare | Cloudflare DNS | ✅ Production |
| Mock | In-memory (testing) | ✅ Production |

### Route 53 Setup

Route 53 uses boto3's credential chain — pick any method:

1. **AWS CLI** (recommended — easiest):
   ```bash
   aws configure
   ```

2. **Environment variables** (CI/CD, containers):
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_DEFAULT_REGION="us-east-1"  # Optional
   ```

3. **Named profile**:
   ```bash
   export AWS_PROFILE="my-profile"
   ```

4. **IAM role** (EC2/ECS/Lambda): automatic, no config needed.

DNS-AID auto-detects Route 53 when any boto3 credential source is configured.

2. Verify zone access:
   ```bash
   dns-aid zones
   ```

3. Publish your agent:
   ```bash
   dns-aid publish -n my-agent -d myzone.com -p mcp -e mcp.myzone.com
   ```

### Infoblox UDDI Setup

Infoblox UDDI (Universal DDI) is Infoblox's cloud-native DDI platform. DNS-AID supports creating SVCB and TXT records via the Infoblox API.

#### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `INFOBLOX_API_KEY` | Yes | - | Infoblox UDDI API key from Cloud Portal |
| `INFOBLOX_DNS_VIEW` | No | `default` | DNS view name (zones exist within views) |
| `INFOBLOX_BASE_URL` | No | `https://csp.infoblox.com` | API base URL |

#### Step-by-Step Setup

1. **Get your API key** from [Infoblox Cloud Portal](https://csp.infoblox.com):
   - Navigate to **Administration** → **API Keys**
   - Create a new API key with DNS permissions
   - Copy the key (shown only once)

2. **Configure environment variables**:
   ```bash
   export INFOBLOX_API_KEY="your-api-key"
   export INFOBLOX_DNS_VIEW="default"  # Or your specific view name
   ```

3. **Identify your zone and view**:
   - In Infoblox Portal, go to **DNS** → **Authoritative Zones**
   - Note the zone name (e.g., `example.com`) and which view it belongs to

4. **Use in Python**:
   ```python
   from dns_aid.backends.infoblox import InfobloxBloxOneBackend
   from dns_aid.core.publisher import set_default_backend
   from dns_aid import publish

   # Initialize backend (reads from environment variables)
   backend = InfobloxBloxOneBackend()

   # Or with explicit configuration
   backend = InfobloxBloxOneBackend(
       api_key="your-api-key",
       dns_view="default",  # Your DNS view name
   )

   set_default_backend(backend)

   await publish(
       name="my-agent",
       domain="example.com",
       protocol="mcp",
       endpoint="agent.example.com",
       capabilities=["chat", "code-review"]
   )
   ```

#### Infoblox UDDI Limitations & DNS-AID Compliance

> **⚠️ Important**: Infoblox UDDI SVCB records only support "alias mode" (priority 0) and do not
> support SVC parameters (`alpn`, `port`, `mandatory`). This means **Infoblox UDDI is not fully
> compliant with the [DNS-AID draft](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/)**.
>
> The draft requires ServiceMode SVCB records (priority > 0) with mandatory `alpn` and `port`
> parameters. Infoblox UDDI's limitation is a platform constraint, not a DNS-AID limitation.

| DNS-AID Requirement | Route 53 | Cloudflare | DDNS (BIND) | Infoblox NIOS | Infoblox UDDI |
|---------------------|----------|------------|-------------|---------------|---------------|
| ServiceMode (priority > 0) | ✅ | ✅ | ✅ | ✅ | ❌ |
| `alpn` parameter | ✅ | ✅ | ✅ | ✅ | ❌ |
| `port` parameter | ✅ | ✅ | ✅ | ✅ | ❌ |
| `mandatory` key | ✅ | ✅ | ✅ | ✅ | ❌ |
| Custom SVCB params (`cap`, `realm`, etc.) | ⚠️ TXT | ⚠️ TXT | ✅ Native | ✅ Native | ❌ |

**⚠️ TXT** = Custom DNS-AID params auto-demoted to TXT records with `dnsaid_` prefix (no data loss).

**For full DNS-AID compliance with native custom SVCB params, use DDNS (BIND/RFC 2136) or Infoblox NIOS. Route 53 and Cloudflare support all standard SVCB params with automatic TXT demotion for custom params.**

DNS-AID stores `alpn` and `port` in TXT records as a fallback for Infoblox UDDI, but this is
a workaround and not standard-compliant for agent discovery.

#### Verify Records via API

Since Infoblox UDDI zones may not be publicly resolvable, verify records via the API:

```python
async with InfobloxBloxOneBackend() as backend:
    async for record in backend.list_records("example.com", name_pattern="my-agent"):
        print(f"{record['type']}: {record['fqdn']}")
```

### Infoblox NIOS Setup (On-Prem)

Infoblox NIOS is the on-premise DDI platform with WAPI (Web API). DNS-AID creates SVCB and TXT records via WAPI v2.13.7+, with full ServiceMode SVCB support including custom DNS-AID parameters.

#### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NIOS_HOST` | Yes | - | Grid Manager hostname or IP |
| `NIOS_USERNAME` | Yes | - | WAPI username |
| `NIOS_PASSWORD` | Yes | - | WAPI password |
| `NIOS_DNS_VIEW` | No | `default` | DNS view name |
| `NIOS_WAPI_VERSION` | No | `2.13.7` | WAPI version |
| `NIOS_VERIFY_SSL` | No | `false` | Verify TLS certificate |

#### Step-by-Step Setup

1. **Ensure NIOS Grid Manager is reachable** from the host running DNS-AID.

2. **Configure environment variables**:
   ```bash
   export NIOS_HOST="nios.example.com"
   export NIOS_USERNAME="admin"
   export NIOS_PASSWORD="your-password"
   export NIOS_DNS_VIEW="default"       # Or your specific view name
   export NIOS_VERIFY_SSL="false"       # Set to true with valid TLS certs
   ```

3. **Verify zone access and publish**:
   ```bash
   dns-aid doctor --domain example.com    # Check NIOS credentials + discovery
   dns-aid publish -n my-agent -d example.com -p mcp -e mcp.example.com --backend nios
   ```

4. **Use in Python**:
   ```python
   from dns_aid.backends.infoblox import InfobloxNIOSBackend
   from dns_aid.core.publisher import set_default_backend
   from dns_aid import publish

   # Initialize backend (reads from environment variables)
   backend = InfobloxNIOSBackend()

   # Or with explicit configuration
   backend = InfobloxNIOSBackend(
       host="nios.example.com",
       username="admin",
       password="your-password",
       dns_view="default",
   )

   set_default_backend(backend)

   await publish(
       name="my-agent",
       domain="example.com",
       protocol="mcp",
       endpoint="agent.example.com",
       capabilities=["chat", "code-review"]
   )
   ```

#### NIOS DNS-AID Compliance

NIOS WAPI supports ServiceMode SVCB records (priority > 0) with full SVC parameters, including custom DNS-AID keys natively via `key65400`–`key65405`.

### DDNS Setup (RFC 2136)

DDNS (Dynamic DNS) is a universal backend that works with any DNS server supporting RFC 2136, including BIND9, Windows DNS, PowerDNS, and Knot DNS. This is ideal for on-premise DNS infrastructure without vendor-specific APIs.

#### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DDNS_SERVER` | Yes | - | DNS server hostname or IP |
| `DDNS_KEY_NAME` | Yes | - | TSIG key name |
| `DDNS_KEY_SECRET` | Yes | - | TSIG key secret (base64) |
| `DDNS_KEY_ALGORITHM` | No | `hmac-sha256` | TSIG algorithm |
| `DDNS_PORT` | No | `53` | DNS server port |

#### Step-by-Step Setup

1. **Create a TSIG key** on your DNS server (BIND example):
   ```bash
   tsig-keygen -a hmac-sha256 dns-aid-key > /etc/bind/dns-aid-key.conf
   ```

2. **Configure your zone** to allow updates with the key:
   ```
   zone "example.com" {
       type master;
       file "/var/lib/bind/example.com.zone";
       allow-update { key "dns-aid-key"; };
   };
   ```

3. **Configure DNS-AID**:
   ```bash
   export DDNS_SERVER="ns1.example.com"
   export DDNS_KEY_NAME="dns-aid-key"
   export DDNS_KEY_SECRET="your-base64-secret"
   ```

4. **Use in Python**:
   ```python
   from dns_aid.backends.ddns import DDNSBackend
   from dns_aid import publish

   backend = DDNSBackend()
   # Or with explicit configuration
   backend = DDNSBackend(
       server="ns1.example.com",
       key_name="dns-aid-key",
       key_secret="base64secret==",
       key_algorithm="hmac-sha256"
   )

   await publish(
       name="my-agent",
       domain="example.com",
       protocol="mcp",
       endpoint="agent.example.com",
       backend=backend
   )
   ```

#### DDNS Advantages

- **Universal**: Works with BIND, Windows DNS, PowerDNS, Knot, and any RFC 2136 server
- **No vendor lock-in**: Standard protocol, no proprietary APIs
- **On-premise friendly**: Perfect for enterprise internal DNS
- **Full DNS-AID compliance**: Supports ServiceMode SVCB with all standard parameters (custom DNS-AID params auto-demoted to TXT)

### Cloudflare Setup

Cloudflare DNS is ideal for demos, workshops, and quick prototyping thanks to its free tier and excellent API support. DNS-AID fully supports Cloudflare's SVCB record implementation.

#### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CLOUDFLARE_API_TOKEN` | Yes | - | API token with DNS edit permissions |
| `CLOUDFLARE_ZONE_ID` | No | - | Zone ID (auto-discovered if not set) |

#### Step-by-Step Setup

1. **Create an API token** in Cloudflare Dashboard:
   - Go to **My Profile** → **API Tokens** → **Create Token**
   - Use the "Edit zone DNS" template or create custom with:
     - **Permissions**: Zone → DNS → Edit
     - **Zone Resources**: Include → Specific zone → your-domain.com
   - Copy the token (shown only once)

2. **Configure environment variables**:
   ```bash
   export CLOUDFLARE_API_TOKEN="your-api-token"
   # Optional: specify zone ID (otherwise auto-discovered from domain)
   export CLOUDFLARE_ZONE_ID="your-zone-id"
   ```

3. **Publish your first agent**:
   ```bash
   dns-aid publish \
       --name my-agent \
       --domain your-domain.com \
       --protocol mcp \
       --endpoint agent.your-domain.com \
       --backend cloudflare
   ```

4. **Use in Python**:
   ```python
   from dns_aid.backends.cloudflare import CloudflareBackend
   from dns_aid import publish

   # Initialize backend (reads from environment variables)
   backend = CloudflareBackend()

   # Or with explicit configuration
   backend = CloudflareBackend(
       api_token="your-api-token",
       zone_id="optional-zone-id",  # Auto-discovered if not provided
   )

   await publish(
       name="my-agent",
       domain="your-domain.com",
       protocol="mcp",
       endpoint="agent.your-domain.com",
       backend=backend
   )
   ```

#### Cloudflare Advantages

- **Free tier**: DNS hosting is free for unlimited domains
- **SVCB support**: Full RFC 9460 compliance with SVCB Type 64 records
- **Global anycast**: Fast DNS resolution worldwide
- **Simple API**: Well-documented REST API v4
- **Full DNS-AID compliance**: Supports ServiceMode SVCB with all standard parameters (custom DNS-AID params auto-demoted to TXT)

## Why DNS-AID?

### vs Competing Proposals

| Approach | Problem | DNS-AID Advantage |
|----------|---------|-------------------|
| **ANS (GoDaddy)** | Centralized registry, KYC required, single gatekeeper | Federated — you control your domain, publish instantly |
| **Google (A2A + UCP)** | Discovery via Gemini/Search, payments via UCP | Neutral discovery — no platform lock-in or transaction fees |
| **.agent gTLD** | Requires ICANN approval, ongoing domain fees | Works NOW with domains you already own |
| **AgentDNS (China Telecom)** | Requires 6G infrastructure, carrier control | Works NOW on existing DNS infrastructure |
| **NANDA (MIT)** | New P2P overlay network, new ops paradigm | Uses infrastructure your DNS team already operates |
| **Web3 (ERC-8004)** | Gas fees, crypto wallets, enterprise-hostile | Free DNS queries, no blockchain complexity |
| **ai.txt / llms.txt** | No integrity verification, free-form JSON | DNSSEC cryptographic verification, structured SVCB |

### Feature Comparison

| Feature | DNS-AID | Central Registry | ai.txt |
|---------|---------|------------------|--------|
| **Decentralized** | ✅ | ❌ | ✅ |
| **Secure (DNSSEC)** | ✅ | Varies | ❌ |
| **Sovereign** | ✅ | ❌ | ✅ |
| **Standards-based** | ✅ (IETF) | ❌ | ❌ |
| **Works with existing infra** | ✅ | ❌ | ✅ |

### The Sovereignty Question

> **Who controls agent discovery?**
> - ANS: GoDaddy (US company as gatekeeper)
> - AgentDNS: China Telecom (state-owned carrier)
> - Web3: Ethereum Foundation
> - **DNS-AID: You control your own domain**
>
> DNS-AID preserves sovereignty. Organizations and nations maintain control over their own agent namespaces with no central authority that can block, censor, or surveil agent discovery.

### Google's Agent Ecosystem

Google is building a full-stack agent platform: **A2A** (communication), **UCP** (payments), and **Gemini/Search** (discovery). While A2A is an open protocol, discovery through Google surfaces means:
- Google controls visibility (pay-to-rank)
- Transaction fees via [UCP](https://developers.google.com/merchant/ucp)
- Platform dependency for reach

**DNS-AID complements A2A** by providing neutral, decentralized discovery — find agents anywhere, not just through Google.

### Understanding the .agent Domain Approach

The [Agent Community](https://agentcommunity.org/) is pursuing a `.agent` top-level domain through ICANN's [new gTLD program](https://newgtlds.icann.org/). Here's how the two approaches compare:

**How .agent Domains Would Work:**
1. Apply to ICANN for `.agent` gTLD (~$185,000 application fee)
2. Wait 9-20 months for ICANN approval process
3. Build registry infrastructure (Open Agent Registry, Inc.)
4. Sell `.agent` domains through accredited registrars
5. Users pay annual registration fees (~$15-50/year per domain)

**How DNS-AID Works:**
1. Use your existing domain (you already own `yourcompany.com`)
2. Add DNS-AID records to your zone (`_myagent._mcp._agents.yourcompany.com`)
3. Start discovering and being discovered immediately

| Factor | .agent gTLD | DNS-AID |
|--------|-------------|---------|
| **Cost to publish** | ~$15-50/year domain fee | Free (use existing domain) |
| **Time to start** | Months (gTLD launch + registration) | Minutes |
| **Who controls discovery** | Registry operator | You (your domain) |
| **Works today** | ❌ Pending ICANN approval | ✅ Works now |
| **Requires new infrastructure** | ✅ Registry, registrars | ❌ Uses existing DNS |
| **Memorable names** | ✅ `myagent.agent` | `_myagent._mcp._agents.example.com` |

**The Friendly Take:**

Both approaches share the goal of making AI agents discoverable. The `.agent` gTLD creates a dedicated namespace that's easy to remember (`mycompany.agent`), while DNS-AID leverages existing infrastructure so you can start publishing agents today.

DNS-AID doesn't require waiting for ICANN approval or paying for new domains—it works with the DNS infrastructure your organization already operates. If you own `example.com`, you can publish agents to `_myagent._mcp._agents.example.com` right now.

*Fun fact: When `.agent` domains become available, DNS-AID records will work on them too! The approaches are complementary.*

## Examples

See the `examples/` directory:

- `demo_route53.py` - Basic Route 53 publish/discover
- `demo_full.py` - Complete end-to-end demonstration

```bash
# Run the full demo
export DNS_AID_TEST_ZONE="your-zone.com"
python examples/demo_full.py
```

## Development

```bash
# Clone the repo
git clone https://github.com/infobloxopen/dns-aid-core
cd dns-aid-core

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[all]"

# Run tests
pytest

# Run with coverage
pytest --cov=dns_aid
```

## Related Standards

- [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html) - SVCB and HTTPS Resource Records
- [RFC 4033-4035](https://www.rfc-editor.org/rfc/rfc4033.html) - DNSSEC
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698.html) - DANE TLSA

## Governance

DNS-AID is intended for contribution to the [Linux Foundation Agent AI Foundation](https://lfaidata.foundation/). All contributions are subject to the Developer Certificate of Origin (DCO). See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Apache 2.0

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
