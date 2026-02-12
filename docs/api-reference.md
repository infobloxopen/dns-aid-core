# DNS-AID API Reference

Complete API documentation for DNS-AID - DNS-based Agent Identification and Discovery.

## Table of Contents

- [Quick Start](#quick-start)
- [Core Functions](#core-functions)
  - [publish()](#publish)
  - [discover()](#discover)
  - [verify()](#verify)
- [Data Models](#data-models)
  - [AgentRecord](#agentrecord)
  - [DiscoveryResult](#discoveryresult)
  - [PublishResult](#publishresult)
  - [VerifyResult](#verifyresult)
  - [Protocol](#protocol)
- [Backends](#backends)
  - [DNSBackend Interface](#dnsbackend-interface)
  - [Route53Backend](#route53backend)
  - [InfobloxBloxOneBackend](#infobloxbloxonebackend)
  - [CloudflareBackend](#cloudflarebackend)
  - [DDNSBackend](#ddnsbackend)
  - [MockBackend](#mockbackend)
- [Kubernetes Controller (Planned)](#kubernetes-controller-planned)
  - [apply()](#apply)
  - [DesiredAgentState](#desiredagentstate)
  - [Annotations](#annotations)
- [JWS Signatures](#jws-signatures)
  - [generate_keypair()](#generate_keypair)
  - [sign_record()](#sign_record)
  - [verify_signature()](#verify_signature)
- [Validation Utilities](#validation-utilities)
- [CLI Reference](#cli-reference)
- [MCP Server](#mcp-server)
- [SDK: Invocation & Telemetry](#sdk-invocation--telemetry)
  - [AgentClient](#agentclient)
  - [SDKConfig](#sdkconfig)
  - [InvocationResult](#invocationresult)
  - [InvocationSignal](#invocationsignal)
  - [Ranking](#ranking)

---

## Quick Start

```python
import asyncio
from dns_aid import publish, discover, verify, Protocol

async def main():
    # Publish an agent
    result = await publish(
        name="my-agent",
        domain="example.com",
        protocol="mcp",
        endpoint="agent.example.com",
        capabilities=["chat", "code-review"],
    )

    # Discover agents at a domain
    discovery = await discover("example.com", protocol=Protocol.MCP)

    # Verify an agent's DNS records
    verification = await verify("_my-agent._mcp._agents.example.com")

asyncio.run(main())
```

---

## Core Functions

### publish()

Publish an AI agent to DNS using the DNS-AID protocol.

```python
async def publish(
    name: str,
    domain: str,
    protocol: str | Protocol,
    endpoint: str,
    port: int = 443,
    capabilities: list[str] | None = None,
    version: str = "1.0.0",
    description: str | None = None,
    ttl: int = 3600,
    backend: DNSBackend | None = None,
    cap_uri: str | None = None,
    cap_sha256: str | None = None,
    bap: list[str] | None = None,
    policy_uri: str | None = None,
    realm: str | None = None,
) -> PublishResult
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | `str` | Yes | - | Agent identifier (e.g., "chat", "network-specialist"). Must be DNS label format: lowercase alphanumeric with hyphens, 1-63 chars. |
| `domain` | `str` | Yes | - | Domain to publish under (e.g., "example.com") |
| `protocol` | `str \| Protocol` | Yes | - | Communication protocol: "mcp" or "a2a" |
| `endpoint` | `str` | Yes | - | Hostname where agent is reachable |
| `port` | `int` | No | 443 | Port number (1-65535) |
| `capabilities` | `list[str]` | No | `[]` | List of agent capabilities |
| `version` | `str` | No | "1.0.0" | Agent version (semver format) |
| `description` | `str` | No | `None` | Human-readable description |
| `ttl` | `int` | No | 3600 | DNS record TTL in seconds (60-86400) |
| `backend` | `DNSBackend` | No | `None` | DNS backend to use (uses default if None) |
| `cap_uri` | `str` | No | `None` | URI to capability document (BANDAID custom param) |
| `cap_sha256` | `str` | No | `None` | Base64url SHA-256 digest of capability descriptor |
| `bap` | `list[str]` | No | `None` | Supported protocols with versions (e.g., `["mcp/1", "a2a/1"]`) |
| `policy_uri` | `str` | No | `None` | URI to agent policy document |
| `realm` | `str` | No | `None` | Multi-tenant scope identifier |

#### Returns

`PublishResult` - Contains the published agent and created DNS records.

#### Example

```python
from dns_aid import publish

result = await publish(
    name="network-specialist",
    domain="example.com",
    protocol="mcp",
    endpoint="mcp.example.com",
    capabilities=["ipam", "dns", "vpn"],
    ttl=300,
)

if result.success:
    print(f"Published: {result.agent.fqdn}")
    print(f"Records: {result.records_created}")
else:
    print(f"Failed: {result.message}")
```

#### DNS Records Created

- **SVCB**: `_{name}._{protocol}._agents.{domain}` → Service binding record
- **TXT**: `_{name}._{protocol}._agents.{domain}` → Capabilities and metadata

---

### discover()

Discover AI agents at a domain using DNS-AID protocol.

```python
async def discover(
    domain: str,
    protocol: str | Protocol | None = None,
    name: str | None = None,
    require_dnssec: bool = False,
    use_http_index: bool = False,
) -> DiscoveryResult
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `domain` | `str` | Yes | - | Domain to search for agents |
| `protocol` | `str \| Protocol` | No | `None` | Filter by protocol (None for all) |
| `name` | `str` | No | `None` | Filter by specific agent name |
| `require_dnssec` | `bool` | No | `False` | Require DNSSEC validation |
| `use_http_index` | `bool` | No | `False` | Use HTTP index endpoint instead of DNS-only discovery |

#### Discovery Methods

| Method | Endpoint | Use Case |
|--------|----------|----------|
| **DNS (default)** | `_index._agents.{domain}` TXT record | Decentralized, cached, minimal round trips |
| **HTTP Index** | `https://_index._aiagents.{domain}/index-wellknown` | ANS-compatible, rich metadata (descriptions, model cards) |

#### Returns

`DiscoveryResult` - Contains list of discovered agents and query metadata.

#### Example

```python
from dns_aid import discover, Protocol

# Discover all agents (pure DNS - default)
result = await discover("example.com")

# Discover MCP agents only
result = await discover("example.com", protocol=Protocol.MCP)

# Discover specific agent
result = await discover("example.com", protocol="mcp", name="chat")

# Discover via HTTP index (ANS-compatible, richer metadata)
result = await discover("example.com", use_http_index=True)

for agent in result.agents:
    print(f"{agent.name}: {agent.endpoint_url}")
    print(f"  Capabilities: {', '.join(agent.capabilities)}")
    if agent.description:
        print(f"  Description: {agent.description}")
```

---

### verify()

Verify DNS-AID records for an agent with security validation.

```python
async def verify(fqdn: str) -> VerifyResult
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fqdn` | `str` | Yes | Fully qualified domain name (e.g., "_chat._mcp._agents.example.com") |

#### Returns

`VerifyResult` - Contains security validation results and score.

#### Example

```python
from dns_aid import verify

result = await verify("_chat._mcp._agents.example.com")

print(f"Record exists: {result.record_exists}")
print(f"DNSSEC valid: {result.dnssec_valid}")
print(f"Security Score: {result.security_score}/100")
print(f"Rating: {result.security_rating}")
```

---

## Data Models

### AgentRecord

Represents an AI agent published via DNS-AID.

```python
from dns_aid import AgentRecord, Protocol

agent = AgentRecord(
    name="network-specialist",
    domain="example.com",
    protocol=Protocol.MCP,
    target_host="mcp.example.com",
    port=443,
    capabilities=["ipam", "dns", "vpn"],
    version="1.0.0",
    description="Network automation agent",
    ttl=3600,
)
```

#### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | `str` | Yes | - | Agent identifier (1-63 chars, DNS label format) |
| `domain` | `str` | Yes | - | Domain where agent is published |
| `protocol` | `Protocol` | Yes | - | Communication protocol |
| `target_host` | `str` | Yes | - | Hostname where agent is reachable |
| `port` | `int` | No | 443 | Port number |
| `ipv4_hint` | `str` | No | `None` | IPv4 address hint |
| `ipv6_hint` | `str` | No | `None` | IPv6 address hint |
| `capabilities` | `list[str]` | No | `[]` | Agent capabilities |
| `version` | `str` | No | "1.0.0" | Agent version |
| `description` | `str` | No | `None` | Description |
| `ttl` | `int` | No | 3600 | DNS TTL (60-86400) |
| `cap_uri` | `str` | No | `None` | URI to capability document (BANDAID) |
| `cap_sha256` | `str` | No | `None` | SHA-256 digest of capability descriptor |
| `bap` | `list[str]` | No | `[]` | Supported protocols with versions |
| `policy_uri` | `str` | No | `None` | URI to agent policy document |
| `realm` | `str` | No | `None` | Multi-tenant scope identifier |
| `capability_source` | `str` | No | `None` | Where capabilities came from: `cap_uri`, `txt_fallback`, `none` |
| `endpoint_source` | `str` | No | `None` | Where endpoint came from: `dns_svcb`, `http_index_fallback`, `direct` |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `fqdn` | `str` | Full DNS-AID record name: `_{name}._{protocol}._agents.{domain}` |
| `endpoint_url` | `str` | Full URL: `https://{target_host}:{port}` |
| `svcb_target` | `str` | SVCB target with trailing dot |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `to_svcb_params()` | `dict[str, str]` | SVCB record parameters |
| `to_txt_values()` | `list[str]` | TXT record values |

---

### DiscoveryResult

Result of a DNS-AID discovery query.

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `query` | `str` | DNS query made |
| `domain` | `str` | Domain that was queried |
| `agents` | `list[AgentRecord]` | Discovered agents |
| `dnssec_validated` | `bool` | Whether DNSSEC was verified |
| `cached` | `bool` | Whether result was cached |
| `query_time_ms` | `float` | Query latency in milliseconds |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `count` | `int` | Number of agents discovered |

---

### PublishResult

Result of publishing an agent to DNS.

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `agent` | `AgentRecord` | The published agent |
| `records_created` | `list[str]` | DNS records created |
| `zone` | `str` | DNS zone used |
| `backend` | `str` | DNS backend used |
| `success` | `bool` | Whether publish succeeded |
| `message` | `str \| None` | Status message |

---

### VerifyResult

Result of verifying an agent's DNS records.

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `fqdn` | `str` | FQDN that was verified |
| `record_exists` | `bool` | DNS record exists |
| `svcb_valid` | `bool` | SVCB record is valid |
| `dnssec_valid` | `bool` | DNSSEC chain validated |
| `dane_valid` | `bool \| None` | DANE/TLSA verified |
| `endpoint_reachable` | `bool` | Endpoint responds |
| `endpoint_latency_ms` | `float \| None` | Response time |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `security_score` | `int` | Security score (0-100) |
| `security_rating` | `str` | "Excellent", "Good", "Fair", or "Poor" |

#### Security Scoring

| Check | Points |
|-------|--------|
| Record exists | 20 |
| SVCB valid | 20 |
| DNSSEC valid | 30 |
| DANE valid | 15 |
| Endpoint reachable | 15 |
| **Total** | **100** |

---

### Protocol

Enumeration of supported agent communication protocols.

```python
from dns_aid import Protocol

Protocol.MCP   # Model Context Protocol (Anthropic)
Protocol.A2A   # Agent-to-Agent (Google)
Protocol.HTTPS # Standard HTTPS
```

---

## Backends

### DNSBackend Interface

Abstract base class for DNS providers.

```python
from dns_aid.backends.base import DNSBackend

class CustomBackend(DNSBackend):
    @property
    def name(self) -> str:
        return "custom"

    async def create_svcb_record(self, zone, name, priority, target, params, ttl) -> str:
        ...

    async def create_txt_record(self, zone, name, values, ttl) -> str:
        ...

    async def delete_record(self, zone, name, record_type) -> bool:
        ...

    async def list_records(self, zone, name_pattern, record_type):
        ...

    async def zone_exists(self, zone) -> bool:
        ...
```

### Route53Backend

AWS Route 53 implementation.

```python
from dns_aid.backends.route53 import Route53Backend

# Auto-discover zones from AWS
backend = Route53Backend()

# Or specify zone ID directly
backend = Route53Backend(zone_id="Z1234567890ABC")

# Use with publish
from dns_aid import publish
from dns_aid.core.publisher import set_default_backend

set_default_backend(backend)
result = await publish(name="my-agent", ...)
```

**Requirements**: `pip install dns-aid[route53]` and AWS credentials configured.

### InfobloxBloxOneBackend

Infoblox UDDI (Universal DDI) implementation.

```python
from dns_aid.backends.infoblox import InfobloxBloxOneBackend

# From environment variables (recommended)
backend = InfobloxBloxOneBackend()

# Or with explicit configuration
backend = InfobloxBloxOneBackend(
    api_key="your-api-key",
    dns_view="default",  # DNS view name
    base_url="https://csp.infoblox.com",  # Optional
)

# Use as context manager
async with InfobloxBloxOneBackend() as backend:
    zones = await backend.list_zones()
    print(zones)
```

**Environment Variables**:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `INFOBLOX_API_KEY` | Yes | - | Infoblox UDDI API key |
| `INFOBLOX_DNS_VIEW` | No | `default` | DNS view name |
| `INFOBLOX_BASE_URL` | No | `https://csp.infoblox.com` | API URL |

**⚠️ BANDAID Compliance**: Infoblox UDDI is **not fully compliant** with the [BANDAID draft](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-bandaid/). It only supports alias mode SVCB (priority 0) and lacks `alpn`, `port`, and `mandatory` parameters. For full compliance, use Route53Backend or DDNSBackend.

### DDNSBackend

RFC 2136 Dynamic DNS implementation. Works with BIND, Windows DNS, PowerDNS, Knot DNS, and any RFC 2136 compliant server.

```python
from dns_aid.backends.ddns import DDNSBackend

# From environment variables (recommended)
backend = DDNSBackend()

# Or with explicit configuration
backend = DDNSBackend(
    server="ns1.example.com",
    key_name="dns-aid-key",
    key_secret="YourBase64SecretHere==",
    key_algorithm="hmac-sha256",  # default
    port=53,                       # default
    timeout=10.0,                  # default
)

# Or load from BIND key file
backend = DDNSBackend(key_file="/etc/bind/dns-aid-key.conf")

# Use as context manager
async with DDNSBackend() as backend:
    exists = await backend.zone_exists("example.com")
```

**Environment Variables**:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DDNS_SERVER` | Yes | - | DNS server hostname or IP |
| `DDNS_KEY_NAME` | Yes | - | TSIG key name |
| `DDNS_KEY_SECRET` | Yes | - | TSIG key secret (base64) |
| `DDNS_KEY_ALGORITHM` | No | `hmac-sha256` | TSIG algorithm |
| `DDNS_PORT` | No | `53` | DNS server port |
| `DDNS_TIMEOUT` | No | `10` | Query timeout in seconds |

**Supported TSIG Algorithms**:
- `hmac-sha256` (recommended)
- `hmac-sha384`
- `hmac-sha512`
- `hmac-sha224`
- `hmac-md5` (legacy)

**Full BANDAID Compliance**: DDNSBackend supports ServiceMode SVCB records (priority > 0) with all required parameters (`alpn`, `port`, `mandatory`).

### MockBackend

In-memory backend for testing.

```python
from dns_aid.backends.mock import MockBackend

backend = MockBackend()

# Pre-populate zones
backend = MockBackend(zones={"example.com": {}})
```

---

## Kubernetes Controller (Planned)

> **Status: Planned** — The Kubernetes controller is not yet implemented in dns-aid-core.
> The API below documents the intended interface for a future release.

The K8s controller will automatically publish agents based on Service/Ingress annotations.

### apply()

Idempotent reconciliation function - the core contract for the K8s controller.

```python
from dns_aid.k8s import apply, DesiredAgentState

async def apply(
    desired: DesiredAgentState,
    backend: DNSBackend | None = None,
) -> ApplyResult:
    """
    Idempotent reconciliation: converge DNS toward desired state.

    - If agent should exist: create/update SVCB + TXT records
    - If agent should be absent: delete records
    - Returns result with action taken and drift information
    """
```

**Returns:** `ApplyResult` with:
- `action`: `ReconcileAction` (CREATED, UPDATED, DELETED, UNCHANGED, FAILED)
- `identity`: Stable identity of the agent
- `fqdn`: Fully qualified domain name
- `drift_detected`: Whether drift was detected
- `drift_details`: Details of detected drift

### DesiredAgentState

Model representing desired DNS state, computed from K8s annotations.

```python
from dns_aid.k8s.models import DesiredAgentState

state = DesiredAgentState(
    identity="prod-cluster/default/payment-service",  # {cluster}/{namespace}/{name}
    domain="agents.example.com",
    agent_name="payment",
    protocol="mcp",
    endpoint="payment.svc.cluster.local",
    port=443,
    capabilities=["payment", "invoice"],
    version="1.0.0",
    ttl=300,
    absent=False,  # Set True for deletion
)
```

### Annotations

K8s Service/Ingress annotations recognized by the controller:

| Annotation | Required | Description |
|------------|----------|-------------|
| `dns-aid.io/agent-name` | Yes | Agent identifier (DNS label format) |
| `dns-aid.io/protocol` | Yes | Protocol: `mcp`, `a2a`, or `https` |
| `dns-aid.io/domain` | Yes | Domain to publish under |
| `dns-aid.io/endpoint` | No | Override auto-detected endpoint |
| `dns-aid.io/port` | No | Override port (default: first service port) |
| `dns-aid.io/capabilities` | No | Comma-separated capabilities |
| `dns-aid.io/version` | No | Agent version string |
| `dns-aid.io/description` | No | Human-readable description |
| `dns-aid.io/ttl` | No | DNS record TTL (default: 300) |
| `dns-aid.io/cap-uri` | No | URI to capability document |

---

## JWS Signatures

Application-layer signature verification as an alternative to DNSSEC.

### generate_keypair()

Generate an EC P-256 keypair for signing DNS records.

```python
from dns_aid.core.jwks import generate_keypair

private_key, public_key = generate_keypair()
# private_key: EllipticCurvePrivateKey
# public_key: EllipticCurvePublicKey
```

### export_jwks()

Export public key as JWKS JSON for hosting at `.well-known/dns-aid-jwks.json`.

```python
from dns_aid.core.jwks import export_jwks

jwks_dict = export_jwks(public_key, kid="dns-aid-2024")
# {
#   "keys": [{
#     "kty": "EC",
#     "crv": "P-256",
#     "kid": "dns-aid-2024",
#     "use": "sig",
#     "x": "...",
#     "y": "..."
#   }]
# }
```

### sign_record()

Sign a DNS record payload with a private key.

```python
from dns_aid.core.jwks import sign_record, RecordPayload

payload = RecordPayload(
    fqdn="_payment._mcp._agents.example.com",
    target="payment.example.com",
    port=443,
    alpn="mcp",
)

jws_compact = sign_record(payload, private_key)
# Returns: "eyJhbGciOiJFUzI1NiIs..."
```

### verify_signature()

Verify a JWS signature against a public key.

```python
from dns_aid.core.jwks import verify_signature

is_valid, payload = verify_signature(jws_compact, public_key)
# is_valid: bool
# payload: RecordPayload if valid, None if invalid
```

### Publishing with Signatures

```python
from dns_aid import publish

result = await publish(
    name="payment",
    domain="example.com",
    protocol="mcp",
    endpoint="payment.example.com",
    sign=True,
    private_key_path="./keys/private.pem",
)
```

### Discovery with Verification

```python
from dns_aid import discover

agents = await discover(
    "example.com",
    verify_signatures=True,  # Verify JWS sig= parameter
)
```

---

## Validation Utilities

Input validation functions for security compliance.

```python
from dns_aid.utils.validation import (
    validate_agent_name,
    validate_domain,
    validate_protocol,
    validate_endpoint,
    validate_port,
    validate_ttl,
    validate_capabilities,
    validate_fqdn,
    ValidationError,
)
```

### Functions

| Function | Input | Returns | Description |
|----------|-------|---------|-------------|
| `validate_agent_name(name)` | `str` | `str` | Validate/normalize agent name |
| `validate_domain(domain)` | `str` | `str` | Validate/normalize domain |
| `validate_protocol(protocol)` | `str` | `Literal["mcp", "a2a"]` | Validate protocol |
| `validate_endpoint(endpoint)` | `str` | `str` | Validate endpoint hostname |
| `validate_port(port)` | `int` | `int` | Validate port (1-65535) |
| `validate_ttl(ttl)` | `int` | `int` | Validate TTL (60-604800) |
| `validate_capabilities(caps)` | `list[str]` | `list[str]` | Validate capability list |
| `validate_fqdn(fqdn)` | `str` | `str` | Validate DNS-AID FQDN |

### ValidationError

Custom exception with structured error details.

```python
try:
    validate_agent_name("INVALID NAME!")
except ValidationError as e:
    print(f"Field: {e.field}")
    print(f"Message: {e.message}")
    print(f"Value: {e.value}")
```

---

## CLI Reference

The `dns-aid` CLI provides command-line access to all DNS-AID functions.

### Commands

```bash
# Publish an agent (auto-updates index)
dns-aid publish --name my-agent --domain example.com --protocol mcp \
    --endpoint agent.example.com --capability chat --capability code

# Publish without updating index
dns-aid publish --name internal-bot --domain example.com --protocol mcp \
    --endpoint bot.example.com --no-update-index

# Discover agents (pure DNS - default)
dns-aid discover example.com
dns-aid discover example.com --protocol mcp

# Discover via HTTP index (ANS-compatible)
dns-aid discover example.com --use-http-index

# Verify an agent
dns-aid verify _my-agent._mcp._agents.example.com

# List all agents in a zone
dns-aid list example.com

# Delete an agent (auto-removes from index)
dns-aid delete --name my-agent --domain example.com --protocol mcp --force

# Delete without updating index
dns-aid delete --name my-agent --domain example.com --protocol mcp --force --no-update-index

# List available DNS zones
dns-aid zones

# Agent Index Commands
dns-aid index list example.com           # List agents in domain's index
dns-aid index sync example.com           # Sync index with actual DNS records
```

### Environment Variables

**General:**

| Variable | Description |
|----------|-------------|
| `DNS_AID_BACKEND` | Default backend: "route53", "bloxone", "ddns", or "mock" |
| `DNS_AID_LOG_LEVEL` | Logging level: DEBUG, INFO, WARNING, ERROR |

**AWS Route 53:**

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `AWS_DEFAULT_REGION` | AWS region (default: us-east-1) |
| `AWS_PROFILE` | AWS CLI profile name |

**Infoblox UDDI:**

| Variable | Description |
|----------|-------------|
| `INFOBLOX_API_KEY` | Infoblox UDDI API key (required) |
| `INFOBLOX_DNS_VIEW` | DNS view name (default: "default") |
| `INFOBLOX_BASE_URL` | API URL (default: https://csp.infoblox.com) |

**DDNS (RFC 2136):**

| Variable | Description |
|----------|-------------|
| `DDNS_SERVER` | DNS server hostname or IP (required) |
| `DDNS_KEY_NAME` | TSIG key name (required) |
| `DDNS_KEY_SECRET` | TSIG key secret, base64 (required) |
| `DDNS_KEY_ALGORITHM` | TSIG algorithm (default: hmac-sha256) |
| `DDNS_PORT` | DNS server port (default: 53) |

---

## MCP Server

The MCP server (`dns-aid-mcp`) exposes DNS-AID as tools for AI assistants.

### Starting the Server

```bash
# Stdio transport (for Claude Desktop)
dns-aid-mcp

# HTTP transport (for remote access)
dns-aid-mcp --transport http --port 8000

# HTTP with custom host binding
dns-aid-mcp --transport http --host 0.0.0.0 --port 8000
```

### Available Tools

| Tool | Description |
|------|-------------|
| `publish_agent_to_dns` | Publish an agent to DNS (auto-updates index) |
| `discover_agents_via_dns` | Discover agents at a domain (supports `use_http_index` param) |
| `verify_agent_dns` | Verify agent DNS records |
| `list_published_agents` | List all agents in a zone |
| `delete_agent_from_dns` | Delete an agent from DNS (auto-updates index) |
| `list_agent_index` | List agents in domain's index |
| `sync_agent_index` | Sync index with actual DNS records |

### Health Endpoints (HTTP Transport)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Server info and available tools |
| `/health` | GET | Basic health check |
| `/ready` | GET | Readiness check (DNS backend available) |

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

---

## Error Handling

All functions may raise exceptions. Recommended pattern:

```python
from dns_aid import publish, discover
from dns_aid.utils.validation import ValidationError

try:
    result = await publish(
        name="my-agent",
        domain="example.com",
        protocol="mcp",
        endpoint="agent.example.com",
    )
    if not result.success:
        print(f"Publish failed: {result.message}")
except ValidationError as e:
    print(f"Invalid input: {e.field} - {e.message}")
except Exception as e:
    print(f"Unexpected error: {e}")
```


## SDK: Invocation & Telemetry

The Tier 1 SDK provides agent invocation with automatic telemetry capture, and community-wide ranking queries.

### Top-Level Functions

#### invoke()

```python
async def invoke(
    agent: AgentRecord,
    *,
    method: str | None = None,
    arguments: dict | None = None,
    timeout: float | None = None,
    config: SDKConfig | None = None,
) -> InvocationResult
```

One-shot agent invocation with telemetry. Creates an AgentClient, calls the agent, returns the result with an attached signal.

**Example:**
```python
import dns_aid

result = await dns_aid.discover("example.com", protocol="mcp")
resp = await dns_aid.invoke(result.agents[0], method="tools/list")
print(resp.signal.invocation_latency_ms)  # 148.2
```

#### rank()

```python
async def rank(
    agents: list[AgentRecord],
    *,
    method: str | None = None,
    arguments: dict | None = None,
    config: SDKConfig | None = None,
) -> list[RankedAgent]
```

Invoke multiple agents and rank by telemetry performance (composite score).

### AgentClient

The main SDK class. Use as async context manager for connection reuse.

```python
from dns_aid.sdk import AgentClient, SDKConfig

config = SDKConfig(timeout_seconds=30.0, caller_id="my-app")

async with AgentClient(config=config) as client:
    result = await client.invoke(agent, method="tools/list")
    ranked = client.rank()
```

**Methods:**

| Method | Description |
|--------|-------------|
| `invoke(agent, method, arguments, timeout)` | Invoke agent, return `InvocationResult` |
| `rank(strategy)` | Rank all invoked agents by composite score |
| `fetch_rankings(fqdns, limit)` | Fetch community-wide rankings from telemetry API |
| `signals` | Property: list of all collected `InvocationSignal` objects |

#### fetch_rankings()

```python
async def fetch_rankings(
    self,
    fqdns: list[str] | None = None,
    limit: int = 50,
) -> list[dict]
```

Fetch community-wide rankings from the central telemetry API. Returns pre-computed composite scores based on aggregated telemetry from all SDK users.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `fqdns` | `list[str] \| None` | `None` | Filter rankings to specific agent FQDNs |
| `limit` | `int` | `50` | Maximum number of rankings to return |

**Returns:** List of ranking dictionaries with `agent_fqdn`, `composite_score`, etc.

**Example:**
```python
async with AgentClient(config) as client:
    # Get all rankings
    rankings = await client.fetch_rankings()

    # Get rankings for specific agents only
    rankings = await client.fetch_rankings(
        fqdns=["_booking._mcp._agents.example.com"],
        limit=10
    )

    for r in rankings:
        print(f"{r['agent_fqdn']}: {r['composite_score']}")
```

**Note:** Requires `telemetry_api_url` to be configured in SDKConfig. Returns empty list if not configured.

### SDKConfig

```python
from dns_aid.sdk import SDKConfig

config = SDKConfig(
    timeout_seconds=30.0,        # Default request timeout
    caller_id="my-app",          # Caller identifier for signals
    persist_signals=False,       # Auto-save signals to PostgreSQL
    database_url=None,           # DB URL (falls back to DATABASE_URL env)
    otel_enabled=False,          # Enable OpenTelemetry export
    otel_endpoint=None,          # OTLP endpoint URL
    otel_export_format="otlp",   # "otlp" or "console"
    http_push_url=None,          # POST signals to remote telemetry API
    telemetry_api_url=None,      # Base URL for fetch_rankings() queries
)

# Or from environment variables:
config = SDKConfig.from_env()
```

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_AID_SDK_TIMEOUT` | 30.0 | Request timeout in seconds |
| `DNS_AID_SDK_CALLER_ID` | None | Caller identifier |
| `DNS_AID_SDK_PERSIST_SIGNALS` | false | Enable DB persistence |
| `DATABASE_URL` | None | PostgreSQL connection URL |
| `DNS_AID_SDK_OTEL_ENABLED` | false | Enable OpenTelemetry |
| `DNS_AID_SDK_OTEL_ENDPOINT` | None | OTLP collector URL |
| `DNS_AID_SDK_HTTP_PUSH_URL` | None | POST signals to this URL |
| `DNS_AID_SDK_TELEMETRY_API_URL` | None | Base URL for fetch_rankings() queries |

### InvocationResult

Returned by `invoke()`. Contains response data and telemetry signal.

| Field | Type | Description |
|-------|------|-------------|
| `success` | bool | Whether invocation succeeded |
| `data` | dict \| str \| None | Response payload |
| `signal` | InvocationSignal | Telemetry signal for this call |
| `error_message` | str \| None | Error description if failed |

### InvocationSignal

Per-call telemetry captured automatically.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique signal identifier |
| `agent_fqdn` | str | Agent DNS-AID FQDN |
| `agent_endpoint` | str | Endpoint URL used |
| `protocol` | str | Protocol (mcp, a2a, https) |
| `method` | str | Method called |
| `status` | InvocationStatus | success, error, timeout, refused |
| `invocation_latency_ms` | float | Total invocation time |
| `ttfb_ms` | float | Time to first byte |
| `http_status_code` | int | HTTP response status |
| `cost_units` | float | Cost from X-Cost-Units header |
| `cost_currency` | str | Currency from X-Cost-Currency header |
| `response_size_bytes` | int | Response payload size |
| `tls_version` | str | TLS version used |
| `timestamp` | datetime | When the call was made |
| `caller_id` | str | Caller identifier from config |

### Ranking

```python
ranked = client.rank()  # Default: WeightedCompositeStrategy

for r in ranked:
    print(f"{r.agent_fqdn}: {r.composite_score:.1f}")
```

**Scoring Formula (WeightedComposite):**
```
composite = 0.40 * reliability   (success_rate * 100)
          + 0.30 * latency       (100 * (1 - avg_latency/5000))
          + 0.15 * cost          (relative to cheapest)
          + 0.15 * freshness     (recency weighted)
```

**Available Strategies:**
- `WeightedCompositeStrategy` (default)
- `LatencyFirstStrategy` — prioritizes lowest latency
- `ReliabilityFirstStrategy` — prioritizes highest success rate

### HTTP Telemetry Push

The SDK can push signals to a remote telemetry API for centralized monitoring:

```python
config = SDKConfig(
    http_push_url="https://api.velosecurity-ai.io/api/v1/telemetry/signals"
)

async with AgentClient(config=config) as client:
    # Signals automatically pushed to telemetry API
    await client.invoke(agent, method="tools/list")
```

**Production Endpoints:**
- **POST signals:** `https://api.velosecurity-ai.io/api/v1/telemetry/signals`
- **Dashboard:** [directory.velosecurity-ai.io/telemetry](https://directory.velosecurity-ai.io/telemetry)

**POST /api/v1/telemetry/signals**

Accepts telemetry signals from SDK clients.

```bash
curl -X POST https://api.velosecurity-ai.io/api/v1/telemetry/signals \
  -H "Content-Type: application/json" \
  -d '{
    "agent_fqdn": "_booking._mcp._agents.example.com",
    "agent_endpoint": "https://booking.example.com/mcp",
    "protocol": "mcp",
    "method": "tools/list",
    "invocation_latency_ms": 150,
    "status": "success",
    "caller_id": "my-app"
  }'
```

**Response:** `202 Accepted` with `{"accepted": 1, "signal_id": "..."}`

**Note:** The MCP server (`dns-aid-mcp`) has HTTP push enabled by default to the production API.

---

## Version

```python
import dns_aid
print(dns_aid.__version__)  # "0.6.0"
```

---

## See Also

- [Getting Started Guide](getting-started.md)
- [IETF Draft: BANDAID](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-bandaid/)
- [RFC 9460: SVCB Records](https://www.rfc-editor.org/rfc/rfc9460.html)
- [GitHub Repository](https://github.com/iracic82/dns-aid)
