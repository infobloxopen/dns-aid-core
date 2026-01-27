# Changelog

All notable changes to DNS-AID will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.8] - 2026-01-27

### Added
- **BANDAID Custom SVCB Parameters (IETF Draft Alignment)**
  - `cap` — URI to capability document (HTTPS endpoint for rich capability metadata)
  - `cap-sha256` — Base64url-encoded SHA-256 digest of capability descriptor for integrity checks
  - `bap` — Supported bulk agent protocols with versioning (e.g., `mcp/1,a2a/1`)
  - `policy` — URI to agent policy document (jurisdiction/compliance signaling)
  - `realm` — Multi-tenant scope identifier for federated agent environments
  - New `AgentRecord` fields: `cap_uri`, `cap_sha256`, `bap`, `policy_uri`, `realm`
  - Updated `to_svcb_params()` to include custom params when present (backwards compatible)
  - CLI options: `--cap-uri`, `--cap-sha256`, `--bap`, `--policy-uri`, `--realm`
  - MCP server: publish and discover tools support all BANDAID custom params
  - Discovery priority: SVCB `cap` URI → fetch capability document → TXT fallback

- **Capability Document Fetcher** (`src/dns_aid/core/cap_fetcher.py`)
  - Fetch and parse agent capability documents from `cap` URI
  - Returns structured `CapabilityDocument` with capabilities, version, description, use_cases
  - Graceful fallback to TXT record capabilities on fetch failure
  - 12 unit tests covering success, failure, timeout, and malformed responses

- **Discovery Capability Source Transparency**
  - `capability_source` field on discovered agents: `cap_uri`, `txt_fallback`, or `none`
  - JSON output includes `cap_uri`, `cap_sha256`, `bap`, `policy_uri`, `realm` when present

- **HTTP Index Capabilities + Capability Document Endpoint**
  - HTTP index now includes `capabilities` list inline per agent (e.g., `["travel", "booking", "reservations"]`)
  - New `/cap/{agent-name}` endpoint serves per-agent capability documents as JSON
  - Flow Visualizer HTTP Index tab now shows capabilities in step cards and summary table
  - Capability document format: capabilities, version, description, protocols, modality

### Changed
- Discovery flow now tries SVCB `cap` URI first, falls back to TXT capabilities
- `bap` field uses versioned protocol identifiers (`mcp/1` instead of bare `mcp`)
- HTTP Index discovery now extracts and displays agent capabilities from index JSON
- Flow Visualizer summary table for HTTP mode includes Capabilities column

## [0.4.1] - 2026-01-20

### Added
- **HTTP Index Discovery (ANS-Compatible)**
  - New `use_http_index` parameter for `discover()` function
  - Supports ANS-style HTTP index endpoint: `https://_index._aiagents.{domain}/index-wellknown`
  - Falls back to well-known paths: `/.well-known/agents-index.json`, `/.well-known/agents.json`
  - Richer metadata support: descriptions, model cards, modality, costs
  - CLI flag: `dns-aid discover example.com --use-http-index`
  - MCP tool parameter: `discover_agents_via_dns(..., use_http_index=True)`
  - New core module: `src/dns_aid/core/http_index.py`
  - 29 unit tests for HTTP index functionality
  - Demo Lambda handler for workshop demonstrations

- **DDNS Backend (RFC 2136)**
  - New `DDNSBackend` for universal DNS server support
  - Works with BIND9, Windows DNS, PowerDNS, Knot DNS, and any RFC 2136 compliant server
  - TSIG authentication support with multiple algorithms (hmac-sha256, sha384, sha512, sha224, md5)
  - Key file loading support (BIND key file format)
  - Full BANDAID compliance with ServiceMode SVCB records
  - Docker-based BIND9 integration tests
  - Documentation and examples for on-premise DNS deployments

## [0.3.1] - 2026-01-16

### Fixed
- **httpx Client Event Loop Bug** (Cloudflare & Infoblox backends)
  - Fixed "Event loop is closed" error when CLI runs sequential async operations
  - Affects `publish` → auto-index update and `delete` → auto-index update flows
  - Root cause: httpx.AsyncClient cached across multiple `asyncio.run()` calls
  - Fix: Track event loop ID and recreate client when loop changes

## [0.3.0] - 2026-01-16

### Added
- **Agent Index Management** (`_index._agents.*` TXT records)
  - New `dns-aid index list <domain>` command to view agents in a domain's index
  - New `dns-aid index sync <domain>` command to sync index with actual DNS records
  - Automatic index updates on `publish` (creates/updates index record)
  - Automatic index removal on `delete` (removes agent from index)
  - `--no-update-index` flag for publish/delete to skip index updates
  - RFC draft Section 3.2 compliant: enables single-query discovery
  - Index format: `_index._agents.{domain}. TXT "agents=name1:proto1,name2:proto2,..."`

- **MCP Server Index Tools**
  - New `list_agent_index` tool to view domain's agent index
  - New `sync_agent_index` tool to rebuild index from DNS records
  - Added `update_index` parameter to `publish_agent_to_dns` (default: true)
  - Added `update_index` parameter to `delete_agent_from_dns` (default: true)

- **New Core Module** (`src/dns_aid/core/indexer.py`)
  - `read_index()` - Read `_index._agents.*` TXT record
  - `update_index()` - Add/remove agents from index (read-modify-write)
  - `delete_index()` - Remove entire index record
  - `sync_index()` - Scan DNS and rebuild index from actual records
  - `IndexEntry` dataclass for agent entries
  - `IndexResult` dataclass for operation results

### Changed
- `publish` command now auto-creates/updates the domain's agent index by default
- `delete` command now auto-removes the agent from the domain's index by default
- MockBackend now returns `values` at top level (consistent with Route53 backend)
- Test suite expanded to 607 unit tests (34 new indexer tests)

### Fixed
- MockBackend `list_records` now uses substring matching (consistent with Route53)

## [0.2.1] - 2026-01-15

### Added
- **Cloudflare DNS Backend**
  - New `CloudflareBackend` for Cloudflare DNS API v4
  - Free tier support - ideal for demos and workshops
  - Full BANDAID compliance with ServiceMode SVCB records
  - Zone auto-discovery from domain name
  - 32 unit tests with mocked API responses

### Changed
- CLI `--backend` option now accepts "cloudflare"
- Updated getting-started.md with Cloudflare setup instructions
- README updated with Cloudflare examples

## [0.2.0] - 2026-01-13

### Added
- **BANDAID Compliance**
  - Added `mandatory="alpn,port"` parameter to SVCB records per IETF draft
  - Ensures proper agent discovery signaling

- **Top-Level API Improvements**
  - Exported `unpublish()` and `delete()` (alias) to top-level API
  - Simpler imports: `from dns_aid import publish, unpublish, delete`

- **MCP E2E Test Script** (`scripts/test_mcp_e2e.py`)
  - Automated testing of all MCP tools via HTTP transport
  - Auto-start capability for MCP server
  - Full publish/discover/verify/list/delete cycle

- **Demo Guide** (`docs/demo-guide.md`)
  - Step-by-step demonstration guide for conferences
  - Quick Checklist for pre-demo verification
  - ngrok integration with `ngrok-skip-browser-warning` header
  - Python library E2E script example

- **Infoblox BloxOne Backend**
  - Full support for BloxOne Cloud API
  - DNS view configuration support
  - SVCB and TXT record creation/deletion
  - Zone listing and verification
  - Integration tests with real API

- **E2E Integration Tests** (`tests/integration/test_e2e.py`)
  - Full publish → discover → verify → delete workflow test
  - Multi-protocol discovery test (MCP + A2A)
  - Security scoring verification
  - Capabilities roundtrip test

- **Documentation**
  - CODE_OF_CONDUCT.md (Contributor Covenant 2.1)
  - Comprehensive Infoblox setup guide
  - Troubleshooting guide for both backends

### Changed
- Test suite expanded to 126 unit tests + 19 integration tests (from 108 in v0.1.0)

### Planned
- Cloudflare DNS backend
- Infoblox NIOS backend (on-prem)
- Agent capability negotiation
- Multi-region discovery

## [0.1.0] - 2026-01-13

### Added
- **Core Protocol Implementation**
  - SVCB record support per RFC 9460
  - TXT record metadata for capabilities and versioning
  - DNS-AID naming convention: `_{agent}._{protocol}._agents.{domain}`
  - Support for MCP (Model Context Protocol) and A2A (Agent-to-Agent) protocols

- **Python Library**
  - `publish()` - Publish agents to DNS
  - `discover()` - Discover agents at a domain
  - `verify()` - Verify DNS-AID records with security scoring
  - Pydantic models with full validation
  - Async/await throughout

- **CLI Interface** (`dns-aid`)
  - `dns-aid publish` - Publish agent records
  - `dns-aid discover` - Find agents at a domain
  - `dns-aid verify` - Check DNS record validity
  - `dns-aid list` - List all agents in a zone
  - `dns-aid delete` - Remove agent records
  - `dns-aid zones` - List available DNS zones
  - Rich terminal output with tables and colors

- **MCP Server** (`dns-aid-mcp`)
  - 5 MCP tools for AI agent integration
  - Stdio transport for Claude Desktop
  - HTTP transport with health endpoints
  - `/health`, `/ready`, `/` endpoints for orchestration

- **DNS Backends**
  - AWS Route 53 backend (production-ready)
  - Mock backend for testing

- **Security Features**
  - Comprehensive input validation (RFC 1035 compliant)
  - DNSSEC validation support
  - DANE/TLSA advisory checking
  - Security scoring (0-100) for agents
  - Default localhost binding for HTTP transport

- **Developer Experience**
  - Type hints throughout
  - Structured logging with structlog
  - Comprehensive test suite (108 tests)
  - GitHub Actions CI/CD pipeline
  - Docker support with multi-stage builds

### Security
- All inputs validated against DNS naming standards
- No hardcoded credentials
- Bandit security scanning in CI
- Dependency vulnerability checking with pip-audit

### Documentation
- Comprehensive README with examples
- Getting Started guide with AWS setup
- Security policy and vulnerability reporting
- Contributing guidelines

## References

- [IETF draft-mozleywilliams-dnsop-bandaid-02](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-bandaid/)
- [RFC 9460 - SVCB and HTTPS Resource Records](https://www.rfc-editor.org/rfc/rfc9460.html)
- [RFC 4033-4035 - DNSSEC](https://www.rfc-editor.org/rfc/rfc4033.html)

[Unreleased]: https://github.com/iracic82/dns-aid-core/compare/v0.4.8...HEAD
[0.4.8]: https://github.com/iracic82/dns-aid-core/compare/v0.4.7...v0.4.8
[0.3.1]: https://github.com/iracic82/dns-aid-core/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/iracic82/dns-aid-core/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/iracic82/dns-aid-core/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/iracic82/dns-aid-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/iracic82/dns-aid-core/releases/tag/v0.1.0
