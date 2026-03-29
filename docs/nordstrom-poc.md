# Nordstrom DNS-AID POC — Discovery → Policy → Threat Defense

## The Problem

Nordstrom has a "wild west" of internal AI agents across many teams. No standard way to:
- **Inventory** what agents exist (including shadow agents)
- **Tie agents** to owners, capabilities, and policies
- **Enforce controls** on who can call what

## The Solution: DNS-AID + Infoblox Threat Defense

DNS-AID adds a control plane layer using existing DNS infrastructure (BloxOne UDDI).
Agents publish their identity and policies to DNS. Threat Defense enforces them.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        NORDSTROM AI CONTROL PLANE                       │
│                                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────────────┐ │
│  │   PUBLISH    │    │   DISCOVER   │    │         ENFORCE             │ │
│  │             │    │              │    │                             │ │
│  │ Teams publish│───▶│ dns-aid finds│───▶│ Policy compiled to TD      │ │
│  │ agents to   │    │ ALL agents   │    │ named list + security      │ │
│  │ DNS via SVCB│    │ (incl shadow)│    │ policy = NXDOMAIN          │ │
│  └─────────────┘    └──────────────┘    └─────────────────────────────┘ │
│        │                   │                        │                   │
│        ▼                   ▼                        ▼                   │
│  BloxOne UDDI        DNS queries             BloxOne Threat Defense     │
│  (SVCB records)      (zero infra cost)       (named lists + policies)  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Two MCP Servers — AI Agent Control + Full DDI Management

The POC uses two MCP servers that work together in Claude Desktop (or any MCP-compatible AI agent):

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         AI AGENT (Claude Desktop)                       │
│                                                                         │
│  "Discover all agents at nordstrom.com, compile the governance policy, │
│   push to TD as action_log, then show me the security posture"         │
│                                                                         │
│         │                                    │                          │
│         ▼                                    ▼                          │
│  ┌──────────────────────┐     ┌──────────────────────────────────┐     │
│  │   dns-aid MCP        │     │   infoblox-ddi MCP               │     │
│  │   (15 tools)         │     │   (23 intent-level tools)        │     │
│  │                      │     │                                  │     │
│  │ • discover_agents    │     │ • manage_security_policy         │     │
│  │ • compile_policy     │     │   (CRUD named lists, policies)   │     │
│  │ • publish_rpz_zone   │     │ • assess_security_posture        │     │
│  │   (push + bind to TD)│     │ • investigate_threat             │     │
│  │ • list_rpz_rules     │     │ • explore_network                │     │
│  │ • list_td_policies   │     │ • provision_dns / provision_host │     │
│  │ • publish_agent      │     │ • diagnose_dns                   │     │
│  │ • verify_agent       │     │ • check_infrastructure_health    │     │
│  └──────────┬───────────┘     └──────────────┬───────────────────┘     │
│             │                                │                          │
│             └────────────┬───────────────────┘                          │
│                          ▼                                              │
│               ┌─────────────────────┐                                   │
│               │  BloxOne CSP API    │                                   │
│               │  /api/atcfw/v1/     │  TD: named lists, policies        │
│               │  /api/ddi/v1/       │  DDI: DNS, DHCP, IPAM            │
│               └─────────────────────┘                                   │
└──────────────────────────────────────────────────────────────────────────┘
```

**dns-aid MCP** handles the agent lifecycle:
- Publish/discover agents via DNS
- Compile policies (CEL + native rules) to TD format
- Push named lists + bind to TD security policies
- All TD actions: `action_block`, `action_log`, `action_allow`, `action_redirect`

**infoblox-ddi MCP** handles full infrastructure:
- DDI management (DNS zones, IPAM, DHCP)
- Security posture assessment
- Threat investigation
- Named list CRUD with incremental `add_items`/`remove_items`

## End-to-End Demo Script (Claude Desktop)

### Demo 1: Discovery — "What agents do we have?"

Prompt to Claude Desktop:
> "Use dns-aid to discover all agents at highvelocitynetworking.com. Show me a summary."

Claude uses: `discover_agents_via_dns("highvelocitynetworking.com")`

Expected output: 13 agents with names, protocols, endpoints, capabilities.

### Demo 2: Policy Compilation — "What would we enforce?"

Prompt:
> "Compile this governance policy and show me what gets enforced at DNS vs SDK layer:"
> (paste nordstrom-agent-governance.json)

Claude uses: `compile_policy_to_rpz(policy_json, format="both")`

Expected: 8 RPZ directives (Layer 0), 10 bind-aid directives, 10 skipped (Layer 1/2).

### Demo 3: Monitor Mode — "Start logging without blocking"

Prompt:
> "Push this policy to Infoblox TD as action_log so we can monitor matches before blocking. Use rpz zone name rpz.nordstrom-poc."

Claude uses: `publish_rpz_zone(policy_json, backend="infoblox", rpz_zone="rpz.nordstrom-poc", td_action="action_log")`

Expected: Named list created, bound to Default Global Policy as `action_log`.

### Demo 4: Verify — "What's in TD now?"

Prompt:
> "Show me what TD security policies exist and what named lists we have for rpz.nordstrom-poc"

Claude uses:
- `list_td_security_policies()` → shows policies
- `list_rpz_rules("rpz.nordstrom-poc", backend="infoblox")` → shows named list

Then ask infoblox-ddi MCP:
> "Use Infoblox DDI to assess the current security posture"

Claude uses: `assess_security_posture()` → shows TD health including our new named list

### Demo 5: Enforce — "Go live"

Prompt:
> "Change the TD action from action_log to action_block for rpz.nordstrom-poc"

Claude uses: `publish_rpz_zone(policy_json, backend="infoblox", rpz_zone="rpz.nordstrom-poc", td_action="action_block")`

Expected: Named list updated, policy rule changed to `action_block`. Blocked domains now get NXDOMAIN.

### Demo 6: Full DDI Context

Prompt to infoblox-ddi MCP:
> "Show me all DNS zones and named lists related to nordstrom"

Claude uses: `explore_network()` + `manage_security_policy(resource_type="named_list", action="list")`

This shows the full DDI context — DNS zones, security policies, named lists — alongside the DNS-AID agent control plane.

## One-Command Enforcement (CLI)

```bash
# Shadow mode — see what WOULD be blocked (safe to run anytime)
dns-aid enforce \
  -d nordstrom.com \
  -p policy.json \
  --mode shadow

# Monitor mode — log matches without blocking (recommended first step)
dns-aid enforce \
  -d nordstrom.com \
  -p policy.json \
  --mode enforce \
  -b infoblox \
  --td-action action_log

# Enforce mode — blocked domains get NXDOMAIN from Threat Defense
dns-aid enforce \
  -d nordstrom.com \
  -p policy.json \
  --mode enforce \
  -b infoblox \
  --td-action action_block

# Target a specific TD policy (not default)
dns-aid enforce \
  -d nordstrom.com \
  -p policy.json \
  --mode enforce \
  -b infoblox \
  --td-action action_block \
  --td-policy-id 224296
```

## Policy Document (What Alex's Team Writes)

```json
{
  "version": "1.0",
  "agent": "_inventory._mcp._agents.nordstrom.com",
  "rules": {
    "allowed_caller_domains": [
      "ai-platform.nordstrom.com",
      "ml-ops.nordstrom.com",
      "data-eng.nordstrom.com"
    ],
    "blocked_caller_domains": [
      "*.personal-dev.nordstrom.com",
      "*.sandbox.nordstrom.com"
    ],
    "required_protocols": ["mcp"],
    "required_auth_types": ["oauth2"],

    "cel_rules": [
      {
        "id": "block-shadow-agents",
        "expression": "!request.caller_domain.endsWith(\".shadow.nordstrom.com\")",
        "effect": "deny",
        "message": "Block unregistered shadow agents",
        "enforcement_layers": ["layer0", "layer1"]
      },
      {
        "id": "require-prod-trust",
        "expression": "request.caller_trust_score >= 0.8",
        "effect": "deny",
        "message": "Production agents require high trust",
        "enforcement_layers": ["layer1"]
      },
      {
        "id": "restrict-pii-tools",
        "expression": "!(request.tool_name in [\"export_customer_data\", \"bulk_pii_extract\"])",
        "effect": "deny",
        "message": "PII-sensitive tools restricted",
        "enforcement_layers": ["layer1", "layer2"]
      }
    ]
  }
}
```

## How CEL Rules Enforce Across Layers

One CEL expression, multiple enforcement points:

```
CEL Rule: "block-shadow-agents"
Expression: !request.caller_domain.endsWith(".shadow.nordstrom.com")
Effect: deny
Layers: [layer0, layer1]

                    ┌──────────────────────────────────────────────┐
                    │          PolicyCompiler.compile()             │
                    │                                              │
                    │  "Can DNS enforce this expression?"          │
                    │  Pattern: !endsWith(".shadow.nordstrom.com") │
                    │  → YES: domain-based, simple pattern         │
                    └──────────┬───────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
   ┌──────────▼──────────────┐   ┌─────────────▼───────────────────┐
   │  Layer 0: Threat Defense│   │  Layer 1: Caller SDK (runtime)  │
   │                         │   │                                 │
   │  TD Named List:         │   │  CEL Evaluator (Rust, ~2µs):    │
   │  *.shadow.nordstrom.com │   │  Evaluates full expression      │
   │  → NXDOMAIN             │   │  against live PolicyContext      │
   │                         │   │                                 │
   │  Enforced BEFORE the    │   │  Enforced even if DNS           │
   │  agent is reachable     │   │  is bypassed (direct IP)        │
   └─────────────────────────┘   └─────────────────────────────────┘


CEL Rule: "require-prod-trust"
Expression: request.caller_trust_score >= 0.8
Effect: deny
Layers: [layer1]

                    ┌──────────────────────────────────────────────┐
                    │          PolicyCompiler.compile()             │
                    │                                              │
                    │  "Can DNS enforce this expression?"          │
                    │  Pattern: trust_score comparison             │
                    │  → NO: DNS can't evaluate trust scores       │
                    │  → SKIPPED at Layer 0                        │
                    └──────────┬───────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
   ┌──────────▼──────────────┐   ┌─────────────▼───────────────────┐
   │  Layer 0: TD            │   │  Layer 1: Caller SDK (runtime)  │
   │                         │   │                                 │
   │  (skipped — DNS can't   │   │  CEL Evaluator (Rust, ~2µs):    │
   │   evaluate trust scores)│   │  caller_trust_score=0.3         │
   │                         │   │  → 0.3 >= 0.8 = false           │
   │                         │   │  → effect=deny → BLOCKED        │
   └─────────────────────────┘   └─────────────────────────────────┘
```

## What Gets Enforced Where

| Policy Rule | Infoblox TD (Layer 0) | Caller SDK (Layer 1) | Target (Layer 2) |
|---|---|---|---|
| `blocked_caller_domains` | **Named list → NXDOMAIN** | — | — |
| `allowed_caller_domains` | **Named list → allow + catch-all block** | — | — |
| `required_protocols` | — | **CEL evaluator** | — |
| `required_auth_types` | — | **CEL evaluator** | — |
| CEL `endsWith` (domain) | **Named list → NXDOMAIN** | **CEL evaluator** | — |
| CEL `trust_score >= 0.8` | — (can't express in DNS) | **CEL evaluator** | — |
| CEL `tool_name in [...]` | — (can't express in DNS) | **CEL evaluator** | **CEL evaluator** |

## Deployment Path for Nordstrom

### Phase 1: Publish (Week 1)
```bash
# Alex's teams publish their agents to BloxOne UDDI
dns-aid publish \
  -n inventory-agent \
  -d nordstrom.com \
  -p mcp \
  -e inventory.ai-platform.nordstrom.com \
  --policy-uri https://policies.nordstrom.com/inventory-agent.json \
  -b infoblox

# Also publish via NS1 for external DNS
dns-aid publish -n public-api -d nordstrom.com -p mcp -b ns1
```

### Phase 2: Discover + Audit (Week 1-2)
```bash
# See ALL agents across the org (including shadow agents)
dns-aid discover nordstrom.com --json

# Shadow enforce — see what WOULD be blocked
dns-aid enforce -d nordstrom.com -p governance-policy.json --mode shadow
```

### Phase 3: Monitor (Week 2-3)
```bash
# action_log — TD logs matches but doesn't block
dns-aid enforce \
  -d nordstrom.com \
  -p governance-policy.json \
  --mode enforce \
  -b infoblox \
  --td-action action_log
```

### Phase 4: Enforce (Week 3+)
```bash
# action_block — unauthorized callers get NXDOMAIN
dns-aid enforce \
  -d nordstrom.com \
  -p governance-policy.json \
  --mode enforce \
  -b infoblox \
  --td-action action_block
```

### Phase 5: Auto-policy (Future)
```bash
# Each agent publishes its own policy_uri in SVCB
# Enforce fetches ALL policies from DNS and compiles them
dns-aid enforce -d nordstrom.com --auto-policy --mode enforce -b infoblox
```

## Before / After

### Before DNS-AID
- 47+ AI agents across 12 teams
- No central inventory
- Shadow agents unknown to security
- No policy enforcement
- CISO has no visibility into agent-to-agent communication

### After DNS-AID + Threat Defense
- Every agent published to DNS with owner, capabilities, policy
- `dns-aid discover` shows the full inventory in seconds
- Shadow agents detected by crawling (Phase 8)
- Policy compiled to TD named lists — unauthorized callers get NXDOMAIN
- CISO dashboard: TD security policy shows all blocked domains
- AI agents (Claude Desktop) can manage the entire pipeline via MCP
- Path to CSP Asset Insights integration (agent inventory in BloxOne)

## External DNS: NS1

Nordstrom uses NS1 for external DNS. DNS-AID supports NS1 natively (shipped v0.16.0):

```bash
# Publish to NS1 for external discovery
dns-aid publish -n public-api -d nordstrom.com -p mcp -b ns1

# Publish to BloxOne for internal + policy enforcement
dns-aid publish -n public-api -d nordstrom.com -p mcp -b infoblox
```

Both backends produce the same SVCB records. External agents discover via NS1.
Internal policy enforcement happens via BloxOne TD.

## Architecture: Three Interfaces + Two MCP Servers

```
┌──────────────────────────────────────────────────────────────┐
│                        DNS-AID                               │
│                                                              │
│  ┌─────────┐  ┌───────────────┐  ┌────────────────────────┐ │
│  │   CLI   │  │  MCP Server   │  │     Python SDK         │ │
│  │         │  │  (15 tools)   │  │                        │ │
│  │ enforce │  │               │  │ PolicyCompiler()       │ │
│  │ policy  │  │ compile_rpz   │  │ .compile(doc)          │ │
│  │ compile │  │ publish_rpz   │  │                        │ │
│  │ show    │  │ list_rpz      │  │ BloxOneBackend         │ │
│  │ discover│  │ list_td_pol   │  │ .create_named_list()   │ │
│  │ publish │  │ discover      │  │ .bind_to_policy()      │ │
│  └─────────┘  └───────────────┘  └────────────────────────┘ │
└──────────────────────┬───────────────────────────────────────┘
                       │
┌──────────────────────┼───────────────────────────────────────┐
│  infoblox-ddi MCP    │            BloxOne CSP API            │
│  (23 tools)          │                                       │
│                      ▼                                       │
│  manage_security ──▶ /api/atcfw/v1/ (TD: named lists,       │
│  assess_posture     │               security policies)       │
│  investigate       │                                        │
│  explore_network ──▶ /api/ddi/v1/  (DDI: DNS, DHCP, IPAM)  │
│  provision_dns     │                                        │
│  diagnose_dns      │                                        │
└──────────────────────────────────────────────────────────────┘
```

## TD Security Policy Actions

| Action | Behavior | Use When |
|---|---|---|
| `action_log` | Log the query, allow it through | **Phase 3: Monitor** — see what would be blocked |
| `action_block` | NXDOMAIN response | **Phase 4: Enforce** — block unauthorized callers |
| `action_allow` | Explicit allow (override other blocks) | Whitelist trusted agents |
| `action_redirect` | Redirect to a landing page | Show "this agent is blocked" page |

## Key Numbers (from live testing)

| Metric | Value |
|---|---|
| Policy compilation | 1.5ms for 1010 directives |
| CEL evaluation (Rust) | ~2µs per rule |
| TD named list push | ~500ms per API call |
| TD security policy bind | ~500ms per API call |
| Full enforce pipeline | ~7s (dominated by DNS discovery) |
| Tests | 1191 core + 381 enterprise = 1572 total |

## Verified Live Against Infoblox BloxOne TD

- Created named list with blocked domains (HTTP 201)
- Bound to Default Global Policy as `action_block` (HTTP 201)
- Changed action to `action_log` (HTTP 201)
- Verified list exists with correct item count
- Unbound and cleaned up (HTTP 204)
- Full round-trip: create → bind → verify → change action → unbind → delete
- Both MCP servers tested from Claude Desktop
