# OWASP MAESTRO mapping for dns-aid-core

This document maps the OWASP MAESTRO multi-agentic threat taxonomy (T1-T47 +
BV-1 through BV-12) against the dns-aid-core codebase. Each threat is marked
as **Mitigated** (a primitive in the codebase addresses it), **Partial**
(primitive exists but enforcement is opt-in or limited in scope), **Out of
scope** (the threat lives at a layer dns-aid-core does not own — foundation
models, agent reasoning, RAG, runtime sandboxing, payments), or **Gap**
(a real defect tracked for follow-up work).

Last updated: 2026-05-13. Reflects the trust-enforcement hardening shipped on
`feat/owasp-maestro-trust-enforcement`.

## Attribution

This mapping is built directly on the following published threat models. The
applicability commentary is dns-aid-core specific; the threat enumeration,
descriptions, and MAESTRO layering are the work of the authors below.

- **OWASP Multi-Agentic System Threat Modelling Guide v1.0** (April 2025) —
  Ken Huang, A. Sheriff, J. Sotiropoulos, R. F. Del, V. Lu, et al.
  <https://genai.owasp.org/resource/multi-agentic-system-threat-modeling-guide-v1-0/>
- **MAESTRO Playbook & Threat Taxonomy** (CC BY-SA 4.0). Contains the T1-T47
  enumeration and the BV-1 through BV-12 blindspot vectors used below.
  <https://agentic-threat-modeling.github.io/MAESTRO/playbook/02-threat-taxonomy.html>
- **ANS / MAESTRO mapping** — Scott Courtney (GoDaddy). The MAESTRO threat
  model applied to the Agent Name Service. Several of the dns-aid-core
  mitigations below are direct applications of patterns documented in his
  mapping (notably DANE/TLSA pinning, signed integrity envelopes, capability
  contract sealing, and the multi-stream audit model).
  <https://github.com/godaddy/ans-registry/blob/main/MAESTRO.md>

## Design posture

dns-aid-core defaults are **permissive** — designed to match the real-world
adoption levels of DNSSEC, DANE/TLSA, and mTLS on the public internet. Every
hardening discussed below is **opt-in** via `SDKConfig` flags or via
publisher-driven `mandatory=` declarations in the SVCB record itself.
See [best-practices.md](best-practices.md) for the operator-facing flag
recommendations.

## Core threats (T1-T15)

| ID | Threat | Status | Notes |
|---|---|---|---|
| T1 | Memory Poisoning | Out of scope | Agent-runtime / RAG-layer concern. |
| T2 | Tool Misuse | Mitigated | `cap=` URI sealed by `cap-sha256` (RFC 9460 SVCB params). Tool contract is publisher-declared and integrity-checked at fetch. |
| T3 | Privilege Compromise | Out of scope | Caller-side workload-identity concern (SPIFFE / SCIM territory). |
| T4 | Resource Overload | Partial | Caller-side rate limiting via `SDKConfig.max_retries` + circuit breaker; substrate does not throttle. |
| T5 | Cascading Hallucinations | Out of scope | Foundation model layer. |
| T6 | Intent Breaking & Goal Manipulation | Out of scope | Agent framework layer. |
| T7 | Misaligned & Deceptive Behaviour | Out of scope | Runtime / governance layer. |
| T8 | Repudiation & Untraceability | Partial | Telemetry signals in `sdk/signals/` capture invocation outcomes; audit-log integrity (hash chaining / signed checkpoints) is open work — see Gap T23. |
| T9 | Identity Spoofing | Mitigated | DNSSEC-validated SVCB resolution; DANE TLSA pinning when configured (`prefer_dane` / `require_dane`); `cap-sha256` integrity check. |
| T10 | Overwhelming HITL | Out of scope | Human-in-the-loop UX layer. |
| T11 | Unexpected RCE / Code Attacks | Out of scope | Runtime sandboxing concern. |
| T12 | Agent Communication Poisoning | Partial | DNS-layer protected by DNSSEC; transport-layer protected by DANE pinning when enabled; application-layer message authentication is the runtime's responsibility (JWS via `sdk/auth/`). |
| T13 | Rogue Agents | Mitigated | DCV (`core/dcv.py`) proves the publishing zone is controlled by whoever placed the challenge; DNSSEC ties the chain back to the trust anchor. |
| T14 | Human Attacks on MAS | Out of scope | Social-engineering / agent-framework layer. |
| T15 | Human Trust Manipulation | Out of scope | UX / human-factors layer. |

## Extended threats (T16-T47)

T26 and T27 are reserved in the canonical taxonomy. Threats omitted from the
table below (T16-T18, T20-T21, T28-T35, T38, T42) are runtime / framework /
blockchain / RAG-layer concerns that dns-aid-core does not address by design.

| ID | Threat | Status | Notes |
|---|---|---|---|
| T19 | Unintended Workflow Execution | Out of scope | Agent framework. |
| T22 | Service Account Exposure | Partial | Backends consume credentials from env / SDKConfig. HSM/TPM-backed signing is not yet a first-class primitive in `sdk/auth/`. Operational guidance only — see [best-practices.md](best-practices.md). |
| T23 | Selective Log Manipulation | Gap | `sdk/telemetry/` writes plain events. Hash-chained / signed-checkpoint audit log is open work; not included in this PR. |
| T24 | Dynamic Policy Enforcement Failure | Mitigated | `sdk/policy/` evaluates per-invocation; failures fall open with structured warning logs. |
| T25 | Workflow Disruption via Dependency | Out of scope | Runtime layer. |
| T29 | Plugin Vulnerability | Out of scope | dns-aid-core itself is not a plugin host; consumers integrating into Claude Desktop / Marketplace need their own input-validation discipline at that boundary. |
| T36 | Malicious Agent Diffusion | Partial | Records published via DCV-controlled zones can be retracted (revocation propagates as DNS NXDOMAIN). Continuous re-verification is open work. |
| T37 | Agent Registry Poisoning | Mitigated | DNSSEC + DCV are the canonical mitigations and exist in `core/validator.py` and `core/dcv.py`. Enforcement is opt-in (`require_dnssec`) because of partial real-world DNSSEC adoption. |
| T39 | Unintended Resource Consumption | Out of scope (substrate); Partial (SDK) | Substrate does not budget; SDK circuit breaker bounds repeated failures per agent. |
| T40 | MCP Client Impersonation | Mitigated | Caller-side identity is JWS-signable via `sdk/auth/jws.py` (HTTP Message Signatures). Web Bot Auth handler is open work. |
| T41 | Schema Mismatch | Mitigated | `cap-sha256` seals the capability descriptor against post-hoc divergence; client refuses non-matching content (`core/cap_fetcher.py`). |
| T43 | Network Exposure | Out of scope | Deployment concern. Documented in [best-practices.md](best-practices.md). |
| T44 | Insufficient Logging | Partial | Telemetry exists; W3C `traceparent` propagation across protocol handlers is open work. |
| T45 | Insufficient Server Permission Isolation | Out of scope | Deployment concern. |
| T46 | Data Residency / Compliance Violation | Partial | `policy=` SVCB key carries the URI; bundle schema and runtime evaluator are open work. |
| T47 | Rogue Server | Mitigated | DANE TLSA pinning on the invocation path (`SDKConfig.prefer_dane` / `require_dane`). Mismatch always refuses; absent falls back to WebPKI in permissive mode. |

## Blindspot Vectors (BV-1 through BV-12)

| ID | Vector | Status | Notes |
|---|---|---|---|
| BV-1 | Context Window Poisoning | Out of scope | Foundation model layer. |
| BV-2 | Tool Description Poisoning (Rug Pull) | Mitigated | `cap-sha256` re-validation against current SVCB at every fetch, plus `SDKConfig.verify_freshness_seconds` re-resolves before invoke when set and detects rotated cap_sha256 as drift. |
| BV-3 | Agentic Supply Chain (Dependency Confusion) | Partial | The dns-aid-core repository is open source. SLSA build provenance + Sigstore signing of wheels + transparency-log entry per release is open work; not in this PR. |
| BV-4 | Prompt Leakage via Tool Outputs | Out of scope | Foundation model / framework layer. |
| BV-5 | Multi-Tenant Agent Isolation Failure | Out of scope (this PR) | Substrate is per-zone; multi-tenant registrar isolation would be a separate design. |
| BV-6 | Cost / Budget Exhaustion Attacks | Out of scope | Foundation model billing concern. |
| BV-7 | Agent Memory Injection via A2A | Out of scope | Runtime / A2A protocol concern. |
| BV-8 | Steganographic Data Exfiltration | Out of scope | Foundation model output layer. |
| BV-9 | Time-of-Check-to-Time-of-Use (TOCTOU) | Mitigated | `SDKConfig.verify_freshness_seconds` re-resolves stale `DiscoveryResult` records before invoke; essential fields (target_host, port, cap_sha256) are compared between cached and fresh; drift refuses the invocation. |
| BV-10 | LLM Reasoning Manipulation | Out of scope | Foundation model layer. |
| BV-11 | OAuth/OIDC Token Relay Attacks | Out of scope (this PR) | Delegation wire format is deferred — tracked for OIDC-A maturity. |
| BV-12 | Observability Overload | Gap | Audit-sink classification / anomaly detection is open work; pair with the T23 audit-integrity work. |

## Status summary

- **Mitigated** in this codebase: T2, T9, T13, T24, T37, T40, T41, T47, BV-2, BV-9
- **Partial**: T4, T8, T12, T22, T36, T39, T44, T46, BV-3
- **Gap (tracked)**: T23, BV-12
- **Out of scope**: everything else listed (foundation model, agent framework, RAG, payments, deployment, runtime sandboxing — none of which dns-aid-core owns)

## What this PR specifically lands

This document was created as part of the
`feat/owasp-maestro-trust-enforcement` branch. The code changes that ship
alongside this mapping address: T47 / T7.1 / T9 (DANE pinning at invoke),
BV-9 (TOCTOU re-verification), BV-2 (cap-doc drift detection via the same
re-verification), and T7.6 (RFC 9460 `mandatory=` enforcement so publishers
can declare which keys clients MUST honor).

See [best-practices.md](best-practices.md) for the operator-facing flags
that gate each mitigation.
