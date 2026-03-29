# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Policy-to-RPZ/bind-aid compiler.

Transforms a ``PolicyDocument`` into RPZ directives (standard Response Policy Zone
``CNAME`` records) and bind-aid directives (Ingmar's BIND 9 fork with per-record
``TXT`` action/param-op directives).

Layer 0 (DNS resolver) can only enforce domain-based access control and protocol
filtering.  Rules that require application-layer context (auth, TLS, payload, etc.)
are skipped with a documented reason so callers know which rules require Layer 1/2
enforcement.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field

from dns_aid.sdk.policy.schema import PolicyDocument

# ── Data models ────────────────────────────────────────────────


class RPZAction(StrEnum):
    """Standard RPZ actions (RFC 8010 §2)."""

    NXDOMAIN = "NXDOMAIN"  # CNAME .
    NODATA = "NODATA"  # CNAME *.
    PASSTHRU = "PASSTHRU"  # CNAME rpz-passthru.
    DROP = "DROP"  # CNAME rpz-drop.


class RPZDirective(BaseModel):
    """A single RPZ zone entry."""

    owner: str  # LHS of the RR (e.g., "evil.example.com")
    action: RPZAction
    comment: str = ""
    source_rule: str = ""  # which policy rule produced this


class BindAidAction(StrEnum):
    """bind-aid enforcement actions."""

    NXDOMAIN = "nxdomain"
    NODATA = "nodata"
    PASSTHRU = "passthru"
    DROP = "drop"


class BindAidParamOp(StrEnum):
    """bind-aid SVCB parameter operations."""

    STRIP = "strip"
    REQUIRE = "require"
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    ENFORCE = "enforce"
    VALIDATE = "validate"


class BindAidDirective(BaseModel):
    """A single bind-aid policy zone entry."""

    owner: str
    action: BindAidAction
    param_ops: list[str] = Field(default_factory=list)  # e.g., ["key65402=whitelist:mcp,a2a"]
    comment: str = ""
    source_rule: str = ""


class SkippedRule(BaseModel):
    """A rule that could not be compiled to Layer 0."""

    rule_name: str
    reason: str


class CompilationResult(BaseModel):
    """Full compilation output for a single policy document."""

    agent_fqdn: str
    rpz_directives: list[RPZDirective] = Field(default_factory=list)
    bindaid_directives: list[BindAidDirective] = Field(default_factory=list)
    skipped: list[SkippedRule] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# ── Compiler ───────────────────────────────────────────────────

# Simple CEL patterns we can translate to DNS zone entries.
# Both positive and negated forms are recognized:
#   endsWith(".evil.io") → positive match (author means "match evil")
#   !endsWith(".evil.io") → negated (evaluator convention: allow condition, deny on match)
# The compiler maps both to the same RPZ output, respecting the effect field.
_CEL_DOMAIN_ENDSWITH = re.compile(r"^!?request\.caller_domain\.endsWith\(\s*\"([^\"]+)\"\s*\)$")
_CEL_DOMAIN_EQ = re.compile(r"^request\.caller_domain\s*(?:==|!=)\s*\"([^\"]+)\"$")


class PolicyCompiler:
    """Compile a PolicyDocument into RPZ + bind-aid directives.

    Only Layer 0 (DNS-enforceable) rules produce output.  Everything else
    is reported in ``skipped`` with a reason string.
    """

    def compile(self, doc: PolicyDocument) -> CompilationResult:
        """Compile a policy document into RPZ and bind-aid directives."""
        result = CompilationResult(agent_fqdn=doc.agent)
        rules = doc.rules

        self._compile_blocked_domains(rules.blocked_caller_domains, result)
        self._compile_allowed_domains(rules.allowed_caller_domains, result)
        self._compile_required_protocols(rules.required_protocols, result)
        self._compile_required_auth_types(rules.required_auth_types, result)
        self._compile_svcparam_ops(rules.svcparam_ops, result)
        self._compile_cel_rules(rules.cel_rules, result)

        # Deduplicate: if the same owner+action appears from multiple rules,
        # keep only the first occurrence (native rules take priority over CEL).
        self._deduplicate(result)

        # Rules that are always skipped at Layer 0
        self._skip_if_set(
            rules.require_dnssec, "require_dnssec", "Resolver-native; no RPZ needed", result
        )
        self._skip_if_set(
            rules.require_mutual_tls, "require_mutual_tls", "Layer 1/2 only (TLS handshake)", result
        )
        self._skip_if_set(
            rules.min_tls_version, "min_tls_version", "Layer 1 only (TLS negotiation)", result
        )
        self._skip_if_set(
            rules.required_caller_trust_score,
            "required_caller_trust_score",
            "Layer 1 only (trust evaluation)",
            result,
        )
        self._skip_if_set(
            rules.rate_limits, "rate_limits", "Layer 1/2 only (request counting)", result
        )
        self._skip_if_set(
            rules.max_payload_bytes,
            "max_payload_bytes",
            "Layer 2 only (HTTP body inspection)",
            result,
        )
        self._skip_if_set(
            rules.allowed_methods, "allowed_methods", "Layer 1/2 only (HTTP method)", result
        )
        self._skip_if_set(
            rules.allowed_intents, "allowed_intents", "Layer 1/2 only (intent extraction)", result
        )
        self._skip_if_set(
            rules.geo_restrictions,
            "geo_restrictions",
            "Needs resolver GeoIP — Phase 7.4",
            result,
        )
        self._skip_if_set(
            rules.availability, "availability", "Layer 1/2 only (time-of-day)", result
        )
        self._skip_if_set(
            rules.data_classification, "data_classification", "Layer 1 only (metadata tag)", result
        )
        self._skip_if_set(
            rules.consent_required, "consent_required", "Layer 1/2 only (consent token)", result
        )

        return result

    # ── Rule compilers ────────────────────────────────────────

    @staticmethod
    def _compile_blocked_domains(
        domains: list[str] | None,
        result: CompilationResult,
    ) -> None:
        if not domains:
            return
        for domain in domains:
            owner = domain  # already includes wildcard if present (e.g., "*.malicious.net")
            result.rpz_directives.append(
                RPZDirective(
                    owner=owner,
                    action=RPZAction.NXDOMAIN,
                    comment=f"Block caller domain: {domain}",
                    source_rule="blocked_caller_domains",
                )
            )
            result.bindaid_directives.append(
                BindAidDirective(
                    owner=owner,
                    action=BindAidAction.NXDOMAIN,
                    comment=f"Block caller domain: {domain}",
                    source_rule="blocked_caller_domains",
                )
            )

    @staticmethod
    def _compile_allowed_domains(
        domains: list[str] | None,
        result: CompilationResult,
    ) -> None:
        if not domains:
            return
        # Passthru for each allowed domain
        for domain in domains:
            owner = domain  # already includes wildcard if present (e.g., "*.partner.org")
            result.rpz_directives.append(
                RPZDirective(
                    owner=owner,
                    action=RPZAction.PASSTHRU,
                    comment=f"Allow caller domain: {domain}",
                    source_rule="allowed_caller_domains",
                )
            )
            result.bindaid_directives.append(
                BindAidDirective(
                    owner=owner,
                    action=BindAidAction.PASSTHRU,
                    comment=f"Allow caller domain: {domain}",
                    source_rule="allowed_caller_domains",
                )
            )
        # Catch-all: block everything else
        result.rpz_directives.append(
            RPZDirective(
                owner="*",
                action=RPZAction.NXDOMAIN,
                comment="Catch-all: block unlisted callers",
                source_rule="allowed_caller_domains",
            )
        )
        result.bindaid_directives.append(
            BindAidDirective(
                owner="*",
                action=BindAidAction.NXDOMAIN,
                comment="Catch-all: block unlisted callers",
                source_rule="allowed_caller_domains",
            )
        )

    @staticmethod
    def _compile_required_protocols(
        protocols: list[str] | None,
        result: CompilationResult,
    ) -> None:
        if not protocols:
            return
        # RPZ cannot filter by protocol — skip
        result.skipped.append(
            SkippedRule(
                rule_name="required_protocols",
                reason="RPZ cannot filter by protocol; bind-aid only",
            )
        )
        # bind-aid can whitelist protocols via SVCB key65402 (bap)
        proto_list = ",".join(protocols)
        result.bindaid_directives.append(
            BindAidDirective(
                owner="*",
                action=BindAidAction.PASSTHRU,
                param_ops=[f"key65402=whitelist:{proto_list}"],
                comment=f"Require protocols: {proto_list}",
                source_rule="required_protocols",
            )
        )

    @staticmethod
    def _compile_required_auth_types(
        auth_types: list[str] | None,
        result: CompilationResult,
    ) -> None:
        if not auth_types:
            return
        # RPZ cannot filter by auth type — skip
        result.skipped.append(
            SkippedRule(
                rule_name="required_auth_types",
                reason="RPZ cannot filter by auth type; bind-aid only",
            )
        )
        # bind-aid can require the cap key (key65400) which implies auth
        result.bindaid_directives.append(
            BindAidDirective(
                owner="*",
                action=BindAidAction.PASSTHRU,
                param_ops=["key65400=require"],
                comment=f"Require auth types: {', '.join(auth_types)}",
                source_rule="required_auth_types",
            )
        )

    @staticmethod
    def _compile_svcparam_ops(
        ops: list | None,
        result: CompilationResult,
    ) -> None:
        """Compile SvcParam operations to bind-aid directives.

        Each ``SvcParamOp`` becomes a separate TXT record in the bind-aid zone.
        RPZ cannot express rdata operations, so these are bind-aid only.
        """
        if not ops:
            return

        for op in ops:
            # Format: key=op:values or key=op (no values)
            if op.values:
                param_str = f"{op.key}={op.op}:{','.join(op.values)}"
            else:
                param_str = f"{op.key}={op.op}"

            result.bindaid_directives.append(
                BindAidDirective(
                    owner="*",
                    action=BindAidAction.PASSTHRU,
                    param_ops=[param_str],
                    comment=f"SvcParam: {param_str}",
                    source_rule="svcparam_ops",
                )
            )

        # RPZ cannot express SvcParam ops — add skip notice
        result.skipped.append(
            SkippedRule(
                rule_name="svcparam_ops",
                reason="RPZ cannot express rdata operations; bind-aid only",
            )
        )

    def _compile_cel_rules(
        self,
        cel_rules: list | None,
        result: CompilationResult,
    ) -> None:
        if not cel_rules:
            return
        for rule in cel_rules:
            # Only compile deny-effect CEL rules with layer0 support
            if rule.enforcement_layers and "layer0" not in rule.enforcement_layers:
                result.skipped.append(
                    SkippedRule(
                        rule_name=f"cel:{rule.id}",
                        reason=f"Not a Layer 0 rule (layers: {rule.enforcement_layers})",
                    )
                )
                continue

            compiled = self._try_compile_cel(rule, result)
            if not compiled:
                result.skipped.append(
                    SkippedRule(
                        rule_name=f"cel:{rule.id}",
                        reason="Complex CEL expression; cannot compile to DNS zone entry",
                    )
                )

    def _try_compile_cel(self, rule, result: CompilationResult) -> bool:
        """Try to compile a CEL rule to RPZ/bind-aid. Returns True if successful.

        CEL evaluator convention: expression=true → allowed, false → effect triggered.

        For domain blocking with ``effect="deny"``:
          ``!request.caller_domain.endsWith(".evil.io")``
            → evaluator: matching domain makes expression false → deny ✓
          ``request.caller_domain != "bad.com"``
            → evaluator: matching domain makes expression false → deny ✓

        The compiler also accepts the non-negated forms for backwards compat:
          ``request.caller_domain.endsWith(".evil.io")``  (effect="deny")
          ``request.caller_domain == "bad.com"``          (effect="deny")

        Both negated and non-negated forms produce the same RPZ output: the
        extracted domain is blocked (NXDOMAIN) or allowed (PASSTHRU) based
        on the effect field.
        """
        expr = rule.expression.strip()

        # Pattern: [!]request.caller_domain.endsWith(".evil.com")
        m = _CEL_DOMAIN_ENDSWITH.match(expr)
        if m:
            suffix = m.group(1)
            owner = f"*{suffix}" if suffix.startswith(".") else f"*.{suffix}"
            # Both negated (!endsWith) and non-negated (endsWith) with deny
            # mean "block matching domains" — the extracted domain is the target.
            action = RPZAction.NXDOMAIN if rule.effect == "deny" else RPZAction.PASSTHRU
            ba_action = BindAidAction.NXDOMAIN if rule.effect == "deny" else BindAidAction.PASSTHRU

            result.rpz_directives.append(
                RPZDirective(
                    owner=owner,
                    action=action,
                    comment=f"CEL rule '{rule.id}': {rule.message or expr}",
                    source_rule=f"cel:{rule.id}",
                )
            )
            result.bindaid_directives.append(
                BindAidDirective(
                    owner=owner,
                    action=ba_action,
                    comment=f"CEL rule '{rule.id}': {rule.message or expr}",
                    source_rule=f"cel:{rule.id}",
                )
            )
            return True

        # Pattern: request.caller_domain == "exact.com" or != "exact.com"
        m = _CEL_DOMAIN_EQ.match(expr)
        if m:
            domain = m.group(1)
            action = RPZAction.NXDOMAIN if rule.effect == "deny" else RPZAction.PASSTHRU
            ba_action = BindAidAction.NXDOMAIN if rule.effect == "deny" else BindAidAction.PASSTHRU

            result.rpz_directives.append(
                RPZDirective(
                    owner=domain,
                    action=action,
                    comment=f"CEL rule '{rule.id}': {rule.message or expr}",
                    source_rule=f"cel:{rule.id}",
                )
            )
            result.bindaid_directives.append(
                BindAidDirective(
                    owner=domain,
                    action=ba_action,
                    comment=f"CEL rule '{rule.id}': {rule.message or expr}",
                    source_rule=f"cel:{rule.id}",
                )
            )
            return True

        return False

    @staticmethod
    def _deduplicate(result: CompilationResult) -> None:
        """Remove duplicate RPZ/bind-aid directives (same owner+action).

        Keeps the first occurrence (native rules compiled before CEL),
        adds a warning for each duplicate removed.
        """
        seen_rpz: set[tuple[str, str]] = set()
        deduped_rpz: list[RPZDirective] = []
        for d in result.rpz_directives:
            key = (d.owner, d.action.value)
            if key in seen_rpz:
                result.warnings.append(
                    f"Duplicate RPZ entry removed: {d.owner} {d.action.value} (from {d.source_rule})"
                )
                continue
            seen_rpz.add(key)
            deduped_rpz.append(d)
        result.rpz_directives = deduped_rpz

        seen_ba: set[tuple[str, str, tuple[str, ...]]] = set()
        deduped_ba: list[BindAidDirective] = []
        for ba in result.bindaid_directives:
            ba_key = (ba.owner, ba.action.value, tuple(ba.param_ops))
            if ba_key in seen_ba:
                result.warnings.append(
                    f"Duplicate bind-aid entry removed: {ba.owner} {ba.action.value} (from {ba.source_rule})"
                )
                continue
            seen_ba.add(ba_key)
            deduped_ba.append(ba)
        result.bindaid_directives = deduped_ba

    @staticmethod
    def _skip_if_set(
        value: object,
        rule_name: str,
        reason: str,
        result: CompilationResult,
    ) -> None:
        """Add a SkippedRule if the value is truthy."""
        if value:
            result.skipped.append(SkippedRule(rule_name=rule_name, reason=reason))
