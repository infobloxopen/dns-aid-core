# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
CEL (Common Expression Language) rule evaluator for DNS-AID policy.

Compiles, caches, and evaluates CEL expressions against PolicyContext.
CEL guarantees termination and hermetic evaluation (no I/O, no loops).

Backend priority:
  1. ``common-expression-language`` (Rust, ~2µs/eval) — ``pip install dns-aid[cel]``
  2. ``cel-python`` (pure Python, ~200µs/eval) — automatic fallback

Both backends are thread-safe: compiled programs are immutable and context
objects are created per-evaluation, so concurrent agents evaluating the
same target policy is safe without locks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

import structlog

if TYPE_CHECKING:
    from dns_aid.sdk.policy.models import PolicyContext, PolicyViolation
    from dns_aid.sdk.policy.schema import CELRule

logger = structlog.get_logger(__name__)

_MAX_CACHE_SIZE = 256  # Max compiled programs per evaluator instance


# ── Backend abstraction ─────────────────────────────────────────


class _CELBackend(Protocol):
    """Minimal interface for a CEL backend."""

    def compile(self, expression: str) -> Any: ...
    def execute(self, program: Any, ctx: dict[str, Any]) -> Any: ...


class _RustBackend:
    """Rust-based CEL backend (common-expression-language). ~2µs/eval."""

    def __init__(self) -> None:
        import cel

        self._cel = cel

    def compile(self, expression: str) -> Any:
        return self._cel.compile(expression)

    def execute(self, program: Any, ctx: dict[str, Any]) -> Any:
        cel_ctx = self._cel.Context()
        cel_ctx.add_variable("request", ctx)
        return program.execute(cel_ctx)


class _PythonBackend:
    """Pure-Python CEL backend (cel-python/celpy). ~200µs/eval."""

    def __init__(self) -> None:
        import celpy
        from celpy import celtypes

        self._celpy = celpy
        self._celtypes = celtypes
        self._env = celpy.Environment()

    def compile(self, expression: str) -> Any:
        ast = self._env.compile(expression)
        return self._env.program(ast)

    def execute(self, program: Any, ctx: dict[str, Any]) -> Any:
        ct = self._celtypes
        activation = {"request": self._dict_to_cel_map(ctx, ct)}
        return program.evaluate(activation)

    @staticmethod
    def _dict_to_cel_map(d: dict[str, Any], ct: Any) -> Any:
        """Convert a plain dict to celpy MapType with proper type coercion."""
        cel_map: dict[Any, Any] = {}
        for k, v in d.items():
            key = ct.StringType(k)
            if isinstance(v, bool):
                cel_map[key] = ct.BoolType(v)
            elif isinstance(v, int):
                cel_map[key] = ct.IntType(v)
            elif isinstance(v, float):
                cel_map[key] = ct.DoubleType(v)
            else:
                cel_map[key] = ct.StringType(str(v))
        return ct.MapType(cel_map)


def _select_backend() -> _CELBackend:
    """Select the fastest available CEL backend."""
    backend: _CELBackend
    try:
        backend = _RustBackend()
        logger.debug("policy.cel_backend", backend="rust")
        return backend
    except ImportError:
        pass
    try:
        backend = _PythonBackend()
        logger.debug("policy.cel_backend", backend="python")
        return backend
    except ImportError:
        raise ImportError("No CEL backend available. Install: pip install dns-aid[cel]") from None


# ── Evaluator ───────────────────────────────────────────────────


class CELRuleEvaluator:
    """Compile, cache, and evaluate CEL custom rules against PolicyContext.

    Thread-safe: compiled programs are cached and immutable.
    Context objects are created per-evaluation (no shared mutable state).
    """

    def __init__(self) -> None:
        self._backend = _select_backend()
        self._cache: dict[str, Any] = {}
        self._bad_expressions: set[str] = set()  # Negative cache for compile errors
        self.backend_name: str = type(self._backend).__name__  # For telemetry/debugging

    def _compile(self, expression: str) -> Any:
        """Compile a CEL expression, returning a cached program.

        Cache is bounded to _MAX_CACHE_SIZE entries to prevent unbounded
        memory growth from attacker-crafted unique expressions.
        Bad expressions are negatively cached to avoid repeated compile errors.
        """
        if expression in self._cache:
            return self._cache[expression]
        if expression in self._bad_expressions:
            raise ValueError(f"Previously failed to compile: {expression[:80]}")
        try:
            prog = self._backend.compile(expression)
        except Exception:
            self._bad_expressions.add(expression)
            raise
        if len(self._cache) >= _MAX_CACHE_SIZE:
            # Evict oldest entry (FIFO via dict insertion order)
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[expression] = prog
        return prog

    @staticmethod
    def _build_activation(ctx: PolicyContext) -> dict[str, Any]:
        """Map PolicyContext fields to a plain dict for CEL evaluation.

        None values are coerced to zero-values (CEL has no null):
        str→"", float→0.0, int→0, bool→False.
        """
        return {
            "caller_id": ctx.caller_id or "",
            "caller_domain": ctx.caller_domain or "",
            "protocol": ctx.protocol or "",
            "method": ctx.method or "",
            "intent": ctx.intent or "",
            "auth_type": ctx.auth_type or "",
            "geo_country": ctx.geo_country or "",
            "tls_version": ctx.tls_version or "",
            "caller_trust_score": float(ctx.caller_trust_score)
            if ctx.caller_trust_score is not None
            else 0.0,
            "payload_bytes": ctx.payload_bytes if ctx.payload_bytes is not None else 0,
            "dnssec_validated": ctx.dnssec_validated,
            "has_mutual_tls": ctx.has_mutual_tls,
        }

    def evaluate(
        self,
        rules: list[CELRule],
        ctx: PolicyContext,
        layer: str,
    ) -> tuple[list[PolicyViolation], list[PolicyViolation]]:
        """Evaluate CEL rules against a PolicyContext.

        Returns:
            Tuple of (violations, warnings). Fails open on errors.
        """
        from dns_aid.sdk.policy.models import PolicyViolation

        violations: list[PolicyViolation] = []
        warnings: list[PolicyViolation] = []
        activation = self._build_activation(ctx)

        for rule in rules:
            # Layer filtering: if rule specifies layers, skip if current layer not included
            if rule.enforcement_layers and layer not in rule.enforcement_layers:
                continue

            try:
                prog = self._compile(rule.expression)
                result = self._backend.execute(prog, activation)

                # Warn on non-boolean return — likely a misconfigured expression
                if not isinstance(result, bool):
                    logger.warning(
                        "policy.cel_non_boolean_result",
                        rule_id=rule.id,
                        result_type=type(result).__name__,
                        hint="CEL rules should return bool; non-bool is coerced via truthiness",
                    )

                # CEL expression should return truthy for "allowed"
                # If falsy → the rule condition is not met → trigger effect
                if not result:
                    pv = PolicyViolation(
                        rule=f"cel:{rule.id}",
                        detail=rule.message or f"CEL rule '{rule.id}' denied request",
                        layer=layer,
                    )
                    if rule.effect == "deny":
                        violations.append(pv)
                    else:
                        warnings.append(pv)

            except Exception as exc:
                logger.warning(
                    "policy.cel_error",
                    rule_id=rule.id,
                    expression=rule.expression[:200],
                    error=str(exc),
                    error_type=type(exc).__name__,
                )

        return violations, warnings
