# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Target-side policy enforcement middleware (Layer 2).

FastAPI/Starlette ASGI middleware that enforces the target agent's
published policy on incoming requests. This is the MANDATORY enforcement
layer — regardless of whether the caller SDK cooperates, the target
rejects non-compliant requests.

Security notes:
- X-DNS-AID-Caller-Domain is ADVISORY without mTLS (header can be spoofed)
- Method is extracted from JSON-RPC body, not from headers (body is truth)
- X-Forwarded-For requires trusted_proxies configuration for geo
- When require_mutual_tls=true, caller domain is verified against cert SAN
"""

from __future__ import annotations

import contextlib
import json
import time
from collections import defaultdict

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from dns_aid.sdk.policy.evaluator import PolicyEvaluator
from dns_aid.sdk.policy.models import PolicyContext
from dns_aid.sdk.policy.schema import PolicyEnforcementLayer

logger = structlog.get_logger(__name__)


class RateLimitState:
    """Sliding window rate limiter per caller with LRU eviction."""

    _MAX_CALLERS = 10_000

    def __init__(self) -> None:
        self._windows: dict[str, list[float]] = defaultdict(list)

    def check(
        self,
        caller: str,
        max_per_minute: int | None,
        max_per_hour: int | None,
    ) -> bool:
        """Returns True if within limits."""
        now = time.monotonic()
        entries = self._windows[caller]
        # Prune entries older than 1 hour
        entries[:] = [t for t in entries if now - t < 3600]

        if max_per_minute and sum(1 for t in entries if now - t < 60) >= max_per_minute:
            return False
        if max_per_hour and len(entries) >= max_per_hour:
            return False

        entries.append(now)

        # LRU eviction: remove oldest caller when over capacity
        if len(self._windows) > self._MAX_CALLERS:
            oldest = min(
                self._windows,
                key=lambda k: self._windows[k][-1] if self._windows[k] else 0,
            )
            del self._windows[oldest]

        return True


class DnsAidPolicyMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware for target-side policy enforcement (Layer 2).

    Usage::

        app = FastAPI()
        app.add_middleware(
            DnsAidPolicyMiddleware,
            policy_uri="https://example.com/policy.json",
            mode="strict",  # or "permissive" (log only)
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        policy_uri: str,
        mode: str = "strict",
        trusted_proxies: list[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.policy_uri = policy_uri
        self.mode = mode  # "strict" | "permissive"
        self.trusted_proxies = set(trusted_proxies or [])
        self._evaluator = PolicyEvaluator(cache_ttl=300)
        self._rate_limiter = RateLimitState()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Evaluate target policy on every incoming request."""
        # Extract caller identity from request
        caller_domain = request.headers.get("x-dns-aid-caller-domain")
        authorization = request.headers.get("authorization", "")
        auth_type = _extract_auth_type(authorization)

        # Extract method from JSON-RPC body (security: body is source of truth)
        method = await _extract_method_from_body(request)

        # Extract intent from header (advisory — caller self-reports)
        intent = request.headers.get("x-dns-aid-intent")

        # Geo from trusted proxy only
        geo_country = None
        client_ip = request.client.host if request.client else None
        if client_ip and client_ip in self.trusted_proxies:
            # Geo lookup integration point for Phase 7 (MaxMind/GeoIP2)
            # Without it, geo_restrictions are NOT enforced at Layer 2
            pass

        # mTLS verification: when present, cert domain overrides claimed domain
        has_mutual_tls = False
        cert_dn = request.headers.get("x-client-certificate-dn")
        if cert_dn:
            has_mutual_tls = True
            cert_domain = _extract_domain_from_dn(cert_dn)
            if cert_domain and caller_domain and caller_domain != cert_domain:
                logger.warning(
                    "policy.caller_domain_mismatch",
                    claimed=caller_domain,
                    cert=cert_domain,
                )
                caller_domain = cert_domain  # Trust the cert, not the header

        # Parse Content-Length safely
        payload_bytes = None
        cl_header = request.headers.get("content-length")
        if cl_header:
            with contextlib.suppress(ValueError):
                payload_bytes = int(cl_header)

        # Extract tool_name from JSON-RPC body for MCP tool calls
        tool_name = await _extract_tool_name_from_body(request, method)

        # Build evaluation context
        ctx = PolicyContext(
            caller_domain=caller_domain,
            auth_type=auth_type,
            method=method,
            intent=intent,
            geo_country=geo_country,
            payload_bytes=payload_bytes,
            has_mutual_tls=has_mutual_tls,
            consent_token=request.headers.get("x-dns-aid-consent-token"),
            tool_name=tool_name,
        )

        # Evaluate policy
        try:
            policy_doc = await self._evaluator.fetch(self.policy_uri)
            result = self._evaluator.evaluate(
                policy_doc,
                ctx,
                layer=PolicyEnforcementLayer.TARGET,
            )
        except Exception as exc:
            logger.error("policy.fetch_failed", error=str(exc))
            # Fail-open: let request through but mark as no-policy
            response = await call_next(request)
            response.headers["X-DNS-AID-Policy-Result"] = "no-policy"
            return response

        # Rate limit check (separate from rule evaluation — stateful)
        if policy_doc.rules.rate_limits and caller_domain:
            rl = policy_doc.rules.rate_limits
            if not self._rate_limiter.check(
                caller_domain,
                rl.max_per_minute,
                rl.max_per_hour,
            ):
                return JSONResponse(
                    status_code=429,
                    content={"error": "rate_limited", "reason": "rate limit exceeded"},
                    headers={"X-DNS-AID-Policy-Result": "denied"},
                )

        # Enforce policy
        if result.denied and self.mode == "strict":
            return JSONResponse(
                status_code=403,
                content={
                    "error": "policy_denied",
                    "violations": [{"rule": v.rule, "detail": v.detail} for v in result.violations],
                },
                headers={"X-DNS-AID-Policy-Result": "denied"},
            )

        if result.denied and self.mode == "permissive":
            logger.warning(
                "policy.permissive_violation",
                caller_domain=caller_domain,
                violations=[f"{v.rule}:{v.detail}" for v in result.violations],
            )

        # Proceed with request — attach result header
        response = await call_next(request)
        response.headers["X-DNS-AID-Policy-Result"] = "allowed" if result.allowed else "denied"
        return response


def _extract_auth_type(authorization: str) -> str | None:
    """Extract auth type from Authorization header value."""
    if not authorization:
        return None
    lower = authorization.lower()
    if lower.startswith("bearer "):
        return "bearer"
    if lower.startswith("basic "):
        return "api_key"
    return "unknown"


async def _extract_method_from_body(request: Request) -> str | None:
    """Extract JSON-RPC method from request body.

    Security: the body is the source of truth for what the caller is actually
    doing. The X-DNS-AID-Method header is only used as fallback for non-JSON
    payloads.
    """
    content_type = request.headers.get("content-type", "")
    if "json" not in content_type:
        method = request.headers.get("x-dns-aid-method")
        if method:
            logger.debug("policy.method_from_header_fallback", method=method)
        return method
    try:
        body = await request.body()
        if body:
            data = json.loads(body)
            if isinstance(data, dict):
                return data.get("method")
    except Exception:
        pass
    return request.headers.get("x-dns-aid-method")


async def _extract_tool_name_from_body(request: Request, method: str | None) -> str | None:
    """Extract tool name from JSON-RPC body for MCP tools/call requests.

    For MCP, tool_name is in params.name when method == "tools/call".
    """
    if method != "tools/call":
        return None
    content_type = request.headers.get("content-type", "")
    if "json" not in content_type:
        return None
    try:
        body = await request.body()
        if body:
            data = json.loads(body)
            if isinstance(data, dict):
                params = data.get("params", {})
                if isinstance(params, dict):
                    return params.get("name")
    except Exception:
        pass
    return None


def _extract_domain_from_dn(dn: str) -> str | None:
    """Extract domain from X.509 Distinguished Name (CN field)."""
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            cn = part[3:]
            return cn.lstrip("*.")
    return None
