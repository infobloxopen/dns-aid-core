# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
AgentClient — main entry point for the DNS-AID Tier 1 SDK.

Wraps agent invocations with protocol handlers, captures telemetry
signals, and exports them according to configuration.
"""

from __future__ import annotations

import threading
import time as _time
from types import TracebackType

import httpx
import structlog

from dns_aid.core.models import AgentRecord
from dns_aid.sdk._circuit_breaker import CircuitBreaker
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.auth import resolve_auth_handler
from dns_aid.sdk.auth.base import AuthHandler
from dns_aid.sdk.models import InvocationResult, InvocationSignal, InvocationStatus
from dns_aid.sdk.policy.evaluator import PolicyEvaluator
from dns_aid.sdk.policy.models import PolicyContext, PolicyViolationError
from dns_aid.sdk.policy.schema import PolicyEnforcementLayer
from dns_aid.sdk.protocols.a2a import A2AProtocolHandler
from dns_aid.sdk.protocols.base import ProtocolHandler
from dns_aid.sdk.protocols.https import HTTPSProtocolHandler
from dns_aid.sdk.protocols.mcp import MCPProtocolHandler
from dns_aid.sdk.signals.collector import SignalCollector

logger = structlog.get_logger(__name__)

# Protocol handler registry
_HANDLERS: dict[str, type[ProtocolHandler]] = {
    "mcp": MCPProtocolHandler,
    "a2a": A2AProtocolHandler,
    "https": HTTPSProtocolHandler,
}


class AgentClient:
    """
    DNS-AID SDK client for invoking agents and collecting telemetry.

    Usage::

        async with AgentClient() as client:
            result = await client.invoke(agent, method="tools/list")
            print(result.signal.invocation_latency_ms)

    Supports MCP agents out of the box. A2A and HTTPS handlers
    are registered in Phase F.
    """

    def __init__(self, config: SDKConfig | None = None) -> None:
        self._config = config or SDKConfig.from_env()
        self._http_client: httpx.AsyncClient | None = None
        self._collector = SignalCollector(
            console=self._config.console_signals,
            caller_id=self._config.caller_id,
        )
        self._handlers: dict[str, ProtocolHandler] = {}
        self._policy_evaluator: PolicyEvaluator | None = None
        self._circuit_breaker = CircuitBreaker(
            enabled=self._config.circuit_breaker_enabled,
            threshold=self._config.circuit_breaker_threshold,
            cooldown=self._config.circuit_breaker_cooldown,
        )

    async def __aenter__(self) -> AgentClient:
        self._http_client = httpx.AsyncClient(
            timeout=self._config.timeout_seconds,
            follow_redirects=True,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    def _get_handler(self, protocol: str) -> ProtocolHandler:
        """Get or create a protocol handler for the given protocol."""
        if protocol not in self._handlers:
            handler_cls = _HANDLERS.get(protocol)
            if handler_cls is None:
                raise ValueError(
                    f"Unsupported protocol: {protocol}. Available: {', '.join(_HANDLERS.keys())}"
                )
            self._handlers[protocol] = handler_cls()
        return self._handlers[protocol]

    def _resolve_auth(
        self,
        agent: AgentRecord,
        credentials: dict | None,
    ) -> AuthHandler | None:
        """Resolve an auth handler from agent metadata and credentials.

        Returns *None* when the agent requires no auth or credentials
        are not supplied.
        """
        auth_type = getattr(agent, "auth_type", None)
        if not auth_type or auth_type == "none":
            return None
        if not credentials:
            logger.debug(
                "sdk.auth_skipped",
                agent_fqdn=agent.fqdn,
                auth_type=auth_type,
                reason="no credentials provided",
            )
            return None
        auth_config = getattr(agent, "auth_config", None) or {}
        try:
            return resolve_auth_handler(
                auth_type=str(auth_type),
                auth_config=auth_config if isinstance(auth_config, dict) else {},
                credentials=credentials,
            )
        except ValueError as exc:
            raise ValueError(
                f"Auth resolution failed for agent {agent.fqdn!r} (auth_type={auth_type!r}): {exc}"
            ) from exc

    async def invoke(
        self,
        agent: AgentRecord,
        *,
        method: str | None = None,
        arguments: dict | None = None,
        timeout: float | None = None,
        credentials: dict | None = None,
        auth_handler: AuthHandler | None = None,
    ) -> InvocationResult:
        """
        Invoke an agent and capture a telemetry signal.

        Args:
            agent: The AgentRecord from dns_aid.discover().
            method: Protocol-specific method (e.g., "tools/call" for MCP).
            arguments: Method arguments / payload.
            timeout: Override timeout for this call (seconds).
            credentials: Caller-supplied secrets (tokens, client_id/secret)
                for automatic auth resolution from agent metadata.
            auth_handler: Explicit auth handler override. When provided,
                *credentials* and agent metadata are ignored.

        Returns:
            InvocationResult with the response data and attached signal.
        """
        if self._http_client is None:
            raise RuntimeError(
                "AgentClient must be used as an async context manager: "
                "async with AgentClient() as client: ..."
            )

        protocol = agent.protocol.value if hasattr(agent.protocol, "value") else str(agent.protocol)
        handler = self._get_handler(protocol)
        effective_timeout = timeout or self._config.timeout_seconds

        # Resolve auth handler from agent metadata or explicit override
        resolved_auth = auth_handler or self._resolve_auth(agent, credentials)

        logger.debug(
            "sdk.invoke",
            agent_fqdn=agent.fqdn,
            endpoint=agent.endpoint_url,
            protocol=protocol,
            method=method,
            auth_type=resolved_auth.auth_type if resolved_auth else None,
        )

        # --- Tool name extraction (Phase 6.6) ---
        tool_name: str | None = None
        if method == "tools/call" and isinstance(arguments, dict):
            tool_name = arguments.get("name")
        elif protocol == "a2a":
            tool_name = method  # A2A method IS the "tool"

        # --- Circuit breaker pre-check (Phase 6.6) ---
        circuit_state = self._circuit_breaker.get_state(agent.fqdn)
        if circuit_state == "open":
            logger.warning(
                "sdk.circuit_open",
                agent_fqdn=agent.fqdn,
                threshold=self._config.circuit_breaker_threshold,
            )
            signal = InvocationSignal(
                agent_fqdn=agent.fqdn,
                agent_endpoint=agent.endpoint_url,
                protocol=protocol,
                method=method,
                invocation_latency_ms=0.0,
                status=InvocationStatus.REFUSED,
                error_type="circuit_open",
                error_message=f"Circuit open for {agent.fqdn}",
                caller_id=self._config.caller_id,
            )
            return InvocationResult(
                success=False,
                data={"error": "circuit_open", "agent_fqdn": agent.fqdn},
                signal=signal,
            )

        # --- Policy enforcement (Phase 6 §3.20) --- Layer 1: caller-side ---
        policy_result_data = None
        policy_doc = None
        policy_fetch_ms = None
        if self._config.policy_mode != "disabled" and getattr(agent, "policy_uri", None):
            if self._policy_evaluator is None:
                self._policy_evaluator = PolicyEvaluator(
                    cache_ttl=self._config.policy_cache_ttl,
                )
            try:
                _t0 = _time.monotonic()
                policy_doc = await self._policy_evaluator.fetch(agent.policy_uri)
                policy_fetch_ms = (_time.monotonic() - _t0) * 1000

                ctx = PolicyContext(
                    caller_id=self._config.caller_id,
                    caller_domain=self._config.caller_domain,
                    protocol=protocol,
                    method=method,
                    auth_type=resolved_auth.auth_type if resolved_auth else None,
                    dnssec_validated=getattr(agent, "dnssec_validated", False),
                    tool_name=tool_name,
                    target_circuit_state=circuit_state,
                )
                policy_result_data = self._policy_evaluator.evaluate(
                    policy_doc,
                    ctx,
                    layer=PolicyEnforcementLayer.CALLER,
                )
                if policy_result_data.denied and self._config.policy_mode == "strict":
                    raise PolicyViolationError(policy_result_data)
                if policy_result_data.denied:
                    logger.warning(
                        "sdk.policy_violation",
                        agent_fqdn=agent.fqdn,
                        mode=self._config.policy_mode,
                        violations=[f"{v.rule}:{v.detail}" for v in policy_result_data.violations],
                    )
            except PolicyViolationError:
                raise
            except Exception as exc:
                logger.warning(
                    "sdk.policy_fetch_failed",
                    error=str(exc),
                    policy_uri=agent.policy_uri,
                )
        # --- end policy enforcement ---

        raw = await handler.invoke(
            client=self._http_client,
            endpoint=agent.endpoint_url,
            method=method,
            arguments=arguments,
            timeout=effective_timeout,
            auth_handler=resolved_auth,
        )

        # --- Circuit breaker post-update (Phase 6.6) ---
        if raw.status == InvocationStatus.SUCCESS:
            self._circuit_breaker.record_success(agent.fqdn)
        else:
            self._circuit_breaker.record_failure(agent.fqdn)

        # Capture target-side policy result (Layer 2) from response header
        target_policy_result = None
        if hasattr(raw, "headers") and raw.headers:
            target_policy_result = raw.headers.get("X-DNS-AID-Policy-Result")

        signal = self._collector.record(
            agent_fqdn=agent.fqdn,
            agent_endpoint=agent.endpoint_url,
            protocol=protocol,
            method=method,
            raw=raw,
            auth_type=resolved_auth.auth_type if resolved_auth else None,
            auth_applied=resolved_auth is not None,
        )

        # Enrich signal with policy data
        if policy_result_data is not None or target_policy_result:
            signal.policy_enforced = True
            signal.policy_mode = self._config.policy_mode
            if policy_result_data:
                signal.policy_result = "allowed" if policy_result_data.allowed else "denied"
                signal.policy_violations = (
                    [f"{v.rule}:{v.detail}" for v in policy_result_data.violations]
                    if policy_result_data.violations
                    else None
                )
                signal.policy_version = policy_doc.version if policy_doc else None
                signal.policy_fetch_time_ms = policy_fetch_ms
            signal.target_policy_result = target_policy_result

        # HTTP push to telemetry API if configured (true fire-and-forget via thread)
        if self._config.http_push_url:
            thread = threading.Thread(
                target=self._push_signal_http_sync,
                args=(signal, self._config.http_push_url),
                daemon=True,
            )
            thread.start()

        return InvocationResult(
            success=raw.success,
            data=raw.data,
            signal=signal,
        )

    @staticmethod
    def _push_signal_http_sync(signal: InvocationSignal, push_url: str) -> None:
        """POST a signal to the telemetry API. Runs in a daemon thread, fire-and-forget."""
        try:
            payload = signal.model_dump(mode="json")
            payload.pop("id", None)
            if hasattr(signal.status, "value"):
                payload["status"] = signal.status.value
            resp = httpx.post(push_url, json=payload, timeout=5.0)
            if resp.status_code in (200, 201, 202):
                logger.debug("sdk.http_push_ok", signal_id=str(signal.id), url=push_url)
            else:
                logger.warning(
                    "sdk.http_push_rejected",
                    signal_id=str(signal.id),
                    status_code=resp.status_code,
                    body=resp.text[:200],
                )
        except Exception as e:
            logger.warning(
                "sdk.http_push_failed",
                signal_id=str(signal.id),
                url=push_url,
                error=str(e),
                exc_info=True,
            )

    def rank(
        self,
        agent_fqdns: list[str] | None = None,
        strategy: object | None = None,
    ) -> list:
        """
        Rank agents by their telemetry signals.

        Args:
            agent_fqdns: FQDNs to rank. If None, ranks all agents with signals.
            strategy: Optional RankingStrategy to use.

        Returns:
            List of RankedAgent sorted by composite score.
        """
        from dns_aid.sdk.ranking.ranker import AgentRanker
        from dns_aid.sdk.ranking.strategies import RankingStrategy

        strat = strategy if isinstance(strategy, RankingStrategy) else None
        ranker = AgentRanker(self._collector, strategy=strat)
        return ranker.rank(agent_fqdns)

    @property
    def collector(self) -> SignalCollector:
        """Access the signal collector for querying signals and scorecards."""
        return self._collector

    async def fetch_rankings(
        self,
        fqdns: list[str] | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """
        Fetch community-wide rankings from the central telemetry API.

        This retrieves aggregated rankings based on telemetry data from all
        SDK users, providing a global view of agent reliability and performance.

        Args:
            fqdns: Optional list of agent FQDNs to filter rankings.
                   If provided, only returns rankings for these agents.
            limit: Maximum number of rankings to fetch (default: 50).

        Returns:
            List of ranking dicts, each containing:
            - agent_fqdn: The agent's fully qualified domain name
            - composite_score: Overall score (0-100)
            - reliability_score: Uptime/success rate score
            - latency_score: Response time score
            - invocation_count: Total invocations tracked

        Example::

            async with AgentClient() as client:
                # Get top 10 rankings for specific agents
                fqdns = [a.fqdn for a in discovered_agents]
                rankings = await client.fetch_rankings(fqdns=fqdns, limit=10)
                best = rankings[0] if rankings else None
        """
        if self._http_client is None:
            raise RuntimeError(
                "AgentClient must be used as an async context manager: "
                "async with AgentClient() as client: ..."
            )

        if not self._config.telemetry_api_url:
            logger.debug("sdk.fetch_rankings_skipped", reason="telemetry_api_url not configured")
            return []

        url = f"{self._config.telemetry_api_url}/api/v1/telemetry/rankings"
        params = {"limit": limit}

        logger.debug("sdk.fetch_rankings", url=url, limit=limit, fqdns=fqdns)

        try:
            resp = await self._http_client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            rankings = data.get("rankings", [])

            # Filter by FQDNs if provided
            if fqdns:
                fqdn_set = set(fqdns)
                rankings = [r for r in rankings if r.get("agent_fqdn") in fqdn_set]

            logger.debug("sdk.fetch_rankings_ok", count=len(rankings))
            return rankings

        except httpx.HTTPStatusError as e:
            logger.warning(
                "sdk.fetch_rankings_failed",
                status_code=e.response.status_code,
                detail=e.response.text[:200],
            )
            return []
        except Exception:
            logger.warning("sdk.fetch_rankings_error", exc_info=True)
            return []

    @classmethod
    def register_handler(cls, protocol: str, handler_cls: type[ProtocolHandler]) -> None:
        """Register a custom protocol handler."""
        _HANDLERS[protocol] = handler_cls
