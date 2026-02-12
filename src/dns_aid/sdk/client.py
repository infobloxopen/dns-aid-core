"""
AgentClient — main entry point for the DNS-AID Tier 1 SDK.

Wraps agent invocations with protocol handlers, captures telemetry
signals, and exports them according to configuration.
"""

from __future__ import annotations

import threading
from types import TracebackType

import httpx
import structlog

from dns_aid.core.models import AgentRecord
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.models import InvocationResult, InvocationSignal
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

    async def invoke(
        self,
        agent: AgentRecord,
        *,
        method: str | None = None,
        arguments: dict | None = None,
        timeout: float | None = None,
    ) -> InvocationResult:
        """
        Invoke an agent and capture a telemetry signal.

        Args:
            agent: The AgentRecord from dns_aid.discover().
            method: Protocol-specific method (e.g., "tools/call" for MCP).
            arguments: Method arguments / payload.
            timeout: Override timeout for this call (seconds).

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

        logger.debug(
            "sdk.invoke",
            agent_fqdn=agent.fqdn,
            endpoint=agent.endpoint_url,
            protocol=protocol,
            method=method,
        )

        raw = await handler.invoke(
            client=self._http_client,
            endpoint=agent.endpoint_url,
            method=method,
            arguments=arguments,
            timeout=effective_timeout,
        )

        signal = self._collector.record(
            agent_fqdn=agent.fqdn,
            agent_endpoint=agent.endpoint_url,
            protocol=protocol,
            method=method,
            raw=raw,
        )

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
        except Exception:
            logger.debug("sdk.http_push_failed", signal_id=str(signal.id), url=push_url)

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
