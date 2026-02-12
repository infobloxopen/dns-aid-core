# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ranking engine."""

from __future__ import annotations

from datetime import UTC, datetime

from dns_aid.sdk.models import AgentScorecard
from dns_aid.sdk.ranking.ranker import AgentRanker, RankedAgent
from dns_aid.sdk.ranking.strategies import (
    LatencyFirstStrategy,
    ReliabilityFirstStrategy,
    WeightedCompositeStrategy,
)
from dns_aid.sdk.signals.collector import SignalCollector


def _populate_collector(
    collector: SignalCollector,
    fqdn: str,
    *,
    success_count: int = 10,
    error_count: int = 0,
    latency_base: float = 100.0,
    cost: float | None = None,
) -> None:
    """Helper to populate a collector with mock signals."""
    from dns_aid.sdk.models import InvocationStatus
    from dns_aid.sdk.protocols.base import RawResponse

    for i in range(success_count):
        raw = RawResponse(
            success=True,
            status=InvocationStatus.SUCCESS,
            invocation_latency_ms=latency_base + i,
            http_status_code=200,
            cost_units=cost,
        )
        collector.record(
            agent_fqdn=fqdn,
            agent_endpoint="https://example.com:443",
            protocol="mcp",
            method="tools/call",
            raw=raw,
        )

    for _ in range(error_count):
        raw = RawResponse(
            success=False,
            status=InvocationStatus.ERROR,
            invocation_latency_ms=5000.0,
            error_type="HTTPError",
            error_message="Server error",
        )
        collector.record(
            agent_fqdn=fqdn,
            agent_endpoint="https://example.com:443",
            protocol="mcp",
            method="tools/call",
            raw=raw,
        )


class TestWeightedCompositeStrategy:
    def test_perfect_agent(self) -> None:
        now = datetime.now(UTC)
        sc = AgentScorecard(
            agent_fqdn="test",
            total_invocations=100,
            success_count=100,
            success_rate=100.0,
            avg_latency_ms=100.0,
            avg_cost_units=0.0,
            total_cost_units=0.0,
            last_seen=now,
        )
        strategy = WeightedCompositeStrategy()
        score = strategy.compute_score(sc)
        assert score > 80  # High reliability + low latency

    def test_slow_agent(self) -> None:
        now = datetime.now(UTC)
        sc = AgentScorecard(
            agent_fqdn="test",
            total_invocations=100,
            success_count=100,
            success_rate=100.0,
            avg_latency_ms=4000.0,
            last_seen=now,
        )
        strategy = WeightedCompositeStrategy()
        score = strategy.compute_score(sc)
        # High reliability but poor latency
        assert score < 80

    def test_unreliable_agent_scores_lower(self) -> None:
        """An unreliable agent scores lower than a reliable one."""
        now = datetime.now(UTC)
        unreliable = AgentScorecard(
            agent_fqdn="test",
            total_invocations=100,
            success_count=50,
            success_rate=50.0,
            avg_latency_ms=100.0,
            last_seen=now,
        )
        reliable = AgentScorecard(
            agent_fqdn="test",
            total_invocations=100,
            success_count=99,
            success_rate=99.0,
            avg_latency_ms=100.0,
            last_seen=now,
        )
        strategy = WeightedCompositeStrategy()
        assert strategy.compute_score(unreliable) < strategy.compute_score(reliable)


class TestLatencyFirstStrategy:
    def test_fast_beats_reliable(self) -> None:
        now = datetime.now(UTC)
        fast = AgentScorecard(
            agent_fqdn="fast",
            total_invocations=100,
            success_rate=90.0,
            avg_latency_ms=50.0,
            last_seen=now,
        )
        reliable = AgentScorecard(
            agent_fqdn="reliable",
            total_invocations=100,
            success_rate=99.0,
            avg_latency_ms=2000.0,
            last_seen=now,
        )
        strategy = LatencyFirstStrategy()
        assert strategy.compute_score(fast) > strategy.compute_score(reliable)


class TestReliabilityFirstStrategy:
    def test_reliable_beats_fast(self) -> None:
        now = datetime.now(UTC)
        fast = AgentScorecard(
            agent_fqdn="fast",
            total_invocations=100,
            success_rate=70.0,
            avg_latency_ms=50.0,
            last_seen=now,
        )
        reliable = AgentScorecard(
            agent_fqdn="reliable",
            total_invocations=100,
            success_rate=99.0,
            avg_latency_ms=2000.0,
            last_seen=now,
        )
        strategy = ReliabilityFirstStrategy()
        assert strategy.compute_score(reliable) > strategy.compute_score(fast)


class TestAgentRanker:
    def test_rank_multiple_agents(self) -> None:
        collector = SignalCollector()
        _populate_collector(collector, "fast_agent", latency_base=50, success_count=20)
        _populate_collector(
            collector, "slow_agent", latency_base=3000, success_count=10, error_count=5
        )
        _populate_collector(collector, "medium_agent", latency_base=500, success_count=15)

        ranker = AgentRanker(collector)
        ranked = ranker.rank()

        assert len(ranked) == 3
        assert isinstance(ranked[0], RankedAgent)
        # Fast agent should rank higher than slow/unreliable
        fqdns = [r.agent_fqdn for r in ranked]
        assert fqdns[0] == "fast_agent"

    def test_rank_with_explicit_fqdns(self) -> None:
        collector = SignalCollector()
        _populate_collector(collector, "agent_a", success_count=10)
        _populate_collector(collector, "agent_b", success_count=10)
        _populate_collector(collector, "agent_c", success_count=10)

        ranker = AgentRanker(collector)
        ranked = ranker.rank(["agent_a", "agent_b"])
        assert len(ranked) == 2

    def test_rank_skips_agents_without_signals(self) -> None:
        collector = SignalCollector()
        _populate_collector(collector, "has_signals", success_count=5)

        ranker = AgentRanker(collector)
        ranked = ranker.rank(["has_signals", "no_signals"])
        assert len(ranked) == 1
        assert ranked[0].agent_fqdn == "has_signals"

    def test_rank_with_custom_strategy(self) -> None:
        collector = SignalCollector()
        _populate_collector(collector, "agent_a", latency_base=100, success_count=10)

        ranker = AgentRanker(collector, strategy=LatencyFirstStrategy())
        assert ranker.strategy.name == "latency_first"

        ranked = ranker.rank()
        assert len(ranked) == 1
        assert ranked[0].composite_score > 0

    def test_empty_collector(self) -> None:
        collector = SignalCollector()
        ranker = AgentRanker(collector)
        ranked = ranker.rank()
        assert ranked == []
