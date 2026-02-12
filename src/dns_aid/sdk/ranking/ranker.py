# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
AgentRanker — ranks agents by their telemetry scorecards.

Uses a pluggable RankingStrategy to compute composite scores,
then sorts agents by score descending.
"""

from __future__ import annotations

from dataclasses import dataclass

from dns_aid.sdk.models import AgentScorecard
from dns_aid.sdk.ranking.strategies import RankingStrategy, WeightedCompositeStrategy
from dns_aid.sdk.signals.collector import SignalCollector


@dataclass
class RankedAgent:
    """An agent with a computed ranking score."""

    agent_fqdn: str
    composite_score: float
    scorecard: AgentScorecard


class AgentRanker:
    """
    Ranks agents based on collected invocation signals.

    Usage::

        ranker = AgentRanker(collector)
        ranked = ranker.rank(agent_fqdns)
        for r in ranked:
            print(f"{r.agent_fqdn}: {r.composite_score:.1f}")
    """

    def __init__(
        self,
        collector: SignalCollector,
        strategy: RankingStrategy | None = None,
    ) -> None:
        self._collector = collector
        self._strategy = strategy or WeightedCompositeStrategy()

    @property
    def strategy(self) -> RankingStrategy:
        return self._strategy

    def rank(self, agent_fqdns: list[str] | None = None) -> list[RankedAgent]:
        """
        Rank agents by their composite score.

        Args:
            agent_fqdns: List of FQDNs to rank. If None, ranks all agents
                         that have signals in the collector.

        Returns:
            List of RankedAgent sorted by composite score descending.
        """
        if agent_fqdns is None:
            # Discover all unique FQDNs from signals
            seen = set()
            agent_fqdns = []
            for s in self._collector.signals:
                if s.agent_fqdn not in seen:
                    seen.add(s.agent_fqdn)
                    agent_fqdns.append(s.agent_fqdn)

        ranked = []
        for fqdn in agent_fqdns:
            scorecard = self._collector.scorecard(fqdn)
            if scorecard.total_invocations == 0:
                continue
            score = self._strategy.compute_score(scorecard)
            ranked.append(
                RankedAgent(
                    agent_fqdn=fqdn,
                    composite_score=score,
                    scorecard=scorecard,
                )
            )

        ranked.sort(key=lambda r: r.composite_score, reverse=True)
        return ranked
