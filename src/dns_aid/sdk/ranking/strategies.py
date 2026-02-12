# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Ranking strategies for agent scoring.

Each strategy defines a different weighting for the composite score.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from dns_aid.sdk.models import AgentScorecard


class RankingStrategy(ABC):
    """Abstract base for ranking strategies."""

    @abstractmethod
    def compute_score(self, scorecard: AgentScorecard) -> float:
        """Compute a composite score (0-100) from a scorecard."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Strategy identifier."""
        ...


class WeightedCompositeStrategy(RankingStrategy):
    """
    Default strategy: weighted combination of reliability, latency, cost, freshness.

    Weights: 40% reliability, 30% latency, 15% cost, 15% freshness.
    """

    @property
    def name(self) -> str:
        return "weighted_composite"

    def compute_score(self, scorecard: AgentScorecard) -> float:
        reliability = scorecard.success_rate
        latency = max(0.0, 100 * (1 - scorecard.avg_latency_ms / 5000))
        cost = _cost_score(scorecard)
        freshness = _freshness_score(scorecard)

        return round(
            0.40 * reliability + 0.30 * latency + 0.15 * cost + 0.15 * freshness,
            2,
        )


class LatencyFirstStrategy(RankingStrategy):
    """Prioritize low-latency agents. Weights: 60% latency, 25% reliability, 15% cost."""

    @property
    def name(self) -> str:
        return "latency_first"

    def compute_score(self, scorecard: AgentScorecard) -> float:
        reliability = scorecard.success_rate
        latency = max(0.0, 100 * (1 - scorecard.avg_latency_ms / 5000))
        cost = _cost_score(scorecard)

        return round(0.60 * latency + 0.25 * reliability + 0.15 * cost, 2)


class ReliabilityFirstStrategy(RankingStrategy):
    """Prioritize reliable agents. Weights: 70% reliability, 15% latency, 15% cost."""

    @property
    def name(self) -> str:
        return "reliability_first"

    def compute_score(self, scorecard: AgentScorecard) -> float:
        reliability = scorecard.success_rate
        latency = max(0.0, 100 * (1 - scorecard.avg_latency_ms / 5000))
        cost = _cost_score(scorecard)

        return round(0.70 * reliability + 0.15 * latency + 0.15 * cost, 2)


def _cost_score(scorecard: AgentScorecard) -> float:
    """Compute cost efficiency score (0-100). Lower cost = higher score."""
    if scorecard.total_cost_units <= 0:
        return 100.0
    # Normalize: assume $1 per invocation is expensive
    avg = scorecard.avg_cost_units
    return max(0.0, 100 * (1 - avg))


def _freshness_score(scorecard: AgentScorecard) -> float:
    """Compute freshness score (0-100). More recent = higher score."""
    from datetime import UTC, datetime

    if scorecard.last_seen is None:
        return 0.0
    age_hours = (datetime.now(UTC) - scorecard.last_seen).total_seconds() / 3600
    return max(0.0, 100 * (1 - age_hours / (24 * 7)))
