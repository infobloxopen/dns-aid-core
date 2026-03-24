# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Agent-aware circuit breaker for cascading failure protection.

Tracks consecutive failures per agent FQDN (not per URL). After a
configurable threshold, the circuit opens and rejects calls immediately.
After a cooldown period, the circuit transitions to half-open to test
recovery. One success closes the circuit; one failure reopens it.

State machine::

    CLOSED  ──N failures──▸  OPEN
    OPEN    ──cooldown──▸    HALF_OPEN
    HALF_OPEN ──success──▸   CLOSED
    HALF_OPEN ──failure──▸   OPEN
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class _CircuitState:
    """Per-agent circuit state."""

    failures: int = 0
    last_failure: float = 0.0
    state: str = "closed"  # "closed" | "open" | "half_open"


class CircuitBreaker:
    """Agent-aware circuit breaker keyed by FQDN.

    Thread-safety note: intended for use within a single AgentClient
    instance. If shared across threads, external synchronization is needed.
    """

    def __init__(
        self,
        *,
        enabled: bool = False,
        threshold: int = 5,
        cooldown: float = 60.0,
    ) -> None:
        self._enabled = enabled
        self._threshold = threshold
        self._cooldown = cooldown
        self._circuits: dict[str, _CircuitState] = {}

    def get_state(self, fqdn: str) -> str:
        """Get the current circuit state for an agent, applying cooldown transition.

        Returns "closed", "open", or "half_open".
        """
        if not self._enabled:
            return "closed"
        circuit = self._circuits.get(fqdn)
        if circuit is None:
            return "closed"
        if circuit.state == "open":
            if (time.monotonic() - circuit.last_failure) >= self._cooldown:
                circuit.state = "half_open"
        return circuit.state

    def record_success(self, fqdn: str) -> None:
        """Record a successful invocation — resets failures and closes circuit."""
        if not self._enabled:
            return
        circuit = self._circuits.get(fqdn)
        if circuit is not None:
            circuit.failures = 0
            circuit.state = "closed"

    def record_failure(self, fqdn: str) -> None:
        """Record a failed invocation — increments failures, may open circuit."""
        if not self._enabled:
            return
        circuit = self._circuits.get(fqdn, _CircuitState())
        circuit.failures += 1
        circuit.last_failure = time.monotonic()
        if circuit.failures >= self._threshold:
            circuit.state = "open"
        self._circuits[fqdn] = circuit

    @property
    def circuits(self) -> dict[str, str]:
        """Snapshot of all circuit states (for debugging/telemetry)."""
        return {fqdn: c.state for fqdn, c in self._circuits.items()}
