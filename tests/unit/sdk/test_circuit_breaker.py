# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for agent-aware circuit breaker (Phase 6.6)."""

from __future__ import annotations

from unittest.mock import patch

from dns_aid.sdk._circuit_breaker import CircuitBreaker


class TestCircuitBreakerStateTransitions:
    """Test the CLOSED → OPEN → HALF_OPEN → CLOSED state machine."""

    def test_starts_closed(self) -> None:
        cb = CircuitBreaker(enabled=True, threshold=3, cooldown=10.0)
        assert cb.get_state("agent.example.com") == "closed"

    def test_stays_closed_below_threshold(self) -> None:
        cb = CircuitBreaker(enabled=True, threshold=3, cooldown=10.0)
        cb.record_failure("agent.example.com")
        cb.record_failure("agent.example.com")
        assert cb.get_state("agent.example.com") == "closed"

    def test_opens_at_threshold(self) -> None:
        cb = CircuitBreaker(enabled=True, threshold=3, cooldown=10.0)
        for _ in range(3):
            cb.record_failure("agent.example.com")
        assert cb.get_state("agent.example.com") == "open"

    def test_open_to_half_open_after_cooldown(self) -> None:
        cb = CircuitBreaker(enabled=True, threshold=3, cooldown=10.0)
        for _ in range(3):
            cb.record_failure("agent.example.com")
        assert cb.get_state("agent.example.com") == "open"

        # Simulate cooldown elapsed
        with patch("dns_aid.sdk._circuit_breaker.time.monotonic", return_value=1e9):
            assert cb.get_state("agent.example.com") == "half_open"

    def test_half_open_to_closed_on_success(self) -> None:
        cb = CircuitBreaker(enabled=True, threshold=3, cooldown=10.0)
        for _ in range(3):
            cb.record_failure("agent.example.com")

        # Transition to half_open via cooldown
        with patch("dns_aid.sdk._circuit_breaker.time.monotonic", return_value=1e9):
            assert cb.get_state("agent.example.com") == "half_open"

        # Success closes it
        cb.record_success("agent.example.com")
        assert cb.get_state("agent.example.com") == "closed"

    def test_half_open_to_open_on_failure(self) -> None:
        cb = CircuitBreaker(enabled=True, threshold=3, cooldown=10.0)
        for _ in range(3):
            cb.record_failure("agent.example.com")

        # Transition to half_open via cooldown
        with patch("dns_aid.sdk._circuit_breaker.time.monotonic", return_value=1e9):
            assert cb.get_state("agent.example.com") == "half_open"

        # Failure reopens (1 failure >= threshold=3? No, but half_open + failure → open)
        cb.record_failure("agent.example.com")
        assert cb.get_state("agent.example.com") == "open"

    def test_success_resets_failure_count(self) -> None:
        cb = CircuitBreaker(enabled=True, threshold=3, cooldown=10.0)
        cb.record_failure("agent.example.com")
        cb.record_failure("agent.example.com")
        cb.record_success("agent.example.com")
        # Failures reset, so 2 more failures shouldn't open
        cb.record_failure("agent.example.com")
        cb.record_failure("agent.example.com")
        assert cb.get_state("agent.example.com") == "closed"


class TestCircuitBreakerIsolation:
    """Test that different agents have independent circuits."""

    def test_independent_circuits(self) -> None:
        cb = CircuitBreaker(enabled=True, threshold=2, cooldown=10.0)
        # Open circuit for agent A
        cb.record_failure("a.example.com")
        cb.record_failure("a.example.com")
        assert cb.get_state("a.example.com") == "open"
        # Agent B should still be closed
        assert cb.get_state("b.example.com") == "closed"

    def test_circuits_snapshot(self) -> None:
        cb = CircuitBreaker(enabled=True, threshold=2, cooldown=10.0)
        cb.record_failure("a.example.com")
        cb.record_failure("a.example.com")
        cb.record_failure("b.example.com")
        assert cb.circuits == {
            "a.example.com": "open",
            "b.example.com": "closed",
        }


class TestCircuitBreakerDisabled:
    """Test that circuit breaker is a no-op when disabled."""

    def test_disabled_always_closed(self) -> None:
        cb = CircuitBreaker(enabled=False, threshold=1, cooldown=1.0)
        cb.record_failure("agent.example.com")
        cb.record_failure("agent.example.com")
        assert cb.get_state("agent.example.com") == "closed"

    def test_disabled_no_state_tracking(self) -> None:
        cb = CircuitBreaker(enabled=False)
        cb.record_failure("agent.example.com")
        cb.record_success("agent.example.com")
        assert cb.circuits == {}


class TestCircuitBreakerConfig:
    """Test circuit breaker configuration via SDKConfig."""

    def test_config_from_env(self) -> None:
        from dns_aid.sdk._config import SDKConfig

        with patch.dict(
            "os.environ",
            {
                "DNS_AID_CIRCUIT_BREAKER": "true",
                "DNS_AID_CIRCUIT_BREAKER_THRESHOLD": "10",
                "DNS_AID_CIRCUIT_BREAKER_COOLDOWN": "120",
            },
        ):
            config = SDKConfig.from_env()
            assert config.circuit_breaker_enabled is True
            assert config.circuit_breaker_threshold == 10
            assert config.circuit_breaker_cooldown == 120.0

    def test_config_defaults(self) -> None:
        from dns_aid.sdk._config import SDKConfig

        config = SDKConfig()
        assert config.circuit_breaker_enabled is False
        assert config.circuit_breaker_threshold == 5
        assert config.circuit_breaker_cooldown == 60.0
