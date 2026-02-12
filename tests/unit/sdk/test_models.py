# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for SDK models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from dns_aid.sdk.models import (
    AgentScorecard,
    InvocationResult,
    InvocationSignal,
    InvocationStatus,
)


class TestInvocationStatus:
    def test_enum_values(self) -> None:
        assert InvocationStatus.SUCCESS == "success"
        assert InvocationStatus.ERROR == "error"
        assert InvocationStatus.TIMEOUT == "timeout"
        assert InvocationStatus.REFUSED == "refused"


class TestInvocationSignal:
    def test_defaults(self) -> None:
        signal = InvocationSignal(
            agent_fqdn="_test._mcp._agents.example.com",
            agent_endpoint="https://mcp.example.com:443",
            protocol="mcp",
            invocation_latency_ms=150.0,
            status=InvocationStatus.SUCCESS,
        )
        assert isinstance(signal.id, uuid.UUID)
        assert isinstance(signal.timestamp, datetime)
        assert signal.discovery_latency_ms == 0.0
        assert signal.total_latency_ms == 0.0
        assert signal.dnssec_validated is False
        assert signal.caller_id is None
        assert signal.cost_units is None

    def test_full_signal(self) -> None:
        signal = InvocationSignal(
            agent_fqdn="_network._mcp._agents.example.com",
            agent_endpoint="https://mcp.example.com:443",
            protocol="mcp",
            method="tools/call",
            discovery_latency_ms=10.0,
            invocation_latency_ms=230.0,
            total_latency_ms=240.0,
            ttfb_ms=200.0,
            status=InvocationStatus.SUCCESS,
            http_status_code=200,
            cost_units=0.5,
            cost_currency="USD",
            response_size_bytes=1024,
            dnssec_validated=True,
            tls_version="TLSv1.3",
            caller_id="my-agent",
        )
        assert signal.total_latency_ms == 240.0
        assert signal.cost_units == 0.5
        assert signal.tls_version == "TLSv1.3"

    def test_signal_is_frozen(self) -> None:
        signal = InvocationSignal(
            agent_fqdn="_test._mcp._agents.example.com",
            agent_endpoint="https://mcp.example.com:443",
            protocol="mcp",
            invocation_latency_ms=100.0,
            status=InvocationStatus.SUCCESS,
        )
        # Frozen model — assignment should raise
        try:
            signal.invocation_latency_ms = 999.0  # type: ignore[misc]
            raise AssertionError("Should have raised ValidationError")
        except Exception:
            pass

    def test_error_signal(self) -> None:
        signal = InvocationSignal(
            agent_fqdn="_test._mcp._agents.example.com",
            agent_endpoint="https://mcp.example.com:443",
            protocol="mcp",
            invocation_latency_ms=5000.0,
            status=InvocationStatus.TIMEOUT,
            error_type="TimeoutError",
            error_message="Connection timed out",
        )
        assert signal.status == InvocationStatus.TIMEOUT
        assert signal.error_type == "TimeoutError"


class TestInvocationResult:
    def test_success_result(self) -> None:
        signal = InvocationSignal(
            agent_fqdn="_test._mcp._agents.example.com",
            agent_endpoint="https://mcp.example.com:443",
            protocol="mcp",
            invocation_latency_ms=100.0,
            status=InvocationStatus.SUCCESS,
        )
        result = InvocationResult(
            success=True,
            data={"tools": ["ping", "traceroute"]},
            signal=signal,
        )
        assert result.success is True
        assert result.data == {"tools": ["ping", "traceroute"]}
        assert result.signal.invocation_latency_ms == 100.0

    def test_error_result(self) -> None:
        signal = InvocationSignal(
            agent_fqdn="_test._mcp._agents.example.com",
            agent_endpoint="https://mcp.example.com:443",
            protocol="mcp",
            invocation_latency_ms=30000.0,
            status=InvocationStatus.TIMEOUT,
        )
        result = InvocationResult(
            success=False,
            data=None,
            signal=signal,
        )
        assert result.success is False
        assert result.data is None


class TestAgentScorecard:
    def test_empty_scorecard(self) -> None:
        sc = AgentScorecard(agent_fqdn="_test._mcp._agents.example.com")
        assert sc.total_invocations == 0
        assert sc.success_rate == 0.0
        assert sc.composite_score == 0.0
        assert sc.first_seen is None

    def test_scorecard_with_data(self) -> None:
        now = datetime.now(UTC)
        sc = AgentScorecard(
            agent_fqdn="_network._mcp._agents.example.com",
            total_invocations=100,
            success_count=95,
            error_count=3,
            timeout_count=2,
            success_rate=95.0,
            error_rate=5.0,
            avg_latency_ms=200.0,
            p50_latency_ms=180.0,
            p95_latency_ms=400.0,
            p99_latency_ms=800.0,
            min_latency_ms=50.0,
            max_latency_ms=1200.0,
            total_cost_units=50.0,
            avg_cost_units=0.5,
            composite_score=82.5,
            first_seen=now,
            last_seen=now,
        )
        assert sc.total_invocations == 100
        assert sc.success_rate == 95.0
        assert sc.composite_score == 82.5
