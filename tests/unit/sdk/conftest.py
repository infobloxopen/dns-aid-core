# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for SDK tests."""

from __future__ import annotations

import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig


@pytest.fixture
def sdk_config() -> SDKConfig:
    """Default SDK config for testing."""
    return SDKConfig(
        timeout_seconds=5.0,
        caller_id="test-caller",
        console_signals=False,
    )


@pytest.fixture
def sample_mcp_agent() -> AgentRecord:
    """A sample MCP agent record for testing."""
    return AgentRecord(
        name="network",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=["ipam", "dns"],
        version="1.0.0",
    )


@pytest.fixture
def sample_a2a_agent() -> AgentRecord:
    """A sample A2A agent record for testing."""
    return AgentRecord(
        name="chat",
        domain="example.com",
        protocol=Protocol.A2A,
        target_host="a2a.example.com",
        port=443,
        capabilities=["conversation"],
        version="1.0.0",
    )
