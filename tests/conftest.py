# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Pytest fixtures for DNS-AID tests."""

import pytest

from dns_aid.backends.mock import MockBackend
from dns_aid.core.models import AgentRecord, Protocol


@pytest.fixture
def mock_backend() -> MockBackend:
    """Create a fresh mock backend for each test."""
    return MockBackend()


@pytest.fixture
def sample_agent() -> AgentRecord:
    """Sample agent record for testing."""
    return AgentRecord(
        name="network-specialist",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=["ipam", "dns", "vpn"],
        version="1.0.0",
        description="Network management agent",
    )


@pytest.fixture
def sample_a2a_agent() -> AgentRecord:
    """Sample A2A agent record for testing."""
    return AgentRecord(
        name="chat",
        domain="example.com",
        protocol=Protocol.A2A,
        target_host="chat.example.com",
        port=443,
        capabilities=["chat", "assistant"],
    )
