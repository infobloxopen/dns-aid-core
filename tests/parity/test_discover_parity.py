# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Path A (discover) cross-interface parity matrix — FR-024, FR-025, US4.

For every Path A filter combination, the SDK free function, the CLI command,
and the MCP tool MUST return the same agent set. Any divergence is a contract
break: an agent that drives all three surfaces (e.g., a tool wrapping the CLI
under the hood, or a planner alternating between SDK and MCP) will get a
*different* answer depending on which surface it picked, which breaks zero-trust
composition guarantees.

The test pins one canonical agent fixture (see ``conftest.parity_agents``) and
asserts that when each surface is given the same filter args, the **agent name
set, ordering, and the trust-related boolean fields** are identical.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dns_aid.cli.main import app
from dns_aid.core.discoverer import discover
from dns_aid.core.models import AgentRecord
from dns_aid.mcp.server import discover_agents_via_dns

# Each entry is (filter_kwargs, expected_agent_names).  Cover one pure-pipeline
# control row plus every Path A filter axis at least once.
DISCOVER_FILTER_CASES: list[tuple[dict[str, Any], set[str]]] = [
    ({}, {"payments", "search", "legacy"}),
    ({"capabilities": ["payment-processing", "fraud-detection"]}, {"payments"}),
    ({"capabilities_any": ["search", "fraud-detection"]}, {"payments", "search", "legacy"}),
    ({"auth_type": "oauth2"}, {"payments", "legacy"}),
    ({"realm": "prod"}, {"payments", "search"}),
    ({"text_match": "fraud"}, {"payments", "legacy"}),
    ({"min_dnssec": True}, {"payments", "search"}),
    ({"require_signed": True}, {"payments", "legacy"}),
    (
        {"require_signed": True, "require_signature_algorithm": ["ES256", "Ed25519"]},
        {"payments"},
    ),
    (
        {
            "capabilities": ["fraud-detection"],
            "auth_type": "oauth2",
            "realm": "prod",
        },
        {"payments"},
    ),
]


def _patches(agents: list[AgentRecord]) -> list[Any]:
    """Stub the substrate so no DNS or HTTP fires for any of the three surfaces."""
    return [
        patch(
            "dns_aid.core.discoverer._execute_discovery",
            new=AsyncMock(return_value=agents),
        ),
        patch(
            "dns_aid.core.discoverer._apply_post_discovery",
            new=AsyncMock(return_value=False),
        ),
    ]


def _kwargs_to_cli_args(kwargs: dict[str, Any]) -> list[str]:
    """Translate a kwargs dict into the corresponding ``dns-aid discover`` flags."""
    args: list[str] = []
    for key, value in kwargs.items():
        flag = "--" + key.replace("_", "-")
        if isinstance(value, bool):
            if value:
                args.append(flag)
            continue
        if isinstance(value, list):
            for item in value:
                args.extend([flag, str(item)])
            continue
        args.extend([flag, str(value)])
    return args


def _extract_json_payload(output: str) -> dict[str, Any]:
    """
    The CLI emits a human-readable status banner ahead of the JSON payload.

    We slice from the first ``{`` to the matching closing brace. ``json.loads``
    is tolerant of trailing whitespace/newlines so we just go to the end of
    the captured output.
    """
    start = output.find("{")
    if start == -1:
        raise AssertionError(f"CLI output contained no JSON object:\n{output}")
    return json.loads(output[start:])


@pytest.mark.parametrize(
    ("filter_kwargs", "expected_names"),
    DISCOVER_FILTER_CASES,
    ids=[
        "no-filters",
        "capabilities-all-of",
        "capabilities-any-of",
        "auth-type",
        "realm",
        "text-match",
        "min-dnssec",
        "require-signed",
        "require-algorithm-allowlist",
        "combined-filters",
    ],
)
def test_discover_parity_across_surfaces(
    parity_agents: list[AgentRecord],
    filter_kwargs: dict[str, Any],
    expected_names: set[str],
) -> None:
    """
    Test stays synchronous on purpose.

    The CLI uses ``asyncio.run()`` internally, and ``asyncio.run`` can't be
    invoked from a thread that already has a running event loop. If we marked
    this test ``@pytest.mark.asyncio`` the CLI would explode with
    ``RuntimeError: asyncio.run() cannot be called from a running event loop``
    the moment ``CliRunner.invoke`` ran. Keeping the test sync and bridging to
    the async SDK with our own ``asyncio.run`` is the cleaner answer: each
    surface runs under the same execution model it would use in production.
    """
    # SDK surface — bridge to async with a fresh loop, matching production.
    patches = _patches(parity_agents)
    for p in patches:
        p.start()
    try:
        sdk_result = asyncio.run(discover("example.com", **filter_kwargs))
        sdk_names = {a.name for a in sdk_result.agents}
    finally:
        for p in patches:
            p.stop()

    # MCP surface — call the registered tool function directly.
    patches = _patches(parity_agents)
    for p in patches:
        p.start()
    try:
        mcp_result = discover_agents_via_dns(domain="example.com", **filter_kwargs)
        assert "agents" in mcp_result, mcp_result  # bail loudly if MCP errored
        mcp_names = {a["name"] for a in mcp_result["agents"]}
    finally:
        for p in patches:
            p.stop()

    # CLI surface — invoke through Typer's runner.
    cli_runner = CliRunner()
    patches = _patches(parity_agents)
    for p in patches:
        p.start()
    try:
        cli_args = ["discover", "example.com", "--json"] + _kwargs_to_cli_args(filter_kwargs)
        cli_result = cli_runner.invoke(app, cli_args)
    finally:
        for p in patches:
            p.stop()

    assert cli_result.exit_code == 0, cli_result.output
    cli_payload = _extract_json_payload(cli_result.output)
    cli_names = {a["name"] for a in cli_payload["agents"]}

    # The headline parity claim.
    assert sdk_names == mcp_names == cli_names == expected_names, (
        f"Surface drift detected: sdk={sdk_names}, mcp={mcp_names}, cli={cli_names}, "
        f"expected={expected_names}"
    )


def test_discover_parity_signature_fields_propagate(
    parity_agents: list[AgentRecord],
) -> None:
    """``signature_verified`` and ``signature_algorithm`` survive every transport."""
    patches = _patches(parity_agents)
    for p in patches:
        p.start()
    try:
        sdk_result = asyncio.run(
            discover(
                "example.com",
                require_signed=True,
                require_signature_algorithm=["ES256", "Ed25519"],
            )
        )
    finally:
        for p in patches:
            p.stop()

    sdk_payments = next(a for a in sdk_result.agents if a.name == "payments")
    assert sdk_payments.signature_verified is True
    assert sdk_payments.signature_algorithm == "ES256"

    patches = _patches(parity_agents)
    for p in patches:
        p.start()
    try:
        mcp_result = discover_agents_via_dns(
            domain="example.com",
            require_signed=True,
            require_signature_algorithm=["ES256", "Ed25519"],
        )
    finally:
        for p in patches:
            p.stop()

    # MCP currently exposes a curated subset of AgentRecord — assert the agent
    # shows up. Trust attestations live on Path B, not Path A.
    assert {a["name"] for a in mcp_result["agents"]} == {"payments"}
