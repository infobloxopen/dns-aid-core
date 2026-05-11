# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Path B (search) cross-interface parity matrix — FR-024, FR-025, US4.

For every Path B query, the SDK ``AgentClient.search()`` call, the CLI
``dns-aid search`` invocation, and the MCP ``search_agents`` tool MUST agree
on the same set of results, totals, and trust attestations. We patch the
single point where all three converge — :meth:`AgentClient.search` — and
record every call. Two assertions then matter:

1. Every surface delivered the same kwargs to the SDK (no surface dropped or
   renamed a filter on the way down).
2. Every surface returned the same user-visible result set up the stack
   (no surface dropped or reformatted a result on the way up).
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from dns_aid.cli.main import app
from dns_aid.mcp.server import search_agents
from dns_aid.sdk import AgentClient, SDKConfig
from dns_aid.sdk.search import SearchResponse

SEARCH_FILTER_CASES: list[dict[str, Any]] = [
    {"q": "payments"},
    {"q": "fraud", "protocol": "mcp"},
    {"capabilities": ["payment-processing"]},
    {"intent": "transaction", "auth_type": "oauth2"},
    {"min_security_score": 70, "verified_only": True},
    {"realm": "prod", "transport": "streamable-http", "limit": 50, "offset": 10},
]


_DIRECTORY_URL = "https://directory.test.example/"


@pytest.fixture(autouse=True)
def _allow_directory_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allow our offline test hostname through the SDK SSRF allowlist."""
    monkeypatch.setenv("DNS_AID_FETCH_ALLOWLIST", "directory.test.example")
    monkeypatch.setenv("DNS_AID_SDK_DIRECTORY_API_URL", _DIRECTORY_URL)


def _patched_search(
    response: SearchResponse,
) -> tuple[Any, list[dict[str, Any]]]:
    """Patch :meth:`AgentClient.search` to return ``response`` and record kwargs."""
    captured: list[dict[str, Any]] = []

    async def fake_search(self: AgentClient, **kwargs: Any) -> SearchResponse:
        captured.append(kwargs)
        return response

    return patch.object(AgentClient, "search", new=fake_search), captured


def _kwargs_to_cli_args(kwargs: dict[str, Any]) -> list[str]:
    args: list[str] = []
    pos_query = kwargs.pop("q", None)
    if pos_query is not None:
        args.append(pos_query)
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


@pytest.mark.parametrize("filter_kwargs", SEARCH_FILTER_CASES)
def test_search_parity_across_surfaces(
    parity_search_payload: dict[str, Any],
    filter_kwargs: dict[str, Any],
) -> None:
    # The fixture is in the directory's flat wire shape; the SDK runs
    # ``_adapt_search_payload`` before validation in production, so we apply the
    # same transformation here to produce the typed response surfaces compare
    # against. This keeps the fixture single-source-of-truth (live API shape).
    # Deepcopy because the adapter mutates the dict in place.
    import copy

    from dns_aid.sdk.client import _adapt_search_payload

    response = SearchResponse.model_validate(
        _adapt_search_payload(copy.deepcopy(parity_search_payload))
    )
    expected_names = [r.agent.name for r in response.results]
    expected_total = response.total

    # ── SDK surface ──
    sdk_patcher, sdk_captured = _patched_search(response)
    with sdk_patcher:

        async def _call_sdk() -> SearchResponse:
            async with AgentClient(config=SDKConfig.from_env()) as client:
                return await client.search(**filter_kwargs)

        sdk_response = asyncio.run(_call_sdk())

    sdk_names = [r.agent.name for r in sdk_response.results]
    assert sdk_names == expected_names
    assert sdk_response.total == expected_total
    assert len(sdk_captured) == 1

    # ── MCP surface ──
    mcp_patcher, mcp_captured = _patched_search(response)
    with mcp_patcher:
        # The MCP tool builds its own AgentClient via SDKConfig.from_env(),
        # so the env vars set by the autouse fixture above are picked up.
        mcp_result = search_agents(**filter_kwargs)

    assert mcp_result["success"] is True, mcp_result
    mcp_names = [r["agent"]["name"] for r in mcp_result["results"]]
    assert mcp_names == expected_names
    assert mcp_result["total"] == expected_total
    assert len(mcp_captured) == 1

    # ── CLI surface ──
    cli_patcher, cli_captured = _patched_search(response)
    with cli_patcher:
        cli_runner = CliRunner()
        cli_args = ["search", "--json"] + _kwargs_to_cli_args(dict(filter_kwargs))
        cli_result = cli_runner.invoke(app, cli_args)

    assert cli_result.exit_code == 0, cli_result.output
    cli_payload = json.loads(cli_result.output)
    cli_names = [r["agent"]["name"] for r in cli_payload["results"]]
    assert cli_names == expected_names
    assert cli_payload["total"] == expected_total
    assert len(cli_captured) == 1

    # ── Headline parity claim: every surface forwarded the SAME kwargs ──
    sdk_call_kwargs = sdk_captured[0]
    mcp_call_kwargs = mcp_captured[0]
    cli_call_kwargs = cli_captured[0]

    # CLI's ``--limit`` defaults to 20 when not set; normalise so we compare
    # what the user actually asked for, not Typer-injected defaults.
    expected_kwargs = _normalize(filter_kwargs)
    assert _normalize(sdk_call_kwargs) == expected_kwargs, (
        f"SDK forwarded different kwargs: {sdk_call_kwargs} vs {filter_kwargs}"
    )
    assert _normalize(mcp_call_kwargs) == expected_kwargs, (
        f"MCP forwarded different kwargs: {mcp_call_kwargs} vs {filter_kwargs}"
    )
    assert _normalize(cli_call_kwargs) == expected_kwargs, (
        f"CLI forwarded different kwargs: {cli_call_kwargs} vs {filter_kwargs}"
    )


def _normalize(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Drop SDK-default values so each surface compares on user-supplied filters only."""
    defaults = {
        "q": None,
        "protocol": None,
        "domain": None,
        "capabilities": None,
        "min_security_score": None,
        "verified_only": False,
        "intent": None,
        "auth_type": None,
        "transport": None,
        "realm": None,
        "limit": 20,
        "offset": 0,
    }
    return {k: v for k, v in kwargs.items() if defaults.get(k, object()) != v}


def test_search_parity_error_class_consistency(
    parity_search_payload: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    A misconfigured directory must produce structurally equivalent failure
    signals on each surface — even though the carriers differ
    (exception / non-zero exit code / structured ``success: False`` envelope).
    """
    from dns_aid.sdk.exceptions import DirectoryConfigError

    monkeypatch.delenv("DNS_AID_SDK_DIRECTORY_API_URL", raising=False)
    monkeypatch.delenv("DNS_AID_SDK_TELEMETRY_API_URL", raising=False)

    # Sanity-check our env scrubbing: any leftover process-level config would
    # mask the failure path the parity assertion depends on.
    assert os.environ.get("DNS_AID_SDK_DIRECTORY_API_URL") is None
    assert os.environ.get("DNS_AID_SDK_TELEMETRY_API_URL") is None

    # SDK raises DirectoryConfigError.
    async def _call_sdk() -> None:
        async with AgentClient(config=SDKConfig()) as client:
            await client.search(q="x")

    with pytest.raises(DirectoryConfigError):
        asyncio.run(_call_sdk())

    # MCP returns a structured envelope.
    mcp_result = search_agents(q="x")
    assert mcp_result["success"] is False
    assert mcp_result["error"] == "directory_not_configured"

    # CLI exits 78 (EX_CONFIG).
    cli_runner = CliRunner()
    cli_result = cli_runner.invoke(app, ["search", "x"])
    assert cli_result.exit_code == 78
