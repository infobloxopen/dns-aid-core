# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for dns_aid.core.dcv — stateless DCV challenge/verify."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.core.dcv import (
    DCVChallenge,
    DCVVerifyResult,
    _build_txt_value,
    _generate_token,
    _parse_txt_value,
    issue,
    place,
    revoke,
    verify,
)


# ---------------------------------------------------------------------------
# _generate_token
# ---------------------------------------------------------------------------


def test_generate_token_format():
    token = _generate_token()
    # base32 lowercase, no padding — only a-z2-7
    assert re.fullmatch(r"[a-z2-7]+", token), f"Unexpected token chars: {token}"


def test_generate_token_length():
    # 20 bytes → 32 base32 chars (no padding)
    token = _generate_token()
    assert len(token) == 32


def test_generate_token_unique():
    tokens = {_generate_token() for _ in range(10)}
    assert len(tokens) == 10


# ---------------------------------------------------------------------------
# _build_txt_value
# ---------------------------------------------------------------------------


def test_build_txt_value_basic():
    expiry = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    txt = _build_txt_value("abc123", expiry, None)
    assert txt == "token=abc123 expiry=2026-01-02T03:04:05Z"


def test_build_txt_value_with_bnd_req():
    expiry = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    txt = _build_txt_value("abc123", expiry, "svc:assistant@orga.test")
    assert txt == "token=abc123 bnd-req=svc:assistant@orga.test expiry=2026-01-02T03:04:05Z"


# ---------------------------------------------------------------------------
# _parse_txt_value
# ---------------------------------------------------------------------------


def test_parse_txt_value_full():
    txt = "token=abc123 bnd-req=svc:assistant@orga.test expiry=2026-01-02T03:04:05Z"
    parsed = _parse_txt_value(txt)
    assert parsed["token"] == "abc123"
    assert parsed["bnd-req"] == "svc:assistant@orga.test"
    assert parsed["expiry"] == "2026-01-02T03:04:05Z"


def test_parse_txt_value_minimal():
    parsed = _parse_txt_value("token=xyz expiry=2026-01-01T00:00:00Z")
    assert parsed["token"] == "xyz"
    assert "bnd-req" not in parsed


def test_parse_txt_value_bare_token():
    # Bare value with no key= prefix is the token per spec
    parsed = _parse_txt_value("baretoken expiry=2026-01-01T00:00:00Z")
    assert parsed["token"] == "baretoken"


def test_parse_txt_value_case_insensitive_keys():
    parsed = _parse_txt_value("TOKEN=abc EXPIRY=2026-01-01T00:00:00Z")
    assert parsed["token"] == "abc"
    assert parsed["expiry"] == "2026-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# issue()
# ---------------------------------------------------------------------------


def test_issue_returns_challenge():
    ch = issue("example.com")
    assert isinstance(ch, DCVChallenge)
    assert ch.domain == "example.com"
    assert ch.fqdn == "_agents-challenge.example.com"
    assert ch.bnd_req is None


def test_issue_token_in_txt_value():
    ch = issue("example.com")
    assert f"token={ch.token}" in ch.txt_value


def test_issue_expiry_in_txt_value():
    ch = issue("example.com")
    assert "expiry=" in ch.txt_value


def test_issue_bnd_req_when_both_supplied():
    ch = issue("example.com", agent_name="assistant", issuer_domain="orga.test")
    assert ch.bnd_req == "svc:assistant@orga.test"
    assert "bnd-req=svc:assistant@orga.test" in ch.txt_value


def test_issue_no_bnd_req_when_partial():
    # bnd-req only emitted when both agent_name and issuer_domain are present
    ch1 = issue("example.com", agent_name="assistant")
    assert ch1.bnd_req is None
    ch2 = issue("example.com", issuer_domain="orga.test")
    assert ch2.bnd_req is None


def test_issue_ttl_affects_expiry():
    ch_short = issue("example.com", ttl_seconds=60)
    ch_long = issue("example.com", ttl_seconds=7200)
    assert ch_long.expiry > ch_short.expiry


def test_issue_is_stateless():
    # Two calls produce different tokens — nothing shared
    ch1 = issue("example.com")
    ch2 = issue("example.com")
    assert ch1.token != ch2.token


# ---------------------------------------------------------------------------
# place()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_place_calls_backend():
    mock_backend = AsyncMock()
    mock_backend.create_txt_record = AsyncMock()

    fqdn = await place("orga.test", "abc123", backend=mock_backend)

    assert fqdn == "_agents-challenge.orga.test"
    mock_backend.create_txt_record.assert_awaited_once()
    call_kwargs = mock_backend.create_txt_record.call_args.kwargs
    assert call_kwargs["zone"] == "orga.test"
    assert call_kwargs["name"] == "_agents-challenge"
    assert len(call_kwargs["values"]) == 1
    assert "token=abc123" in call_kwargs["values"][0]


@pytest.mark.asyncio
async def test_place_includes_bnd_req():
    mock_backend = AsyncMock()
    mock_backend.create_txt_record = AsyncMock()

    await place("orga.test", "abc123", bnd_req="svc:bot@orga.test", backend=mock_backend)

    call_kwargs = mock_backend.create_txt_record.call_args.kwargs
    assert "bnd-req=svc:bot@orga.test" in call_kwargs["values"][0]


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------


def _make_rdata(txt: str):
    """Minimal stub for dns.rdata with a strings attribute."""
    rdata = MagicMock()
    rdata.strings = [txt.encode()]
    return rdata


@pytest.mark.asyncio
async def test_verify_success():
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=timezone.utc)
    txt = _build_txt_value(token, expiry, None)

    with patch("dns_aid.core.dcv.dns.resolver.Resolver") as MockResolver:
        resolver_instance = MockResolver.return_value
        resolver_instance.resolve.return_value = [_make_rdata(txt)]

        result = await verify("example.com", token)

    assert result.verified is True
    assert result.domain == "example.com"
    assert result.token == token


@pytest.mark.asyncio
async def test_verify_wrong_token():
    expiry = datetime(2099, 1, 1, tzinfo=timezone.utc)
    txt = _build_txt_value("righttoken", expiry, None)

    with patch("dns_aid.core.dcv.dns.resolver.Resolver") as MockResolver:
        resolver_instance = MockResolver.return_value
        resolver_instance.resolve.return_value = [_make_rdata(txt)]

        result = await verify("example.com", "wrongtoken")

    assert result.verified is False
    assert result.error == "Token not found in any challenge record"


@pytest.mark.asyncio
async def test_verify_expired():
    token = _generate_token()
    expiry = datetime(2000, 1, 1, tzinfo=timezone.utc)  # in the past
    txt = _build_txt_value(token, expiry, None)

    with patch("dns_aid.core.dcv.dns.resolver.Resolver") as MockResolver:
        resolver_instance = MockResolver.return_value
        resolver_instance.resolve.return_value = [_make_rdata(txt)]

        result = await verify("example.com", token)

    assert result.verified is False
    assert result.expired is True


@pytest.mark.asyncio
async def test_verify_nxdomain():
    import dns.resolver

    with patch("dns_aid.core.dcv.dns.resolver.Resolver") as MockResolver:
        resolver_instance = MockResolver.return_value
        resolver_instance.resolve.side_effect = dns.resolver.NXDOMAIN()

        result = await verify("example.com", "sometoken")

    assert result.verified is False
    assert "NXDOMAIN" in result.error


@pytest.mark.asyncio
async def test_verify_custom_nameserver():
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=timezone.utc)
    txt = _build_txt_value(token, expiry, None)

    with patch("dns_aid.core.dcv.dns.resolver.Resolver") as MockResolver:
        resolver_instance = MockResolver.return_value
        resolver_instance.resolve.return_value = [_make_rdata(txt)]

        await verify("example.com", token, nameserver="1.2.3.4", port=5353)

        assert resolver_instance.nameservers == ["1.2.3.4"]
        assert resolver_instance.port == 5353


# ---------------------------------------------------------------------------
# revoke()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_calls_backend():
    mock_backend = AsyncMock()
    mock_backend.delete_record = AsyncMock(return_value=True)

    result = await revoke("orga.test", backend=mock_backend)

    assert result is True
    mock_backend.delete_record.assert_awaited_once_with(
        zone="orga.test",
        name="_agents-challenge",
        record_type="TXT",
    )


@pytest.mark.asyncio
async def test_revoke_returns_false_when_not_found():
    mock_backend = AsyncMock()
    mock_backend.delete_record = AsyncMock(return_value=False)

    result = await revoke("orga.test", backend=mock_backend)

    assert result is False
