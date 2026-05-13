# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for dns_aid.core._dane — DANE TLSA preflight helper.

Covers the prefer-then-fallback matrix used by the SDK invocation path:

    +------------------------+------------------+------------------+
    | TLSA state             | require_dane=F   | require_dane=T   |
    +========================+==================+==================+
    | absent                 | ok=True ABSENT   | ok=False ABSENT  |
    | present + match        | ok=True MATCH    | ok=True MATCH    |
    | present + mismatch     | ok=False MISMATCH| ok=False MISMATCH|
    | transient lookup error | ok=True ERROR    | ok=False ERROR   |
    +------------------------+------------------+------------------+
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.core._dane import (
    DanePreflightResult,
    DanePreflightStatus,
    TLSARecord,
    dane_preflight,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_tlsa() -> list[TLSARecord]:
    """One TLSA 3 1 1 record — DANE-EE / SPKI / SHA-256 (most common shape)."""
    return [
        TLSARecord(
            usage=3,
            selector=1,
            mtype=1,
            cert=b"\x00" * 32,  # opaque 32-byte fingerprint
        )
    ]


# ---------------------------------------------------------------------------
# Behavior matrix: absent
# ---------------------------------------------------------------------------


async def test_absent_permissive_returns_ok() -> None:
    """TLSA absent + require_dane=False → preflight ok (WebPKI fallback path)."""
    with patch("dns_aid.core._dane.fetch_tlsa_records", new=AsyncMock(return_value=None)):
        result = await dane_preflight("agent.example.com", 443, require_dane=False)
    assert isinstance(result, DanePreflightResult)
    assert result.ok is True
    assert result.status == DanePreflightStatus.ABSENT
    assert result.tlsa_records == []


async def test_absent_strict_refuses() -> None:
    """TLSA absent + require_dane=True → preflight refuses."""
    with patch("dns_aid.core._dane.fetch_tlsa_records", new=AsyncMock(return_value=None)):
        result = await dane_preflight("agent.example.com", 443, require_dane=True)
    assert result.ok is False
    assert result.status == DanePreflightStatus.ABSENT


# ---------------------------------------------------------------------------
# Behavior matrix: present + match
# ---------------------------------------------------------------------------


async def test_present_match_permissive(sample_tlsa: list[TLSARecord]) -> None:
    with (
        patch(
            "dns_aid.core._dane.fetch_tlsa_records",
            new=AsyncMock(return_value=sample_tlsa),
        ),
        patch(
            "dns_aid.core._dane.match_cert_against_tlsa",
            new=AsyncMock(return_value=True),
        ),
    ):
        result = await dane_preflight("agent.example.com", 443, require_dane=False)
    assert result.ok is True
    assert result.status == DanePreflightStatus.MATCH
    assert result.tlsa_records == sample_tlsa


async def test_present_match_strict(sample_tlsa: list[TLSARecord]) -> None:
    """Strict + match → ok (the happy path for hardened deployments)."""
    with (
        patch(
            "dns_aid.core._dane.fetch_tlsa_records",
            new=AsyncMock(return_value=sample_tlsa),
        ),
        patch(
            "dns_aid.core._dane.match_cert_against_tlsa",
            new=AsyncMock(return_value=True),
        ),
    ):
        result = await dane_preflight("agent.example.com", 443, require_dane=True)
    assert result.ok is True
    assert result.status == DanePreflightStatus.MATCH


# ---------------------------------------------------------------------------
# Behavior matrix: present + mismatch (security-critical: always fails)
# ---------------------------------------------------------------------------


async def test_present_mismatch_always_refuses_permissive(
    sample_tlsa: list[TLSARecord],
) -> None:
    """Mismatch is an attack signal — must fail even in permissive mode."""
    with (
        patch(
            "dns_aid.core._dane.fetch_tlsa_records",
            new=AsyncMock(return_value=sample_tlsa),
        ),
        patch(
            "dns_aid.core._dane.match_cert_against_tlsa",
            new=AsyncMock(return_value=False),
        ),
    ):
        result = await dane_preflight("agent.example.com", 443, require_dane=False)
    assert result.ok is False
    assert result.status == DanePreflightStatus.MISMATCH


async def test_present_mismatch_always_refuses_strict(
    sample_tlsa: list[TLSARecord],
) -> None:
    with (
        patch(
            "dns_aid.core._dane.fetch_tlsa_records",
            new=AsyncMock(return_value=sample_tlsa),
        ),
        patch(
            "dns_aid.core._dane.match_cert_against_tlsa",
            new=AsyncMock(return_value=False),
        ),
    ):
        result = await dane_preflight("agent.example.com", 443, require_dane=True)
    assert result.ok is False
    assert result.status == DanePreflightStatus.MISMATCH


# ---------------------------------------------------------------------------
# Behavior matrix: transient errors (fail-soft permissive, fail-hard strict)
# ---------------------------------------------------------------------------


async def test_lookup_error_permissive_returns_ok() -> None:
    """Transient DNS resolver failure + permissive → don't punish the caller."""
    with patch(
        "dns_aid.core._dane.fetch_tlsa_records",
        new=AsyncMock(side_effect=RuntimeError("simulated transient")),
    ):
        result = await dane_preflight("agent.example.com", 443, require_dane=False)
    assert result.ok is True
    assert result.status == DanePreflightStatus.ERROR
    assert result.error is not None
    assert "simulated transient" in result.error


async def test_lookup_error_strict_refuses() -> None:
    """Strict mode treats a TLSA lookup failure as a hard fail."""
    with patch(
        "dns_aid.core._dane.fetch_tlsa_records",
        new=AsyncMock(side_effect=RuntimeError("simulated transient")),
    ):
        result = await dane_preflight("agent.example.com", 443, require_dane=True)
    assert result.ok is False
    assert result.status == DanePreflightStatus.ERROR


async def test_match_error_permissive_returns_ok(sample_tlsa: list[TLSARecord]) -> None:
    """TLSA present but the TLS handshake itself fails: fail-soft in permissive."""
    with (
        patch(
            "dns_aid.core._dane.fetch_tlsa_records",
            new=AsyncMock(return_value=sample_tlsa),
        ),
        patch(
            "dns_aid.core._dane.match_cert_against_tlsa",
            new=AsyncMock(side_effect=ConnectionError("simulated tls failure")),
        ),
    ):
        result = await dane_preflight("agent.example.com", 443, require_dane=False)
    assert result.ok is True
    assert result.status == DanePreflightStatus.ERROR
    assert result.tlsa_records == sample_tlsa
    assert result.error is not None


async def test_match_error_strict_refuses(sample_tlsa: list[TLSARecord]) -> None:
    with (
        patch(
            "dns_aid.core._dane.fetch_tlsa_records",
            new=AsyncMock(return_value=sample_tlsa),
        ),
        patch(
            "dns_aid.core._dane.match_cert_against_tlsa",
            new=AsyncMock(side_effect=ConnectionError("simulated tls failure")),
        ),
    ):
        result = await dane_preflight("agent.example.com", 443, require_dane=True)
    assert result.ok is False
    assert result.status == DanePreflightStatus.ERROR


# ---------------------------------------------------------------------------
# TLSA matching primitive
# ---------------------------------------------------------------------------


def test_match_one_tlsa_full_cert_sha256() -> None:
    """selector=0 mtype=1 — full DER cert, SHA-256."""
    import hashlib

    from dns_aid.core._dane import _match_one_tlsa

    der_cert = b"fake-der-cert-bytes"
    correct_hash = hashlib.sha256(der_cert).digest()
    wrong_hash = hashlib.sha256(b"different").digest()

    matching = TLSARecord(usage=3, selector=0, mtype=1, cert=correct_hash)
    non_matching = TLSARecord(usage=3, selector=0, mtype=1, cert=wrong_hash)

    assert _match_one_tlsa(der_cert, matching) is True
    assert _match_one_tlsa(der_cert, non_matching) is False


def test_match_one_tlsa_exact_match_mtype0() -> None:
    """selector=0 mtype=0 — exact DER cert comparison."""
    from dns_aid.core._dane import _match_one_tlsa

    der_cert = b"exact-der-bytes"
    matching = TLSARecord(usage=3, selector=0, mtype=0, cert=der_cert)
    non_matching = TLSARecord(usage=3, selector=0, mtype=0, cert=b"other")

    assert _match_one_tlsa(der_cert, matching) is True
    assert _match_one_tlsa(der_cert, non_matching) is False
