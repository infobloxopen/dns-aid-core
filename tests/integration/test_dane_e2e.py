# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""End-to-end DANE TLSA tests against a real in-process TLS server.

Generates a self-signed certificate at runtime, spins up an asyncio TLS
server with that cert on a random localhost port, and exercises the full
``core._dane`` preflight path: TLSA lookup → TLS handshake → cert
extraction → RFC 6698 §2.1 selector/matching-type comparison.

Only ``fetch_tlsa_records`` is mocked (so we don't need a live DNS
server). The actual TLS handshake, cert presentation, and
``match_cert_against_tlsa`` body run against the live server, which is
what the unit tests in ``tests/unit/test_dane_preflight.py`` cannot
verify on their own.

Runs hermetically. No Docker / BIND needed.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import socket
import ssl
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from dns_aid.core._dane import (
    DanePreflightStatus,
    TLSARecord,
    dane_preflight,
    match_cert_against_tlsa,
)

# ---------------------------------------------------------------------------
# Self-signed cert helpers
# ---------------------------------------------------------------------------


def _generate_self_signed_cert() -> tuple[bytes, bytes, bytes]:
    """Generate (cert_pem, key_pem, der_cert_bytes) for a fresh RSA-2048 cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dane-e2e-test.local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    der_cert = cert.public_bytes(serialization.Encoding.DER)
    return cert_pem, key_pem, der_cert


def _spki_sha256(der_cert: bytes) -> bytes:
    """SHA-256 of SubjectPublicKeyInfo — the bytes a TLSA 3 1 1 record carries."""
    cert_obj = x509.load_der_x509_certificate(der_cert)
    spki = cert_obj.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).digest()


# ---------------------------------------------------------------------------
# Server fixture
# ---------------------------------------------------------------------------


@pytest.fixture
async def tls_server(tmp_path: Path) -> AsyncIterator[tuple[str, int, bytes]]:
    """Start a localhost TLS server with a fresh self-signed cert.

    Yields ``(host, port, der_cert_bytes)``. The DER cert bytes are exposed
    so tests can build TLSA records that match (or deliberately don't).
    """
    cert_pem, key_pem, der_cert = _generate_self_signed_cert()
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    # Reserve a free port without binding it long-term.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # No-op: the cert is already presented during the handshake and the
        # client extracts it from get_extra_info("ssl_object") before any
        # application data flows. Closing immediately is fine.
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    server = await asyncio.start_server(_handle, "127.0.0.1", port, ssl=ssl_ctx)
    try:
        yield "127.0.0.1", port, der_cert
    finally:
        server.close()
        await server.wait_closed()


# ---------------------------------------------------------------------------
# Full preflight matrix against a real TLS server
# ---------------------------------------------------------------------------


async def test_preflight_match_against_real_tls_server(
    tls_server: tuple[str, int, bytes],
) -> None:
    """Real TLS handshake + TLSA(3, 1, 1) with the correct SPKI hash → MATCH."""
    host, port, der_cert = tls_server
    correct_hash = _spki_sha256(der_cert)
    tlsa = [TLSARecord(usage=3, selector=1, mtype=1, cert=correct_hash)]

    with patch(
        "dns_aid.core._dane.fetch_tlsa_records",
        new=AsyncMock(return_value=tlsa),
    ):
        result = await dane_preflight(host, port, require_dane=True)

    assert result.ok is True
    assert result.status == DanePreflightStatus.MATCH
    assert result.tlsa_records == tlsa


async def test_preflight_mismatch_against_real_tls_server(
    tls_server: tuple[str, int, bytes],
) -> None:
    """Real TLS handshake + TLSA(3, 1, 1) with the WRONG hash → MISMATCH, refused."""
    host, port, _der_cert = tls_server
    wrong_hash = hashlib.sha256(b"definitely-not-the-real-key").digest()
    tlsa = [TLSARecord(usage=3, selector=1, mtype=1, cert=wrong_hash)]

    with patch(
        "dns_aid.core._dane.fetch_tlsa_records",
        new=AsyncMock(return_value=tlsa),
    ):
        result = await dane_preflight(host, port, require_dane=False)

    # Mismatch always refuses regardless of strictness — RFC 7671 promise.
    assert result.ok is False
    assert result.status == DanePreflightStatus.MISMATCH


async def test_preflight_strict_mismatch_against_real_tls_server(
    tls_server: tuple[str, int, bytes],
) -> None:
    """Confirm strict mode also refuses on mismatch (same outcome, different posture)."""
    host, port, _der_cert = tls_server
    wrong_hash = hashlib.sha256(b"other-key-bytes").digest()
    tlsa = [TLSARecord(usage=3, selector=1, mtype=1, cert=wrong_hash)]

    with patch(
        "dns_aid.core._dane.fetch_tlsa_records",
        new=AsyncMock(return_value=tlsa),
    ):
        result = await dane_preflight(host, port, require_dane=True)

    assert result.ok is False
    assert result.status == DanePreflightStatus.MISMATCH


async def test_preflight_absent_falls_back_to_webpki_permissive(
    tls_server: tuple[str, int, bytes],
) -> None:
    """No TLSA record + permissive → WebPKI fallback path (preflight ok, status ABSENT).

    The actual TLS handshake never runs because there's nothing to compare
    against; the SDK's downstream code is what would perform the WebPKI
    handshake. Here we just verify the preflight produces the right verdict.
    """
    host, port, _der_cert = tls_server
    with patch(
        "dns_aid.core._dane.fetch_tlsa_records",
        new=AsyncMock(return_value=None),
    ):
        result = await dane_preflight(host, port, require_dane=False)

    assert result.ok is True
    assert result.status == DanePreflightStatus.ABSENT


async def test_preflight_absent_strict_refuses(
    tls_server: tuple[str, int, bytes],
) -> None:
    """No TLSA + strict → refuse. require_dane is the publisher's commitment gate."""
    host, port, _der_cert = tls_server
    with patch(
        "dns_aid.core._dane.fetch_tlsa_records",
        new=AsyncMock(return_value=None),
    ):
        result = await dane_preflight(host, port, require_dane=True)

    assert result.ok is False
    assert result.status == DanePreflightStatus.ABSENT


# ---------------------------------------------------------------------------
# Selector / matching-type coverage against the real cert
# ---------------------------------------------------------------------------


async def test_match_selector_0_mtype_0_exact_full_cert(
    tls_server: tuple[str, int, bytes],
) -> None:
    """Selector 0 (full cert) + mtype 0 (exact) — exercise the non-hash path."""
    host, port, der_cert = tls_server
    tlsa = [TLSARecord(usage=3, selector=0, mtype=0, cert=der_cert)]
    matched = await match_cert_against_tlsa(host, port, tlsa)
    assert matched is True


async def test_match_selector_0_mtype_1_sha256_full_cert(
    tls_server: tuple[str, int, bytes],
) -> None:
    """Selector 0 (full cert) + mtype 1 (SHA-256 over full cert)."""
    host, port, der_cert = tls_server
    tlsa = [TLSARecord(usage=3, selector=0, mtype=1, cert=hashlib.sha256(der_cert).digest())]
    matched = await match_cert_against_tlsa(host, port, tlsa)
    assert matched is True


async def test_match_selector_0_mtype_2_sha512_full_cert(
    tls_server: tuple[str, int, bytes],
) -> None:
    """Selector 0 + mtype 2 (SHA-512 over full cert)."""
    host, port, der_cert = tls_server
    tlsa = [TLSARecord(usage=3, selector=0, mtype=2, cert=hashlib.sha512(der_cert).digest())]
    matched = await match_cert_against_tlsa(host, port, tlsa)
    assert matched is True


async def test_match_multiple_tlsa_first_wrong_second_correct(
    tls_server: tuple[str, int, bytes],
) -> None:
    """RFC 6698 §2.1: a TLSA RRset can carry multiple records; any match suffices."""
    host, port, der_cert = tls_server
    wrong = hashlib.sha256(b"wrong").digest()
    correct = _spki_sha256(der_cert)
    tlsa = [
        TLSARecord(usage=3, selector=1, mtype=1, cert=wrong),
        TLSARecord(usage=3, selector=1, mtype=1, cert=correct),
    ]
    matched = await match_cert_against_tlsa(host, port, tlsa)
    assert matched is True
