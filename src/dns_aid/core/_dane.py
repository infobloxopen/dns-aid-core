# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Shared DANE TLSA helpers.

Provides a single source of truth for TLSA lookup and certificate-matching
logic used by both:

- ``core.validator`` (advisory + full-cert-match modes inside ``verify()``)
- ``sdk.client`` (pre-invocation preflight against the actual endpoint)

The MAESTRO trust-enforcement hardening PR exposes prefer-then-fallback DANE
on the invocation path: when a TLSA record is present and validates, the
runtime cert is bound to the DNS-published key; when absent, WebPKI takes
over; when present-but-mismatched, the connection is refused.

Per RFC 6698 / RFC 7671, TLSA records MUST be DNSSEC-validated to be
trustworthy. DNSSEC enforcement is layered on top via the ``require_dnssec``
config knob; this module does not assume the caller's DNSSEC posture.
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from dataclasses import dataclass, field
from enum import StrEnum

import dns.asyncresolver
import dns.resolver
import structlog

logger = structlog.get_logger(__name__)


class DanePreflightStatus(StrEnum):
    """Outcome of a DANE preflight against an endpoint."""

    MATCH = "match"  # TLSA present and the endpoint cert matches
    ABSENT = "absent"  # No TLSA record published for this endpoint
    MISMATCH = "mismatch"  # TLSA present but the endpoint cert does NOT match
    ERROR = "error"  # Lookup or TLS handshake failed for a transient reason


@dataclass
class TLSARecord:
    """Lightweight TLSA RDATA carrier — selector / matching type / association data."""

    usage: int
    selector: int
    mtype: int
    cert: bytes


@dataclass
class DanePreflightResult:
    """
    Result of a DANE preflight check.

    ``ok`` is the single boolean the caller should gate on. The other fields
    are diagnostic: which status the preflight produced, any TLSA records
    that were considered, and the raw error string when ``status == ERROR``.
    """

    ok: bool
    status: DanePreflightStatus
    tlsa_records: list[TLSARecord] = field(default_factory=list)
    error: str | None = None


async def fetch_tlsa_records(target: str, port: int) -> list[TLSARecord] | None:
    """
    Look up TLSA records at ``_{port}._tcp.{target}``.

    Returns:
        - A non-empty list of :class:`TLSARecord` when records exist.
        - ``None`` when no TLSA record is configured (NXDOMAIN / NoAnswer).

    Raises:
        Exception: only on transient resolver errors that callers may want
            to retry. Callers that need a fail-soft path should catch and
            treat as ``None`` themselves.
    """
    tlsa_fqdn = f"_{port}._tcp.{target}"
    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(tlsa_fqdn, "TLSA")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None

    records: list[TLSARecord] = []
    for rdata in answers:
        records.append(
            TLSARecord(
                usage=int(rdata.usage),
                selector=int(rdata.selector),
                mtype=int(rdata.mtype),
                cert=bytes(rdata.cert),
            )
        )
    return records or None


async def match_cert_against_tlsa(
    target: str,
    port: int,
    tlsa_records: list[TLSARecord],
) -> bool:
    """
    Connect to ``target:port`` and compare the presented cert against each TLSA.

    Returns ``True`` if any TLSA record matches the endpoint certificate, per
    RFC 6698 § 2.1. Returns ``False`` when every TLSA in the set fails to
    match. Mismatch is the security-relevant outcome — callers must refuse
    the connection.

    The TLS handshake here is intentionally tolerant of WebPKI errors: a
    DANE-EE deployment may publish a self-signed cert whose only attestation
    is the DNSSEC-signed TLSA record. The DANE match is what binds trust,
    not the public CA chain.
    """
    ctx = ssl.create_default_context()
    # DANE-EE (usage 3) commonly uses self-signed certs. Disable WebPKI
    # verification for the handshake; the TLSA match below is the trust
    # anchor we actually care about.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    _, writer = await asyncio.open_connection(target, port, ssl=ctx)
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return False
        der_cert = ssl_object.getpeercert(binary_form=True)
    finally:
        writer.close()
        await writer.wait_closed()

    if not der_cert:
        return False

    return any(_match_one_tlsa(der_cert, rec) for rec in tlsa_records)


def _match_one_tlsa(der_cert: bytes, rec: TLSARecord) -> bool:
    """Apply one TLSA record's selector + matching-type to a DER cert."""
    if rec.selector == 1:
        # SPKI: extract SubjectPublicKeyInfo from the DER certificate
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
        from cryptography.x509 import load_der_x509_certificate

        try:
            x509_cert = load_der_x509_certificate(der_cert)
            cert_bytes = x509_cert.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        except Exception:
            return False
    else:
        # selector 0 — full DER certificate
        cert_bytes = der_cert

    if rec.mtype == 1:
        computed: bytes = hashlib.sha256(cert_bytes).digest()
    elif rec.mtype == 2:
        computed = hashlib.sha512(cert_bytes).digest()
    else:
        # mtype 0 — exact match
        computed = cert_bytes

    return computed == rec.cert


async def dane_preflight(
    target: str,
    port: int,
    *,
    require_dane: bool = False,
) -> DanePreflightResult:
    """
    Run a DANE preflight against ``target:port``.

    Behavior matrix:

    +---------------------------+------------------+------------------+
    | TLSA state                | require_dane=False | require_dane=True |
    +===========================+==================+==================+
    | absent                    | ok=True ABSENT   | ok=False ABSENT  |
    +---------------------------+------------------+------------------+
    | present + match           | ok=True MATCH    | ok=True MATCH    |
    +---------------------------+------------------+------------------+
    | present + mismatch        | ok=False MISMATCH | ok=False MISMATCH |
    +---------------------------+------------------+------------------+
    | transient lookup error    | ok=True ERROR    | ok=False ERROR   |
    +---------------------------+------------------+------------------+

    Mismatch always fails. Absent fails only in strict mode. Transient
    lookup errors are treated as "no TLSA available" in permissive mode
    (matches today's behavior for zones with intermittent DNS issues) and
    as a hard fail in strict mode.
    """
    try:
        records = await fetch_tlsa_records(target, port)
    except Exception as exc:
        logger.debug("dane.preflight.lookup_error", target=target, port=port, error=str(exc))
        return DanePreflightResult(
            ok=not require_dane,
            status=DanePreflightStatus.ERROR,
            error=str(exc),
        )

    if records is None:
        logger.debug("dane.preflight.absent", target=target, port=port)
        return DanePreflightResult(
            ok=not require_dane,
            status=DanePreflightStatus.ABSENT,
        )

    try:
        matched = await match_cert_against_tlsa(target, port, records)
    except Exception as exc:
        logger.debug("dane.preflight.match_error", target=target, port=port, error=str(exc))
        return DanePreflightResult(
            ok=not require_dane,
            status=DanePreflightStatus.ERROR,
            tlsa_records=records,
            error=str(exc),
        )

    if matched:
        logger.debug("dane.preflight.match", target=target, port=port)
        return DanePreflightResult(
            ok=True,
            status=DanePreflightStatus.MATCH,
            tlsa_records=records,
        )

    logger.warning("dane.preflight.mismatch", target=target, port=port)
    return DanePreflightResult(
        ok=False,
        status=DanePreflightStatus.MISMATCH,
        tlsa_records=records,
    )
