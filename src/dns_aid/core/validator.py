"""
DNS-AID Validator: Verify agent DNS records and security.

Handles DNSSEC validation, DANE/TLSA verification, and endpoint health checks.
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
import time

import dns.asyncresolver
import dns.flags
import dns.rdatatype
import dns.resolver
import httpx
import structlog

from dns_aid.core.models import VerifyResult

logger = structlog.get_logger(__name__)


async def verify(fqdn: str, *, verify_dane_cert: bool = False) -> VerifyResult:
    """
    Verify DNS-AID records for an agent.

    Checks:
    - DNS record exists
    - SVCB record is valid
    - DNSSEC chain is validated
    - DANE/TLSA certificate binding (if configured)
    - Endpoint is reachable

    Args:
        fqdn: Fully qualified domain name of agent record
              (e.g., "_chat._a2a._agents.example.com")
        verify_dane_cert: If True, perform full DANE certificate matching
                         (connect to endpoint and compare TLS cert against
                         TLSA record). Default False (existence check only).

    Returns:
        VerifyResult with security validation results
    """
    logger.info("Verifying agent DNS records", fqdn=fqdn)

    result = VerifyResult(fqdn=fqdn)

    # 1. Check SVCB record exists and is valid
    svcb_data = await _check_svcb_record(fqdn)
    if svcb_data:
        result.record_exists = True
        result.svcb_valid = svcb_data.get("valid", False)
        target = svcb_data.get("target")
        port = svcb_data.get("port", 443)
    else:
        target = None
        port = None

    # 2. Check DNSSEC validation
    result.dnssec_valid = await _check_dnssec(fqdn)

    # 3. Check DANE/TLSA (if target is available)
    if target:
        result.dane_valid = await _check_dane(target, port, verify_cert=verify_dane_cert)

    # 4. Check endpoint reachability
    if target and port:
        endpoint_result = await _check_endpoint(target, port)
        result.endpoint_reachable = endpoint_result.get("reachable", False)
        result.endpoint_latency_ms = endpoint_result.get("latency_ms")

    logger.info(
        "Verification complete",
        fqdn=fqdn,
        score=result.security_score,
        rating=result.security_rating,
    )

    return result


async def _check_svcb_record(fqdn: str) -> dict | None:
    """
    Check if SVCB record exists and is valid.

    Returns dict with target, port, and validity info, or None if not found.
    """
    try:
        resolver = dns.asyncresolver.Resolver()

        # Query SVCB record
        try:
            answers = await resolver.resolve(fqdn, "SVCB")
        except dns.resolver.NoAnswer:
            # Try HTTPS record as fallback
            try:
                answers = await resolver.resolve(fqdn, "HTTPS")
            except dns.resolver.NoAnswer:
                logger.debug("No SVCB/HTTPS record found", fqdn=fqdn)
                return None

        for rdata in answers:
            target = str(rdata.target).rstrip(".")

            # Extract port from params
            port = 443
            if hasattr(rdata, "params") and rdata.params:
                # Port param key is 3 in SVCB
                port_param = rdata.params.get(3)
                if port_param and hasattr(port_param, "port"):
                    port = port_param.port

            # SVCB is valid if it has a target
            is_valid = bool(target and target != ".")

            logger.debug(
                "SVCB record found",
                fqdn=fqdn,
                target=target,
                port=port,
                valid=is_valid,
            )

            return {
                "target": target,
                "port": port,
                "valid": is_valid,
                "priority": rdata.priority,
            }

    except dns.resolver.NXDOMAIN:
        logger.debug("FQDN does not exist", fqdn=fqdn)
    except Exception as e:
        logger.debug("SVCB query failed", fqdn=fqdn, error=str(e))

    return None


async def _check_dnssec(fqdn: str) -> bool:
    """
    Check if DNSSEC is validated for the FQDN.

    Limitation: This only checks the AD (Authenticated Data) flag in the DNS
    response from the configured recursive resolver. It does NOT perform
    independent DNSSEC chain validation (DNSKEY → DS → RRSIG). The AD flag
    is only trustworthy if the path to the resolver is secured (e.g., via
    localhost or DoT/DoH). A resolver on an untrusted network could spoof
    the AD flag.

    Returns True if DNSSEC AD (Authenticated Data) flag is set.
    """
    try:
        resolver = dns.asyncresolver.Resolver()

        # Enable DNSSEC validation
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO)

        # Query with DNSSEC
        try:
            answer = await resolver.resolve(fqdn, "SVCB")

            # Check AD (Authenticated Data) flag in response
            if hasattr(answer.response, "flags"):
                ad_flag = answer.response.flags & dns.flags.AD
                if ad_flag:
                    logger.debug("DNSSEC validated", fqdn=fqdn)
                    return True

        except dns.resolver.NoAnswer:
            # Try TXT as fallback for DNSSEC check
            try:
                answer = await resolver.resolve(fqdn, "TXT")
                if hasattr(answer.response, "flags"):
                    ad_flag = answer.response.flags & dns.flags.AD
                    if ad_flag:
                        logger.debug("DNSSEC validated via TXT", fqdn=fqdn)
                        return True
            except Exception:
                pass

    except Exception as e:
        logger.debug("DNSSEC check failed", fqdn=fqdn, error=str(e))

    # Note: Many domains don't have DNSSEC enabled
    # This is not necessarily an error
    logger.debug("DNSSEC not validated", fqdn=fqdn)
    return False


async def _check_dane(target: str, port: int, *, verify_cert: bool = False) -> bool | None:
    """
    Check DANE/TLSA record for the endpoint.

    When ``verify_cert`` is False (default), this only checks whether a TLSA
    record exists in DNS.  When True, it additionally connects to the endpoint
    via TLS, retrieves the certificate, and compares its digest against the
    TLSA association data.

    Args:
        target: Hostname of the endpoint.
        port: Port number.
        verify_cert: If True, perform full certificate matching against TLSA.

    Returns:
        True if TLSA record exists (and optionally cert matches)
        False if TLSA record exists but cert does NOT match (verify_cert=True)
        None if no TLSA record configured
    """
    # TLSA record format: _port._tcp.hostname
    tlsa_fqdn = f"_{port}._tcp.{target}"

    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(tlsa_fqdn, "TLSA")

        for rdata in answers:
            logger.debug(
                "TLSA record found",
                fqdn=tlsa_fqdn,
                usage=rdata.usage,
                selector=rdata.selector,
                mtype=rdata.mtype,
            )

            if not verify_cert:
                # Advisory mode: TLSA exists → True
                return True

            # Full DANE cert matching
            try:
                cert_match = await _match_dane_cert(
                    target, port, rdata.selector, rdata.mtype, rdata.cert
                )
                if cert_match:
                    logger.info("DANE certificate match verified", fqdn=tlsa_fqdn)
                    return True
                else:
                    logger.warning("DANE certificate mismatch", fqdn=tlsa_fqdn)
                    return False
            except Exception as e:
                logger.warning(
                    "DANE certificate matching failed",
                    fqdn=tlsa_fqdn,
                    error=str(e),
                )
                return False

    except dns.resolver.NXDOMAIN:
        logger.debug("No TLSA record (DANE not configured)", fqdn=tlsa_fqdn)
    except dns.resolver.NoAnswer:
        logger.debug("No TLSA record", fqdn=tlsa_fqdn)
    except Exception as e:
        logger.debug("TLSA query failed", fqdn=tlsa_fqdn, error=str(e))

    return None  # Not configured


async def _match_dane_cert(
    target: str,
    port: int,
    selector: int,
    mtype: int,
    tlsa_data: bytes,
) -> bool:
    """
    Connect to ``target:port`` via TLS and compare cert against TLSA data.

    Args:
        target: Hostname to connect to.
        port: Port number.
        selector: TLSA selector — 0 = full cert, 1 = SubjectPublicKeyInfo.
        mtype: TLSA matching type — 0 = exact, 1 = SHA-256, 2 = SHA-512.
        tlsa_data: Certificate association data from the TLSA record.

    Returns:
        True if the presented certificate matches the TLSA record.
    """
    ctx = ssl.create_default_context()
    _, writer = await asyncio.open_connection(target, port, ssl=ctx)

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der_cert = ssl_object.getpeercert(binary_form=True)

        if selector == 1:
            # SPKI: extract SubjectPublicKeyInfo from DER certificate
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
            )
            from cryptography.x509 import load_der_x509_certificate

            x509_cert = load_der_x509_certificate(der_cert)
            cert_bytes = x509_cert.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        else:
            # selector 0: full certificate DER bytes
            cert_bytes = der_cert

        if mtype == 1:
            computed = hashlib.sha256(cert_bytes).digest()
        elif mtype == 2:
            computed = hashlib.sha512(cert_bytes).digest()
        else:
            # mtype 0: exact match
            computed = cert_bytes

        return computed == tlsa_data
    finally:
        writer.close()
        await writer.wait_closed()


async def _check_endpoint(target: str, port: int) -> dict:
    """
    Check if endpoint is reachable.

    Returns dict with reachable status and latency.
    """
    endpoint = f"https://{target}:{port}"

    try:
        start_time = time.perf_counter()

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=True,
        ) as client:
            # Try health endpoint first, then root
            for path in ["/health", "/.well-known/agent.json", "/"]:
                try:
                    response = await client.get(f"{endpoint}{path}")
                    latency_ms = (time.perf_counter() - start_time) * 1000

                    if response.status_code < 500:
                        logger.debug(
                            "Endpoint reachable",
                            endpoint=endpoint,
                            path=path,
                            status=response.status_code,
                            latency_ms=f"{latency_ms:.2f}",
                        )
                        return {
                            "reachable": True,
                            "latency_ms": latency_ms,
                            "status_code": response.status_code,
                        }
                except httpx.HTTPError:
                    continue

    except httpx.ConnectError as e:
        logger.debug("Endpoint connection failed", endpoint=endpoint, error=str(e))
    except httpx.TimeoutException:
        logger.debug("Endpoint timeout", endpoint=endpoint)
    except Exception as e:
        logger.debug("Endpoint check failed", endpoint=endpoint, error=str(e))

    return {"reachable": False}
