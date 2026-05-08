# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-based Domain Control Validation (DCV) for agent identity assertion.

Implements the challenge-response pattern from:
- IETF draft-mozleywilliams-dnsop-dnsaid-01  (bnd-req binding extension)
- draft-ietf-dnsop-domain-verification-techniques-12  (TXT record wire format)

Two primary use cases:
  1. Anonymous / NAT agent asserting org affiliation — Org A issues a challenge;
     the claiming agent places it in the org's DNS zone using its own credentials.
  2. Registry / directory anti-impersonation — a directory requires proof of zone
     control before listing an agent as org-verified.

Wire format (DCV-techniques §6.1.2 ABNF, space-separated key=value):
    token=<base32>  [bnd-req=svc:<agent>@<issuer>]  expiry=<RFC3339>

Challenge owner name: _agents-challenge.{domain}
"""

from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime, timedelta

import dns.exception
import dns.resolver
import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

CHALLENGE_LABEL = "_agents-challenge"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class DCVChallenge(BaseModel):
    """Issued DCV challenge — delivered to the claimant out-of-band."""

    token: str = Field(description="Base32-encoded nonce to place in DNS")
    domain: str = Field(description="Domain being challenged")
    fqdn: str = Field(description="Full owner name of the TXT record")
    txt_value: str = Field(description="Verbatim TXT RDATA to place in the zone")
    expiry: datetime = Field(description="UTC expiry time for this challenge")
    bnd_req: str | None = Field(
        default=None,
        description="Binding request scope — svc:<agent>@<issuer> — optional",
    )


class DCVVerifyResult(BaseModel):
    """Result of verifying a DCV challenge."""

    verified: bool
    domain: str
    token: str
    fqdn: str
    expired: bool = False
    error: str | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _generate_token() -> str:
    """20 bytes of entropy, lowercase base32 (no padding) — DNS-label safe."""
    return base64.b32encode(secrets.token_bytes(20)).decode().lower().rstrip("=")


def _build_txt_value(token: str, expiry: datetime, bnd_req: str | None) -> str:
    """Produce a DCV-techniques-compliant space-separated key=value string."""
    expiry_str = expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [f"token={token}"]
    if bnd_req:
        parts.append(f"bnd-req={bnd_req}")
    parts.append(f"expiry={expiry_str}")
    return " ".join(parts)


def _parse_txt_value(txt: str) -> dict[str, str]:
    """Parse space-separated key=value pairs (DCV-techniques §6.1.2 ABNF)."""
    result: dict[str, str] = {}
    for part in txt.strip().split():
        if "=" in part:
            k, _, v = part.partition("=")
            result[k.lower()] = v
        elif "token" not in result:
            # Bare value with no key= prefix is the token per spec
            result["token"] = part
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def issue(
    domain: str,
    *,
    agent_name: str | None = None,
    issuer_domain: str | None = None,
    ttl_seconds: int = 3600,
) -> DCVChallenge:
    """
    Generate a stateless DCV challenge.

    The challenger calls this, then delivers the returned DCVChallenge to the
    claimant out-of-band (A2A message, MCP tool response, etc.).  Nothing is
    written to DNS here — placement is the claimant's job.

    Args:
        domain:        Domain the claimant must prove control of.
        agent_name:    Optional agent name to scope the bnd-req field.
        issuer_domain: Optional issuer domain to scope the bnd-req field.
        ttl_seconds:   Challenge validity window in seconds (default: 1 hour).

    Returns:
        DCVChallenge containing token, fqdn, txt_value, and expiry.
    """
    token = _generate_token()
    expiry = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
    bnd_req = f"svc:{agent_name}@{issuer_domain}" if agent_name and issuer_domain else None
    fqdn = f"{CHALLENGE_LABEL}.{domain}"
    txt_value = _build_txt_value(token, expiry, bnd_req)

    logger.debug("DCV challenge issued", domain=domain, fqdn=fqdn, bnd_req=bnd_req)

    return DCVChallenge(
        token=token,
        domain=domain,
        fqdn=fqdn,
        txt_value=txt_value,
        expiry=expiry,
        bnd_req=bnd_req,
    )


async def place(
    domain: str,
    token: str,
    *,
    bnd_req: str | None = None,
    expiry_seconds: int = 3600,
    ttl: int = 300,
    backend=None,
) -> str:
    """
    Write the DCV challenge TXT record to DNS via the configured backend.

    The claimant calls this using their own dns-aid backend credentials,
    proving they have write access to the domain's zone.

    Args:
        domain:         Zone to write the challenge into.
        token:          Token received from the challenger.
        bnd_req:        Optional binding scope to include (pass through from challenge).
        expiry_seconds: How long the placed record should be valid (default: 1 hour).
        ttl:            DNS record TTL in seconds (default: 300 — short, for quick cleanup).
        backend:        DNS backend instance; defaults to DNS_AID_BACKEND env var.

    Returns:
        FQDN where the challenge was placed.
    """
    from dns_aid.core.publisher import get_default_backend

    dns_backend = backend or get_default_backend()
    expiry = datetime.now(UTC) + timedelta(seconds=expiry_seconds)
    txt_value = _build_txt_value(token, expiry, bnd_req)
    fqdn = f"{CHALLENGE_LABEL}.{domain}"

    logger.info("Placing DCV challenge", domain=domain, fqdn=fqdn)

    await dns_backend.create_txt_record(
        zone=domain,
        name=CHALLENGE_LABEL,
        values=[txt_value],
        ttl=ttl,
    )

    logger.info("DCV challenge placed", fqdn=fqdn)
    return fqdn


async def verify(
    domain: str,
    token: str,
    *,
    nameserver: str | None = None,
    port: int = 53,
) -> DCVVerifyResult:
    """
    Resolve _agents-challenge.{domain} and verify the token is present and unexpired.

    The challenger calls this after the claimant has placed the record.
    No backend credentials required — pure DNS resolution.

    Args:
        domain:      Domain to check.
        token:       Token originally issued by the challenger.
        nameserver:  Optional nameserver IP to query directly (useful in testbeds
                     or when the challenging org's resolver can't see the claimant's zone).
        port:        DNS port (default: 53).

    Returns:
        DCVVerifyResult with verified=True on success.
    """
    fqdn = f"{CHALLENGE_LABEL}.{domain}"
    logger.debug("DCV verify", domain=domain, fqdn=fqdn, nameserver=nameserver)

    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
        resolver.port = port

    try:
        answers = resolver.resolve(fqdn, "TXT")
    except dns.resolver.NXDOMAIN:
        return DCVVerifyResult(
            verified=False, domain=domain, token=token, fqdn=fqdn,
            error="No challenge record found (NXDOMAIN)",
        )
    except dns.resolver.NoAnswer:
        return DCVVerifyResult(
            verified=False, domain=domain, token=token, fqdn=fqdn,
            error="No TXT records at challenge name",
        )
    except dns.exception.DNSException as e:
        return DCVVerifyResult(
            verified=False, domain=domain, token=token, fqdn=fqdn,
            error=str(e),
        )

    now = datetime.now(UTC)

    for rdata in answers:
        # Multi-string TXT records are concatenated per DCV-techniques §6.1
        txt = "".join(
            s.decode() if isinstance(s, bytes) else s for s in rdata.strings
        )
        parsed = _parse_txt_value(txt)

        if parsed.get("token") != token:
            continue

        expiry_str = parsed.get("expiry", "")
        if expiry_str and expiry_str != "never":
            try:
                expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
                if now > expiry:
                    logger.info("DCV challenge expired", domain=domain, expiry=expiry_str)
                    return DCVVerifyResult(
                        verified=False, domain=domain, token=token, fqdn=fqdn,
                        expired=True, error=f"Challenge expired at {expiry_str}",
                    )
            except ValueError:
                pass  # Unparseable expiry treated as no expiry

        logger.info("DCV verified", domain=domain, fqdn=fqdn)
        return DCVVerifyResult(verified=True, domain=domain, token=token, fqdn=fqdn)

    return DCVVerifyResult(
        verified=False, domain=domain, token=token, fqdn=fqdn,
        error="Token not found in any challenge record",
    )


async def revoke(
    domain: str,
    *,
    backend=None,
) -> bool:
    """
    Delete the DCV challenge TXT record from DNS.

    Should be called after successful verification to clean up.

    Args:
        domain:  Zone to remove the challenge from.
        backend: DNS backend instance; defaults to DNS_AID_BACKEND env var.

    Returns:
        True if deleted, False if not found or deletion failed.
    """
    from dns_aid.core.publisher import get_default_backend

    dns_backend = backend or get_default_backend()
    fqdn = f"{CHALLENGE_LABEL}.{domain}"

    logger.info("Revoking DCV challenge", domain=domain, fqdn=fqdn)

    result = await dns_backend.delete_record(
        zone=domain,
        name=CHALLENGE_LABEL,
        record_type="TXT",
    )

    if result:
        logger.info("DCV challenge revoked", fqdn=fqdn)
    else:
        logger.warning("DCV challenge not found or already removed", fqdn=fqdn)

    return result
