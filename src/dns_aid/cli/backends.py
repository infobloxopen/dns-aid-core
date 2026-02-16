# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Backend registry — single source of truth for backend metadata.

Used by ``_get_backend()``, ``dns-aid init``, ``dns-aid doctor``,
and the MCP server to provide consistent guidance and auto-detection.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class BackendInfo:
    """Metadata for a DNS backend."""

    name: str
    """Short identifier (e.g. ``"route53"``)."""

    display_name: str
    """Human-readable name (e.g. ``"AWS Route 53"``)."""

    required_env: dict[str, str] = field(default_factory=dict)
    """Env vars that *must* be set → human description."""

    optional_env: dict[str, str] = field(default_factory=dict)
    """Env vars that *may* be set → human description."""

    optional_dep: str | None = None
    """pip extra name (e.g. ``"route53"``), ``None`` if no extra deps."""

    setup_url: str = ""
    """Link to setup documentation."""

    setup_steps: list[str] = field(default_factory=list)
    """Human-readable setup steps for ``init`` / error messages."""


BACKEND_REGISTRY: dict[str, BackendInfo] = {
    "route53": BackendInfo(
        name="route53",
        display_name="AWS Route 53",
        required_env={},  # boto3 resolves credentials via its own chain
        optional_env={
            "AWS_ACCESS_KEY_ID": "AWS access key (or use ~/.aws/credentials)",
            "AWS_SECRET_ACCESS_KEY": "AWS secret key",  # nosec B105 — description, not a credential
            "AWS_REGION": "AWS region (default: us-east-1)",
            "AWS_DEFAULT_REGION": "Fallback region variable",
            "AWS_PROFILE": "Named AWS profile from ~/.aws/credentials",
            "ROUTE53_ZONE_ID": "Hosted zone ID (auto-detected if omitted)",
        },
        optional_dep="route53",
        setup_url="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/",
        setup_steps=[
            "Run: aws configure            (easiest — writes ~/.aws/credentials)",
            "Or: export AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY",
            "Or: export AWS_PROFILE=name   (named profile / SSO)",
            "IAM roles (EC2/ECS/Lambda) work automatically",
        ],
    ),
    "cloudflare": BackendInfo(
        name="cloudflare",
        display_name="Cloudflare DNS",
        required_env={
            "CLOUDFLARE_API_TOKEN": "API token with DNS edit permissions",  # nosec B105
        },
        optional_env={
            "CLOUDFLARE_ZONE_ID": "Zone ID (auto-detected if omitted)",
        },
        optional_dep="cloudflare",
        setup_url="https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
        setup_steps=[
            "Create an API token at dash.cloudflare.com → My Profile → API Tokens",
            "Grant Zone.DNS Edit permission for your zone",
            "Set CLOUDFLARE_API_TOKEN",
        ],
    ),
    "infoblox": BackendInfo(
        name="infoblox",
        display_name="Infoblox BloxOne DDI",
        required_env={
            "INFOBLOX_API_KEY": "BloxOne CSP API key",
        },
        optional_env={
            "INFOBLOX_BASE_URL": "API base URL (default: https://csp.infoblox.com)",
            "INFOBLOX_DNS_VIEW": "DNS view name (default: default)",
        },
        optional_dep="infoblox",
        setup_url="https://docs.infoblox.com/space/BloxOneDDI",
        setup_steps=[
            "Generate an API key in the BloxOne Cloud Services Portal",
            "Set INFOBLOX_API_KEY",
            "Optionally set INFOBLOX_DNS_VIEW if not using 'default'",
        ],
    ),
    "ddns": BackendInfo(
        name="ddns",
        display_name="RFC 2136 Dynamic DNS",
        required_env={
            "DDNS_SERVER": "DNS server hostname or IP address",
        },
        optional_env={
            "DDNS_PORT": "DNS server port (default: 53)",
            "DDNS_TIMEOUT": "Request timeout in seconds (default: 10)",
            "DDNS_KEY_NAME": "TSIG key name",
            "DDNS_KEY_SECRET": "TSIG key secret (base64)",  # nosec B105
            "DDNS_KEY_ALGORITHM": "TSIG algorithm (default: hmac-sha256)",
        },
        optional_dep="ddns",
        setup_url="https://en.wikipedia.org/wiki/Dynamic_DNS",
        setup_steps=[
            "Ensure your DNS server supports RFC 2136 dynamic updates",
            "Set DDNS_SERVER to your nameserver address",
            "For authenticated updates, set DDNS_KEY_NAME and DDNS_KEY_SECRET",
        ],
    ),
    "mock": BackendInfo(
        name="mock",
        display_name="Mock (in-memory, for testing)",
        optional_dep=None,
        setup_steps=["No configuration needed — records are stored in memory."],
    ),
}

ALL_BACKEND_NAMES: list[str] = list(BACKEND_REGISTRY.keys())
"""Ordered list of backend names for help text and iteration."""

REAL_BACKEND_NAMES: list[str] = [n for n in ALL_BACKEND_NAMES if n != "mock"]
"""Backend names excluding mock (for init wizard / doctor)."""


def _has_boto3_credentials() -> bool:
    """Check if boto3 can resolve AWS credentials (env, file, IAM role, etc.)."""
    try:
        import boto3

        session = boto3.Session()
        return session.get_credentials() is not None
    except Exception:
        return False


def detect_backend() -> str | None:
    """Auto-detect a backend from configured environment variables.

    Checks each real backend's ``required_env`` and returns the name of
    the backend whose credentials are fully set.  For Route 53, also checks
    the boto3 credential chain (``~/.aws/credentials``, IAM roles, etc.).

    Returns:
        Backend name if exactly one is configured, ``None`` if zero.

    Raises:
        ValueError: If multiple backends have credentials configured.
    """
    detected: list[str] = []

    for name in REAL_BACKEND_NAMES:
        info = BACKEND_REGISTRY[name]

        # Route 53: required_env is empty; check boto3 credential chain
        if name == "route53":
            if _has_boto3_credentials():
                detected.append(name)
            continue

        if not info.required_env:
            continue
        if all(os.environ.get(var) for var in info.required_env):
            detected.append(name)

    if len(detected) == 1:
        return detected[0]
    if len(detected) > 1:
        raise ValueError(
            f"Multiple backends have credentials configured: {', '.join(detected)}. "
            f"Set DNS_AID_BACKEND to choose one, or use --backend."
        )
    return None
