# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Input validation utilities for DNS-AID.

Provides validation and sanitization for domain names, agent names,
and other user inputs. Used to prevent injection attacks and ensure
compliance with DNS naming standards.

Security Note:
    All user-provided inputs should be validated before use in DNS operations.
    This module is designed to pass security scanners (Wiz, SonarQube, Bandit).
"""

from __future__ import annotations

import re
from typing import Literal

# DNS label constraints (RFC 1035)
MAX_LABEL_LENGTH = 63
MAX_DOMAIN_LENGTH = 253
MIN_LABEL_LENGTH = 1

# Agent name pattern: lowercase alphanumeric with hyphens
AGENT_NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Domain name pattern (RFC 1035 compliant)
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# Safe characters for capabilities
CAPABILITY_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Version pattern (semver-like, supports pre-release and build metadata)
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([a-zA-Z0-9._+-]*)?$")


class ValidationError(ValueError):
    """Raised when input validation fails."""

    def __init__(self, field: str, message: str, value: str | None = None):
        self.field = field
        self.message = message
        self.value = value
        super().__init__(f"{field}: {message}")


def validate_agent_name(name: str) -> str:
    """
    Validate and normalize an agent name.

    Agent names must be:
    - 1-63 characters long
    - Lowercase alphanumeric with hyphens
    - Cannot start or end with a hyphen

    Args:
        name: The agent name to validate

    Returns:
        Normalized (lowercase) agent name

    Raises:
        ValidationError: If the name is invalid
    """
    if not name:
        raise ValidationError("name", "Agent name cannot be empty")

    # Normalize to lowercase
    name = name.lower().strip()

    if len(name) > MAX_LABEL_LENGTH:
        raise ValidationError(
            "name",
            f"Agent name cannot exceed {MAX_LABEL_LENGTH} characters",
            name,
        )

    if len(name) < MIN_LABEL_LENGTH:
        raise ValidationError("name", "Agent name cannot be empty", name)

    if not AGENT_NAME_PATTERN.match(name):
        raise ValidationError(
            "name",
            "Agent name must be lowercase alphanumeric with hyphens, "
            "cannot start or end with hyphen",
            name,
        )

    return name


def validate_domain(domain: str) -> str:
    """
    Validate and normalize a domain name.

    Domain names must be:
    - Valid DNS domain format (RFC 1035)
    - Each label 1-63 characters
    - Total length <= 253 characters
    - Only alphanumeric and hyphens in labels

    Args:
        domain: The domain name to validate

    Returns:
        Normalized domain name (lowercase, no trailing dot)

    Raises:
        ValidationError: If the domain is invalid
    """
    if not domain:
        raise ValidationError("domain", "Domain cannot be empty")

    # Normalize: lowercase, remove trailing dot
    domain = domain.lower().strip().rstrip(".")

    if len(domain) > MAX_DOMAIN_LENGTH:
        raise ValidationError(
            "domain",
            f"Domain cannot exceed {MAX_DOMAIN_LENGTH} characters",
            domain,
        )

    # Validate each label
    labels = domain.split(".")

    if len(labels) < 2:
        raise ValidationError(
            "domain",
            "Domain must have at least two labels (e.g., example.com)",
            domain,
        )

    for label in labels:
        if not label:
            raise ValidationError("domain", "Domain labels cannot be empty", domain)

        if len(label) > MAX_LABEL_LENGTH:
            raise ValidationError(
                "domain",
                f"Domain label '{label}' exceeds {MAX_LABEL_LENGTH} characters",
                domain,
            )

        if not DOMAIN_LABEL_PATTERN.match(label):
            raise ValidationError(
                "domain",
                f"Invalid domain label '{label}': must be alphanumeric with hyphens, "
                "cannot start or end with hyphen",
                domain,
            )

    return domain


def validate_protocol(protocol: str) -> Literal["mcp", "a2a"]:
    """
    Validate protocol type.

    Args:
        protocol: Protocol string to validate

    Returns:
        Validated protocol literal

    Raises:
        ValidationError: If protocol is invalid
    """
    if not protocol:
        raise ValidationError("protocol", "Protocol cannot be empty")

    protocol = protocol.lower().strip()

    if protocol not in ("mcp", "a2a"):
        raise ValidationError(
            "protocol",
            "Protocol must be 'mcp' or 'a2a'",
            protocol,
        )

    return protocol  # type: ignore


def validate_endpoint(endpoint: str) -> str:
    """
    Validate endpoint hostname.

    Args:
        endpoint: Hostname where agent is reachable

    Returns:
        Validated endpoint

    Raises:
        ValidationError: If endpoint is invalid
    """
    if not endpoint:
        raise ValidationError("endpoint", "Endpoint cannot be empty")

    endpoint = endpoint.lower().strip().rstrip(".")

    # Endpoint should be a valid hostname (same rules as domain)
    if len(endpoint) > MAX_DOMAIN_LENGTH:
        raise ValidationError(
            "endpoint",
            f"Endpoint cannot exceed {MAX_DOMAIN_LENGTH} characters",
            endpoint,
        )

    labels = endpoint.split(".")

    for label in labels:
        if not label:
            raise ValidationError("endpoint", "Endpoint labels cannot be empty", endpoint)

        if len(label) > MAX_LABEL_LENGTH:
            raise ValidationError(
                "endpoint",
                f"Endpoint label '{label}' exceeds {MAX_LABEL_LENGTH} characters",
                endpoint,
            )

        if not DOMAIN_LABEL_PATTERN.match(label):
            raise ValidationError(
                "endpoint",
                f"Invalid endpoint label '{label}'",
                endpoint,
            )

    return endpoint


def validate_port(port: int) -> int:
    """
    Validate port number.

    Args:
        port: Port number to validate

    Returns:
        Validated port number

    Raises:
        ValidationError: If port is invalid
    """
    if not isinstance(port, int):
        raise ValidationError("port", "Port must be an integer", str(port))

    if port < 1 or port > 65535:
        raise ValidationError(
            "port",
            "Port must be between 1 and 65535",
            str(port),
        )

    return port


def validate_ttl(ttl: int) -> int:
    """
    Validate DNS TTL value.

    Args:
        ttl: TTL value in seconds

    Returns:
        Validated TTL

    Raises:
        ValidationError: If TTL is invalid
    """
    if not isinstance(ttl, int):
        raise ValidationError("ttl", "TTL must be an integer", str(ttl))

    # Minimum 60 seconds, maximum 1 week
    if ttl < 60:
        raise ValidationError("ttl", "TTL must be at least 60 seconds", str(ttl))

    if ttl > 604800:  # 7 days
        raise ValidationError("ttl", "TTL cannot exceed 604800 seconds (7 days)", str(ttl))

    return ttl


def validate_capabilities(capabilities: list[str] | None) -> list[str]:
    """
    Validate list of capabilities.

    Args:
        capabilities: List of capability strings

    Returns:
        Validated list of capabilities

    Raises:
        ValidationError: If any capability is invalid
    """
    if not capabilities:
        return []

    validated = []
    seen = set()

    for cap in capabilities:
        if not cap:
            continue

        cap = cap.strip().lower()

        if not CAPABILITY_PATTERN.match(cap):
            raise ValidationError(
                "capabilities",
                f"Invalid capability '{cap}': must be alphanumeric with hyphens/underscores, "
                "max 64 characters",
                cap,
            )

        if cap not in seen:
            validated.append(cap)
            seen.add(cap)

    return validated


def validate_version(version: str) -> str:
    """
    Validate version string.

    Args:
        version: Version string (semver format)

    Returns:
        Validated version string

    Raises:
        ValidationError: If version is invalid
    """
    if not version:
        raise ValidationError("version", "Version cannot be empty")

    version = version.strip()

    if not VERSION_PATTERN.match(version):
        raise ValidationError(
            "version",
            "Version must be in semver format (e.g., 1.0.0)",
            version,
        )

    return version


def validate_fqdn(fqdn: str) -> str:
    """
    Validate a fully qualified domain name for DNS-AID records.

    DNS-AID FQDNs follow the pattern: _{agent}._{protocol}._agents.{domain}

    Args:
        fqdn: The FQDN to validate

    Returns:
        Normalized FQDN

    Raises:
        ValidationError: If FQDN is invalid
    """
    if not fqdn:
        raise ValidationError("fqdn", "FQDN cannot be empty")

    fqdn = fqdn.lower().strip().rstrip(".")

    if len(fqdn) > MAX_DOMAIN_LENGTH:
        raise ValidationError(
            "fqdn",
            f"FQDN cannot exceed {MAX_DOMAIN_LENGTH} characters",
            fqdn,
        )

    # DNS-AID records should contain _agents
    if "_agents" not in fqdn:
        raise ValidationError(
            "fqdn",
            "Invalid DNS-AID FQDN: must contain '_agents'",
            fqdn,
        )

    return fqdn


def validate_backend(
    backend: str,
) -> Literal["route53", "cloudflare", "infoblox", "ddns", "mock"]:
    """
    Validate backend type.

    Args:
        backend: Backend string to validate

    Returns:
        Validated backend literal

    Raises:
        ValidationError: If backend is invalid
    """
    if not backend:
        raise ValidationError("backend", "Backend cannot be empty")

    backend = backend.lower().strip()

    valid_backends = ("route53", "cloudflare", "infoblox", "ddns", "mock")
    if backend not in valid_backends:
        raise ValidationError(
            "backend",
            f"Backend must be one of: {', '.join(valid_backends)}",
            backend,
        )

    return backend  # type: ignore
