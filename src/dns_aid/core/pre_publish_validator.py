# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Pre-publish validation for DNS-AID records.

Validates SvcParam syntax, TTL compliance, FQDN length limits, and wire-format
size constraints *before* publishing to DNS, catching errors early rather than
after a failed DNS update.

Usage:
    >>> from dns_aid.core.pre_publish_validator import validate_record
    >>> from dns_aid.core.models import AgentRecord, Protocol
    >>>
    >>> agent = AgentRecord(
    ...     name="my-agent",
    ...     domain="example.com",
    ...     protocol=Protocol.A2A,
    ...     target_host="api.example.com",
    ... )
    >>> errors = validate_record(agent)
    >>> if errors:
    ...     for e in errors:
    ...         print(f"{e.field}: {e.message}")
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from dns_aid.core.models import AgentRecord, Protocol

# DNS limits per RFC 1035
MAX_FQDN_LENGTH = 253
MAX_LABEL_LENGTH = 63

# SVCB RDATA size limit (uint16 length prefix in wire format)
MAX_SVCB_RDATA_BYTES = 65535

# TTL bounds (matching AgentRecord model constraints)
MIN_TTL = 30
MAX_TTL = 86400

# Valid ALPN values for DNS-AID protocols
VALID_ALPN_VALUES = {"a2a", "mcp", "https", "h2", "h3"}

# DNS label pattern (RFC 1035 + RFC 5891 for lowercase)
DNS_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

# Capability string: alphanumeric, hyphens, underscores, dots, slashes
CAPABILITY_RE = re.compile(r"^[a-zA-Z0-9_./:-]+$")


@dataclass(frozen=True)
class ValidationError:
    """A single validation error."""

    field: str
    message: str
    severity: str = "error"  # "error" or "warning"


def validate_record(agent: AgentRecord) -> list[ValidationError]:
    """Validate an AgentRecord before publishing to DNS.

    Checks:
    - FQDN total length (max 253 chars)
    - Individual label lengths (max 63 chars)
    - TTL within bounds (30-86400s)
    - ALPN value validity
    - URI format for cap_uri, policy_uri, enroll_uri
    - Capability string format
    - BAP protocol format
    - Port range (1-65535)
    - Estimated SVCB RDATA wire size

    Returns:
        List of ValidationError. Empty list means the record is valid.
    """
    errors: list[ValidationError] = []

    _validate_fqdn(agent, errors)
    _validate_name(agent, errors)
    _validate_ttl(agent, errors)
    _validate_protocol(agent, errors)
    _validate_port(agent, errors)
    _validate_target_host(agent, errors)
    _validate_uris(agent, errors)
    _validate_capabilities(agent, errors)
    _validate_bap(agent, errors)
    _validate_wire_size(agent, errors)

    return errors


def _validate_fqdn(agent: AgentRecord, errors: list[ValidationError]) -> None:
    """Check FQDN length and label sizes."""
    fqdn = agent.fqdn
    if len(fqdn) > MAX_FQDN_LENGTH:
        errors.append(ValidationError(
            field="fqdn",
            message=f"FQDN '{fqdn}' exceeds {MAX_FQDN_LENGTH} chars ({len(fqdn)} chars)",
        ))

    for label in fqdn.split("."):
        if len(label) > MAX_LABEL_LENGTH:
            errors.append(ValidationError(
                field="fqdn",
                message=f"Label '{label}' exceeds {MAX_LABEL_LENGTH} chars ({len(label)} chars)",
            ))


def _validate_name(agent: AgentRecord, errors: list[ValidationError]) -> None:
    """Check agent name is a valid DNS label."""
    if not DNS_LABEL_RE.match(agent.name):
        errors.append(ValidationError(
            field="name",
            message=f"Name '{agent.name}' is not a valid DNS label "
            "(must be lowercase alphanumeric with hyphens, not starting/ending with hyphen)",
        ))


def _validate_ttl(agent: AgentRecord, errors: list[ValidationError]) -> None:
    """Check TTL is within acceptable bounds."""
    if agent.ttl < MIN_TTL:
        errors.append(ValidationError(
            field="ttl",
            message=f"TTL {agent.ttl}s is below minimum {MIN_TTL}s",
        ))
    elif agent.ttl > MAX_TTL:
        errors.append(ValidationError(
            field="ttl",
            message=f"TTL {agent.ttl}s exceeds maximum {MAX_TTL}s",
        ))


def _validate_protocol(agent: AgentRecord, errors: list[ValidationError]) -> None:
    """Check protocol/ALPN value."""
    if agent.protocol.value not in VALID_ALPN_VALUES:
        errors.append(ValidationError(
            field="protocol",
            message=f"Protocol '{agent.protocol.value}' is not a recognized ALPN value. "
            f"Valid: {', '.join(sorted(VALID_ALPN_VALUES))}",
        ))


def _validate_port(agent: AgentRecord, errors: list[ValidationError]) -> None:
    """Check port is in valid range."""
    if not 1 <= agent.port <= 65535:
        errors.append(ValidationError(
            field="port",
            message=f"Port {agent.port} is outside valid range 1-65535",
        ))


def _validate_target_host(agent: AgentRecord, errors: list[ValidationError]) -> None:
    """Check target host is a valid hostname."""
    host = agent.target_host
    if not host:
        errors.append(ValidationError(
            field="target_host",
            message="Target host must not be empty",
        ))
        return

    if len(host) > MAX_FQDN_LENGTH:
        errors.append(ValidationError(
            field="target_host",
            message=f"Target host exceeds {MAX_FQDN_LENGTH} chars",
        ))

    for label in host.rstrip(".").split("."):
        if len(label) > MAX_LABEL_LENGTH:
            errors.append(ValidationError(
                field="target_host",
                message=f"Target host label '{label}' exceeds {MAX_LABEL_LENGTH} chars",
            ))


def _validate_uris(agent: AgentRecord, errors: list[ValidationError]) -> None:
    """Validate URI fields have proper format."""
    uri_fields = [
        ("cap_uri", agent.cap_uri),
        ("policy_uri", agent.policy_uri),
        ("enroll_uri", agent.enroll_uri),
    ]

    for field_name, value in uri_fields:
        if value is None:
            continue
        parsed = urlparse(value)
        if not parsed.scheme:
            errors.append(ValidationError(
                field=field_name,
                message=f"URI '{value}' has no scheme (expected https:// or urn:)",
            ))
        elif parsed.scheme not in ("https", "http", "urn"):
            errors.append(ValidationError(
                field=field_name,
                message=f"URI scheme '{parsed.scheme}' is unusual; expected https, http, or urn",
                severity="warning",
            ))


def _validate_capabilities(agent: AgentRecord, errors: list[ValidationError]) -> None:
    """Check capability strings are well-formed."""
    for cap in agent.capabilities:
        if not cap:
            errors.append(ValidationError(
                field="capabilities",
                message="Empty capability string",
            ))
        elif not CAPABILITY_RE.match(cap):
            errors.append(ValidationError(
                field="capabilities",
                message=f"Capability '{cap}' contains invalid characters "
                "(allowed: alphanumeric, hyphens, underscores, dots, slashes, colons)",
            ))


def _validate_bap(agent: AgentRecord, errors: list[ValidationError]) -> None:
    """Check BAP protocol format (e.g. 'a2a/1', 'mcp/1')."""
    bap_re = re.compile(r"^[a-z0-9-]+(/[a-z0-9.]+)?$")
    for entry in agent.bap:
        if not bap_re.match(entry):
            errors.append(ValidationError(
                field="bap",
                message=f"BAP entry '{entry}' has invalid format "
                "(expected: protocol or protocol/version, e.g. 'a2a/1')",
            ))


def _validate_wire_size(agent: AgentRecord, errors: list[ValidationError]) -> None:
    """Estimate SVCB RDATA wire size and warn if large."""
    params = agent.to_svcb_params()
    # Rough estimate: each param is key(2) + length(2) + value bytes
    estimated = 4  # priority(2) + target length(1) + target
    estimated += len(agent.target_host) + 2
    for key, value in params.items():
        estimated += 4 + len(value.encode("utf-8"))

    if estimated > MAX_SVCB_RDATA_BYTES:
        errors.append(ValidationError(
            field="svcb_rdata",
            message=f"Estimated SVCB RDATA size ({estimated} bytes) exceeds "
            f"wire-format limit ({MAX_SVCB_RDATA_BYTES} bytes)",
        ))
    elif estimated > 4000:
        errors.append(ValidationError(
            field="svcb_rdata",
            message=f"SVCB RDATA size ({estimated} bytes) is large; "
            "some DNS providers may truncate or reject records over ~4KB",
            severity="warning",
        ))
