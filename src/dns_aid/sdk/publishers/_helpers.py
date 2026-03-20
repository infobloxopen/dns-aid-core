# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Internal helpers for provider-managed publishers."""

from __future__ import annotations

import re
from typing import Any

from dns_aid.core.discoverer import _parse_fqdn, _parse_svcb_custom_params
from dns_aid.sdk.publishers.models import PublishedAgentState
from dns_aid.utils.validation import validate_agent_name

_INVALID_AGENT_CHARS = re.compile(r"[^a-z0-9-]+")
_DASH_RUN = re.compile(r"-{2,}")


def normalize_agent_name(raw_name: str) -> str:
    """Normalize provider-native service names into DNS-AID-safe agent names."""
    candidate = raw_name.strip().lower()
    candidate = _INVALID_AGENT_CHARS.sub("-", candidate)
    candidate = _DASH_RUN.sub("-", candidate).strip("-")
    return validate_agent_name(candidate)


def get_nested_value(data: Any, path: str) -> Any | None:
    """Traverse a dotted path through nested dict/list structures."""
    if not path:
        return data

    current = data
    for segment in path.split("."):
        if isinstance(current, dict):
            current = current.get(segment)
        elif isinstance(current, list):
            try:
                current = current[int(segment)]
            except (ValueError, IndexError):
                return None
        else:
            return None

        if current is None:
            return None

    return current


def coerce_capabilities(value: Any) -> list[str]:
    """Normalize provider metadata into a deduplicated capability list."""
    if value is None:
        return []
    if isinstance(value, str):
        raw_caps = [part.strip() for part in value.split(",")]
    elif isinstance(value, list):
        raw_caps = [str(part).strip() for part in value]
    else:
        return []

    deduped: list[str] = []
    seen = set()
    for cap in raw_caps:
        normalized = cap.lower()
        if normalized and normalized not in seen:
            deduped.append(normalized)
            seen.add(normalized)
    return deduped


def is_truthy_tag(value: str | None, truthy_values: list[str]) -> bool:
    """Interpret common stable-tag values."""
    if value is None:
        return False
    return value.strip().lower() in {item.strip().lower() for item in truthy_values}


def parse_capabilities_txt(values: list[str]) -> list[str]:
    """Extract the existing DNS-AID TXT capability wire format."""
    for value in values:
        normalized = value.strip().strip('"')
        if normalized.startswith("capabilities="):
            return [
                part.strip()
                for part in normalized[len("capabilities=") :].split(",")
                if part.strip()
            ]
    return []


def parse_published_state(record: dict[str, Any], txt_values: list[str] | None = None) -> PublishedAgentState | None:
    """Convert backend SVCB record data into a comparable publisher state."""
    fqdn = record.get("fqdn") or ""
    name, protocol = _parse_fqdn(str(fqdn))
    if not name or not protocol:
        return None

    values = record.get("values") or []
    if not values:
        return None

    first_value = str(values[0]).strip()
    parts = first_value.split()
    if len(parts) < 2:
        return None

    target_host = parts[1].rstrip(".")
    custom_params = _parse_svcb_custom_params(first_value)
    return PublishedAgentState(
        name=name,
        protocol=protocol,
        target_host=target_host,
        ttl=int(record.get("ttl", 0)),
        capabilities=parse_capabilities_txt(txt_values or []),
        connect_class=custom_params.get("connect-class"),
        connect_meta=custom_params.get("connect-meta"),
        enroll_uri=custom_params.get("enroll-uri"),
    )
