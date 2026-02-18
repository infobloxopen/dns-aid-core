# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LiveNiosTarget:
    """Configuration for one live NIOS target."""

    name: str
    host: str
    username: str
    password: str
    verify_ssl: bool = True
    wapi_version: str = "2.13.7"
    dns_view: str = "default"
    timeout: float = 15.0
    test_zone: str | None = None


def _parse_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def _live_targets_file() -> Path:
    configured = os.environ.get("DNS_AID_LIVE_TARGETS_FILE")
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parent / "live_targets.json"


def _as_str(value: Any, default: str = "") -> str:
    return str(value if value is not None else default).strip()


def load_live_nios_targets() -> list[LiveNiosTarget]:
    """
    Load live NIOS targets from JSON config.

    Expected file shape:
    {
      "nios": [
        {
          "name": "lab-nios",
          "host": "10.100.0.100",
          "username": "admin",
          "password_env": "NIOS_LAB_PASSWORD",
          "verify_ssl": false,
          "wapi_version": "2.13.7",
          "dns_view": "default",
          "timeout": 15.0,
          "test_zone": "example.com"
        }
      ]
    }
    """
    path = _live_targets_file()
    if not path.exists():
        return []

    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        warnings.warn(f"Failed to parse live targets file {path}: {exc}", stacklevel=2)
        return []

    raw_targets = payload.get("nios", [])
    if not isinstance(raw_targets, list):
        warnings.warn(f"Invalid live targets format in {path}: 'nios' must be a list", stacklevel=2)
        return []

    targets: list[LiveNiosTarget] = []
    for index, raw in enumerate(raw_targets):
        if not isinstance(raw, dict):
            warnings.warn(f"Skipping non-object nios target at index {index}", stacklevel=2)
            continue

        name = _as_str(raw.get("name"), default=f"nios-{index}")
        host = _as_str(raw.get("host"))
        username = _as_str(raw.get("username"))

        password = raw.get("password")
        password_env = _as_str(raw.get("password_env"))
        if not password and password_env:
            password = os.environ.get(password_env)

        if not host or not username or not password:
            warnings.warn(
                f"Skipping nios target '{name}': host/username/password missing. "
                "Use password or password_env.",
                stacklevel=2,
            )
            continue

        timeout_value = raw.get("timeout", 15.0)
        try:
            timeout = float(timeout_value)
        except (TypeError, ValueError):
            timeout = 15.0

        test_zone = _as_str(raw.get("test_zone")) or None
        if test_zone:
            test_zone = test_zone.rstrip(".")

        targets.append(
            LiveNiosTarget(
                name=name,
                host=host,
                username=username,
                password=str(password),
                verify_ssl=_parse_bool(raw.get("verify_ssl"), default=True),
                wapi_version=_as_str(raw.get("wapi_version"), default="2.13.7"),
                dns_view=_as_str(raw.get("dns_view"), default="default"),
                timeout=timeout,
                test_zone=test_zone,
            )
        )

    return targets


def live_tests_enabled() -> bool:
    return _parse_bool(os.environ.get("DNS_AID_LIVE_TESTS"), default=False)


def live_mutation_tests_enabled() -> bool:
    return _parse_bool(os.environ.get("DNS_AID_LIVE_MUTATION_TESTS"), default=False)
