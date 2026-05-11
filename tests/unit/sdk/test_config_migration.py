# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for SDKConfig directory-URL migration semantics (FR-018, FR-019, FR-020).

The deprecated ``telemetry_api_url`` MUST continue to work as an alias for
``directory_api_url`` for one minor release. When both are set, the canonical field wins
and a DeprecationWarning is emitted exactly once per process.
"""

from __future__ import annotations

import warnings
from typing import Any

import pytest

from dns_aid.sdk._config import SDKConfig, _warn_telemetry_alias_once


@pytest.fixture(autouse=True)
def _reset_deprecation_latch() -> None:
    """Reset the ``functools.cache`` latch between tests so each test sees a fresh state."""
    _warn_telemetry_alias_once.cache_clear()


class TestResolvedDirectoryURL:
    """``SDKConfig.resolved_directory_url`` is the single source of truth."""

    def test_returns_none_when_neither_field_set(self) -> None:
        config = SDKConfig()
        assert config.resolved_directory_url is None

    def test_returns_directory_api_url_when_only_canonical_field_set(self) -> None:
        config = SDKConfig(directory_api_url="https://directory.example.com")
        assert config.resolved_directory_url == "https://directory.example.com"

    def test_returns_telemetry_api_url_when_only_alias_set(self) -> None:
        config = SDKConfig(telemetry_api_url="https://legacy.example.com")
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            assert config.resolved_directory_url == "https://legacy.example.com"

    def test_directory_api_url_wins_when_both_set(self) -> None:
        config = SDKConfig(
            directory_api_url="https://canonical.example.com",
            telemetry_api_url="https://legacy.example.com",
        )
        assert config.resolved_directory_url == "https://canonical.example.com"


class TestDeprecationWarning:
    """Deprecation warning fires once per process when the legacy alias is the active source."""

    def test_warning_emitted_when_legacy_alias_resolves(self) -> None:
        config = SDKConfig(telemetry_api_url="https://legacy.example.com")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = config.resolved_directory_url
        deprecation_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 1
        assert "telemetry_api_url is deprecated" in str(deprecation_warnings[0].message)

    def test_warning_only_emitted_once_per_process(self) -> None:
        config = SDKConfig(telemetry_api_url="https://legacy.example.com")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = config.resolved_directory_url
            _ = config.resolved_directory_url
            _ = config.resolved_directory_url
        deprecation_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 1

    def test_no_warning_when_canonical_field_used(self) -> None:
        config = SDKConfig(directory_api_url="https://canonical.example.com")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = config.resolved_directory_url
        deprecation_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert deprecation_warnings == []

    def test_no_warning_when_both_fields_set(self) -> None:
        config = SDKConfig(
            directory_api_url="https://canonical.example.com",
            telemetry_api_url="https://legacy.example.com",
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = config.resolved_directory_url
        deprecation_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert deprecation_warnings == []


class TestEnvVarPopulation:
    """``SDKConfig.from_env`` honors both new and legacy environment variables."""

    def test_directory_api_url_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DNS_AID_SDK_DIRECTORY_API_URL", "https://directory.example.com")
        monkeypatch.delenv("DNS_AID_SDK_TELEMETRY_API_URL", raising=False)
        config = SDKConfig.from_env()
        assert config.directory_api_url == "https://directory.example.com"
        assert config.telemetry_api_url is None

    def test_legacy_telemetry_api_url_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DNS_AID_SDK_DIRECTORY_API_URL", raising=False)
        monkeypatch.setenv("DNS_AID_SDK_TELEMETRY_API_URL", "https://legacy.example.com")
        config = SDKConfig.from_env()
        assert config.directory_api_url is None
        assert config.telemetry_api_url == "https://legacy.example.com"

    def test_both_env_vars_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DNS_AID_SDK_DIRECTORY_API_URL", "https://canonical.example.com")
        monkeypatch.setenv("DNS_AID_SDK_TELEMETRY_API_URL", "https://legacy.example.com")
        config = SDKConfig.from_env()
        assert config.directory_api_url == "https://canonical.example.com"
        assert config.telemetry_api_url == "https://legacy.example.com"
        assert config.resolved_directory_url == "https://canonical.example.com"


class TestWarnHelper:
    """The internal warn-once helper is process-scoped and idempotent."""

    def test_helper_warns_once(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _warn_telemetry_alias_once()
            _warn_telemetry_alias_once()
            _warn_telemetry_alias_once()
        assert sum(1 for w in caught if issubclass(w.category, DeprecationWarning)) == 1


class TestBackwardsCompatibility:
    """Existing callers of SDKConfig must continue to work unchanged."""

    def test_config_with_only_existing_fields_still_works(self) -> None:
        config = SDKConfig(timeout_seconds=15.0, telemetry_api_url="https://api.test.io")
        assert config.timeout_seconds == 15.0
        assert config.telemetry_api_url == "https://api.test.io"

    def test_config_default_construction_unchanged(self) -> None:
        config = SDKConfig()
        # Previously ``telemetry_api_url`` defaulted to None; check that's still the case
        # AND the new ``directory_api_url`` also defaults to None.
        assert config.telemetry_api_url is None
        assert config.directory_api_url is None
        # And every other previously-default field stays at its prior default.
        assert config.timeout_seconds == 30.0
        assert config.max_retries == 0
        assert config.policy_mode == "permissive"


def test_config_serialization_roundtrip() -> None:
    """Pydantic model_dump → SDKConfig should preserve directory URL fields."""
    original = SDKConfig(
        directory_api_url="https://directory.example.com",
        telemetry_api_url="https://legacy.example.com",
    )
    dumped: dict[str, Any] = original.model_dump()
    restored = SDKConfig.model_validate(dumped)
    assert restored.directory_api_url == original.directory_api_url
    assert restored.telemetry_api_url == original.telemetry_api_url
