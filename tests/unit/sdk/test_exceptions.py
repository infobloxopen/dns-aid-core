# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the directory exception hierarchy.

The hierarchy supports two dispatch patterns:

1. Specific subclass (``except DirectoryConfigError`` or ``except DirectoryAuthError``) for
   distinct remediation paths.
2. Catch-all (``except DirectoryError``) for callers who treat any directory failure the same.

``DirectoryRateLimitedError`` inherits from ``DirectoryUnavailableError`` so a catch-all
``except DirectoryUnavailableError`` covers transient + rate-limited failures together.
"""

from __future__ import annotations

import pytest

from dns_aid.sdk.exceptions import (
    DirectoryAuthError,
    DirectoryConfigError,
    DirectoryError,
    DirectoryRateLimitedError,
    DirectoryUnavailableError,
)


class TestHierarchy:
    """Class hierarchy and ``isinstance`` dispatch."""

    def test_config_error_inherits_from_base(self) -> None:
        err = DirectoryConfigError("not configured")
        assert isinstance(err, DirectoryError)
        assert isinstance(err, Exception)

    def test_unavailable_error_inherits_from_base(self) -> None:
        err = DirectoryUnavailableError("backend down")
        assert isinstance(err, DirectoryError)

    def test_rate_limited_error_inherits_from_unavailable(self) -> None:
        err = DirectoryRateLimitedError("slow down")
        assert isinstance(err, DirectoryUnavailableError)
        assert isinstance(err, DirectoryError)

    def test_auth_error_inherits_from_base(self) -> None:
        err = DirectoryAuthError("bad token")
        assert isinstance(err, DirectoryError)

    def test_auth_error_does_not_inherit_from_unavailable(self) -> None:
        # Auth errors are NOT transient — caller must change config, not retry.
        err = DirectoryAuthError("bad token")
        assert not isinstance(err, DirectoryUnavailableError)


class TestDetailsField:
    """``details`` carries structured context for log analyzers, separate from ``message``."""

    def test_details_defaults_to_empty_dict(self) -> None:
        err = DirectoryConfigError("not configured")
        assert err.details == {}

    def test_details_populated_via_kwarg(self) -> None:
        err = DirectoryConfigError(
            "not configured",
            details={
                "missing_field": "directory_api_url",
                "env_var": "DNS_AID_SDK_DIRECTORY_API_URL",
            },
        )
        assert err.details == {
            "missing_field": "directory_api_url",
            "env_var": "DNS_AID_SDK_DIRECTORY_API_URL",
        }

    def test_details_is_isolated_from_kwarg_dict(self) -> None:
        # Mutating the original dict after construction MUST NOT affect the exception.
        original = {"directory_url": "https://x.example.com"}
        err = DirectoryUnavailableError("down", details=original)
        original["directory_url"] = "MUTATED"
        assert err.details["directory_url"] == "https://x.example.com"

    def test_message_accessible_via_attribute(self) -> None:
        err = DirectoryConfigError("not configured")
        assert err.message == "not configured"
        assert str(err) == "not configured"

    def test_repr_includes_class_name_and_details(self) -> None:
        err = DirectoryConfigError("not configured", details={"missing_field": "x"})
        rendered = repr(err)
        assert "DirectoryConfigError" in rendered
        assert "not configured" in rendered
        assert "missing_field" in rendered


class TestDispatchPatterns:
    """Realistic ``except`` patterns across the hierarchy."""

    def test_specific_subclass_catch(self) -> None:
        with pytest.raises(DirectoryConfigError):
            raise DirectoryConfigError("not configured")

    def test_catch_all_via_base(self) -> None:
        for err_class in (
            DirectoryConfigError,
            DirectoryUnavailableError,
            DirectoryRateLimitedError,
            DirectoryAuthError,
        ):
            with pytest.raises(DirectoryError):
                raise err_class("test")

    def test_rate_limited_caught_as_unavailable(self) -> None:
        with pytest.raises(DirectoryUnavailableError):
            raise DirectoryRateLimitedError("slow down", details={"retry_after_seconds": 30})

    def test_auth_error_not_caught_as_unavailable(self) -> None:
        with pytest.raises(DirectoryAuthError):
            try:
                raise DirectoryAuthError("bad token")
            except DirectoryUnavailableError:
                pytest.fail("DirectoryAuthError should not be caught as DirectoryUnavailableError")
