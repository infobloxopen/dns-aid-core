# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for auth handler registry and factory."""

from __future__ import annotations

import pytest

from dns_aid.sdk.auth.registry import resolve_auth_handler
from dns_aid.sdk.auth.simple import (
    ApiKeyAuthHandler,
    BearerAuthHandler,
    NoopAuthHandler,
)


class TestResolveAuthHandler:
    def test_noop(self) -> None:
        handler = resolve_auth_handler("none")
        assert isinstance(handler, NoopAuthHandler)

    def test_api_key(self) -> None:
        handler = resolve_auth_handler(
            "api_key",
            credentials={"api_key": "sk-123"},
        )
        assert isinstance(handler, ApiKeyAuthHandler)

    def test_api_key_with_config(self) -> None:
        handler = resolve_auth_handler(
            "api_key",
            auth_config={"header_name": "X-Custom", "location": "header"},
            credentials={"api_key": "sk-123"},
        )
        assert isinstance(handler, ApiKeyAuthHandler)
        assert handler._header_name == "X-Custom"

    def test_bearer(self) -> None:
        handler = resolve_auth_handler(
            "bearer",
            credentials={"token": "my-token"},
        )
        assert isinstance(handler, BearerAuthHandler)

    def test_oauth2(self) -> None:
        handler = resolve_auth_handler(
            "oauth2",
            auth_config={
                "oauth_discovery": "https://auth.example.com/.well-known/openid-configuration"
            },
            credentials={
                "client_id": "id",
                "client_secret": "secret",
            },
        )
        assert handler.auth_type == "oauth2"

    def test_ztaip_alias_bearer_token(self) -> None:
        handler = resolve_auth_handler(
            "bearer_token",
            credentials={"token": "tok"},
        )
        assert isinstance(handler, BearerAuthHandler)

    def test_ztaip_alias_oauth2_client_credentials(self) -> None:
        handler = resolve_auth_handler(
            "oauth2_client_credentials",
            auth_config={"token_url": "https://auth.example.com/token"},
            credentials={"client_id": "id", "client_secret": "s"},
        )
        assert handler.auth_type == "oauth2"

    def test_unknown_auth_type(self) -> None:
        with pytest.raises(ValueError, match="Unknown auth_type"):
            resolve_auth_handler("kerberos")

    def test_missing_api_key_credential(self) -> None:
        with pytest.raises(ValueError, match="requires 'api_key'"):
            resolve_auth_handler("api_key", credentials={})

    def test_missing_bearer_token(self) -> None:
        with pytest.raises(ValueError, match="requires 'token'"):
            resolve_auth_handler("bearer", credentials={})

    def test_missing_oauth2_credentials(self) -> None:
        with pytest.raises(ValueError, match="requires 'client_id'"):
            resolve_auth_handler(
                "oauth2",
                auth_config={"token_url": "https://auth.example.com/token"},
                credentials={},
            )
