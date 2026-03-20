# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.utils.google_auth."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from dns_aid.utils.google_auth import GoogleAccessTokenProvider


class _FakeCredentials:
    def __init__(self, *, token: str, expiry: datetime, valid: bool = True) -> None:
        self.token = token
        self.expiry = expiry
        self.valid = valid
        self.refresh_count = 0

    def refresh(self, _request: object) -> None:
        self.refresh_count += 1
        self.token = "fresh-token"
        self.valid = True
        self.expiry = datetime.now(UTC) + timedelta(hours=1)


class _FakeRequest:
    pass


@pytest.mark.asyncio
async def test_google_access_token_provider_refreshes_and_caches(monkeypatch):
    credentials = _FakeCredentials(
        token="stale-token",
        expiry=datetime.now(UTC) + timedelta(minutes=1),
        valid=True,
    )
    default_calls = 0

    def fake_default(*, scopes: list[str]):
        nonlocal default_calls
        default_calls += 1
        assert scopes == ["scope"]
        return credentials, "test-project"

    monkeypatch.setattr(
        "dns_aid.utils.google_auth._load_google_auth_modules",
        lambda: (fake_default, _FakeRequest),
    )

    provider = GoogleAccessTokenProvider(["scope"])
    first, second = await asyncio.gather(provider.get_token(), provider.get_token())

    assert first == ("fresh-token", "test-project")
    assert second == ("fresh-token", "test-project")
    assert default_calls == 1
    assert credentials.refresh_count == 1
