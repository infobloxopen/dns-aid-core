# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Helpers for lazily acquiring Google Cloud auth state."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from google.auth.credentials import Credentials


_DEFAULT_REFRESH_MARGIN = timedelta(minutes=5)


def _load_google_auth_modules():
    try:
        from google.auth import default
        from google.auth.transport.requests import Request
    except ImportError as exc:  # pragma: no cover - exercised by optional-dep paths
        raise ImportError(
            "Google Cloud support requires the 'google-auth' package. "
            "Install the dns-aid[apphub] or dns-aid[cloud-dns] extra."
        ) from exc
    return default, Request


def _needs_refresh(credentials: Credentials, refresh_margin: timedelta) -> bool:
    if not credentials.valid or not credentials.token:
        return True
    expiry = getattr(credentials, "expiry", None)
    if expiry is None:
        return False
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return expiry <= datetime.now(UTC) + refresh_margin


def get_google_auth_state(
    scopes: list[str],
    *,
    refresh_margin: timedelta = _DEFAULT_REFRESH_MARGIN,
    credentials: Credentials | None = None,
    project_id: str | None = None,
) -> tuple[Credentials, str | None]:
    """Return refreshed ADC credentials and the discovered project id."""
    default, request_cls = _load_google_auth_modules()

    if credentials is None:
        credentials, discovered_project = default(scopes=scopes)
        if project_id is None:
            project_id = discovered_project

    if _needs_refresh(credentials, refresh_margin):
        credentials.refresh(request_cls())
    if not credentials.token:
        raise RuntimeError("Failed to acquire a Google Cloud access token from ADC")
    return credentials, project_id


def get_google_access_token(scopes: list[str]) -> tuple[str, str | None]:
    """Return a Google Cloud bearer token and the discovered project id."""
    credentials, project_id = get_google_auth_state(scopes)
    return credentials.token, project_id


class GoogleAccessTokenProvider:
    """Async, cached Google ADC token provider with refresh-window handling."""

    def __init__(
        self,
        scopes: list[str],
        *,
        refresh_margin: timedelta = _DEFAULT_REFRESH_MARGIN,
    ) -> None:
        self._scopes = list(scopes)
        self._refresh_margin = refresh_margin
        self._credentials: Credentials | None = None
        self._project_id: str | None = None
        self._lock = asyncio.Lock()

    async def get_token(self) -> tuple[str, str | None]:
        async with self._lock:
            credentials, project_id = await asyncio.to_thread(
                get_google_auth_state,
                self._scopes,
                refresh_margin=self._refresh_margin,
                credentials=self._credentials,
                project_id=self._project_id,
            )
            self._credentials = credentials
            self._project_id = project_id
            if not credentials.token:
                raise RuntimeError("Failed to acquire a Google Cloud access token from ADC")
            return credentials.token, project_id
