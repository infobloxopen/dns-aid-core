# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Helpers for lazily acquiring Google Cloud auth state."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from google.auth.credentials import Credentials


def get_google_auth_state(scopes: list[str]) -> tuple[Credentials, str | None]:
    """Return refreshed ADC credentials and the discovered project id."""
    try:
        from google.auth import default
        from google.auth.transport.requests import Request
    except ImportError as exc:  # pragma: no cover - exercised by optional-dep paths
        raise ImportError(
            "Google Cloud support requires the 'google-auth' package. "
            "Install the dns-aid[cloud-dns] extra."
        ) from exc

    credentials, project_id = default(scopes=scopes)
    if not credentials.valid or not credentials.token:
        credentials.refresh(Request())
    if not credentials.token:
        raise RuntimeError("Failed to acquire a Google Cloud access token from ADC")
    return credentials, project_id


def get_google_access_token(scopes: list[str]) -> tuple[str, str | None]:
    """Return a Google Cloud bearer token and the discovered project id."""
    credentials, project_id = get_google_auth_state(scopes)
    return credentials.token, project_id
