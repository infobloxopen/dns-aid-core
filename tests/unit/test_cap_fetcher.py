# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for DNS-AID capability document fetcher."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.core.cap_fetcher import CapabilityDocument, fetch_cap_document


class TestCapabilityDocument:
    """Tests for CapabilityDocument dataclass."""

    def test_default_values(self):
        doc = CapabilityDocument()
        assert doc.capabilities == []
        assert doc.version is None
        assert doc.description is None
        assert doc.use_cases == []
        assert doc.metadata == {}

    def test_with_values(self):
        doc = CapabilityDocument(
            capabilities=["travel", "booking"],
            version="1.0.0",
            description="Booking agent",
            use_cases=["flight-booking"],
            metadata={"contact": "ops@example.com"},
        )
        assert doc.capabilities == ["travel", "booking"]
        assert doc.version == "1.0.0"
        assert doc.description == "Booking agent"
        assert doc.use_cases == ["flight-booking"]
        assert doc.metadata == {"contact": "ops@example.com"}


class TestFetchCapDocument:
    """Tests for fetch_cap_document."""

    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        """Test fetching a valid capability document."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "capabilities": ["travel", "booking", "calendar"],
            "version": "1.0.0",
            "description": "Booking agent for travel reservations",
            "use_cases": ["flight-booking", "hotel-reservation"],
            "authentication": "oauth2",
            "rate_limit": "100/min",
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.cap_fetcher.httpx.AsyncClient", return_value=mock_client),
        ):
            doc = await fetch_cap_document("https://example.com/.well-known/agent-cap.json")

        assert doc is not None
        assert doc.capabilities == ["travel", "booking", "calendar"]
        assert doc.version == "1.0.0"
        assert doc.description == "Booking agent for travel reservations"
        assert doc.use_cases == ["flight-booking", "hotel-reservation"]
        assert doc.metadata["authentication"] == "oauth2"
        assert doc.metadata["rate_limit"] == "100/min"

    @pytest.mark.asyncio
    async def test_returns_none_on_404(self):
        """Test that 404 returns None."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.cap_fetcher.httpx.AsyncClient", return_value=mock_client),
        ):
            doc = await fetch_cap_document("https://example.com/.well-known/agent-cap.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_returns_none_on_500(self):
        """Test that server error returns None."""
        mock_response = MagicMock()
        mock_response.status_code = 500

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.cap_fetcher.httpx.AsyncClient", return_value=mock_client),
        ):
            doc = await fetch_cap_document("https://example.com/.well-known/agent-cap.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_returns_none_on_timeout(self):
        """Test that timeout returns None."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.cap_fetcher.httpx.AsyncClient", return_value=mock_client),
        ):
            doc = await fetch_cap_document("https://example.com/.well-known/agent-cap.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_returns_none_on_connect_error(self):
        """Test that connection error returns None."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.cap_fetcher.httpx.AsyncClient", return_value=mock_client),
        ):
            doc = await fetch_cap_document("https://unreachable.example.com/cap.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_returns_none_on_invalid_json(self):
        """Test that invalid JSON returns None."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("invalid json")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.cap_fetcher.httpx.AsyncClient", return_value=mock_client),
        ):
            doc = await fetch_cap_document("https://example.com/bad.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_returns_none_on_non_dict_json(self):
        """Test that non-dict JSON (e.g., array) returns None."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = ["not", "a", "dict"]

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.cap_fetcher.httpx.AsyncClient", return_value=mock_client),
        ):
            doc = await fetch_cap_document("https://example.com/array.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_empty_capabilities_list(self):
        """Test document with empty capabilities list."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "capabilities": [],
            "version": "1.0.0",
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.cap_fetcher.httpx.AsyncClient", return_value=mock_client),
        ):
            doc = await fetch_cap_document("https://example.com/cap.json")

        assert doc is not None
        assert doc.capabilities == []
        assert doc.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_missing_capabilities_field(self):
        """Test document without capabilities field."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": "1.0.0",
            "description": "An agent without caps listed",
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.cap_fetcher.httpx.AsyncClient", return_value=mock_client),
        ):
            doc = await fetch_cap_document("https://example.com/cap.json")

        assert doc is not None
        assert doc.capabilities == []
        assert doc.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_extra_metadata_preserved(self):
        """Test that unknown fields are preserved in metadata."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "capabilities": ["travel"],
            "version": "2.0.0",
            "description": "Travel agent",
            "use_cases": ["booking"],
            "protocols": ["mcp"],
            "authentication": "oauth2",
            "rate_limit": "100/min",
            "contact": "ops@example.com",
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.core.cap_fetcher.httpx.AsyncClient", return_value=mock_client),
        ):
            doc = await fetch_cap_document("https://example.com/cap.json")

        assert doc is not None
        assert doc.capabilities == ["travel"]
        # Known fields should NOT be in metadata
        assert "capabilities" not in doc.metadata
        assert "version" not in doc.metadata
        assert "description" not in doc.metadata
        assert "use_cases" not in doc.metadata
        # Unknown fields SHOULD be in metadata
        assert doc.metadata["protocols"] == ["mcp"]
        assert doc.metadata["authentication"] == "oauth2"
        assert doc.metadata["rate_limit"] == "100/min"
        assert doc.metadata["contact"] == "ops@example.com"
