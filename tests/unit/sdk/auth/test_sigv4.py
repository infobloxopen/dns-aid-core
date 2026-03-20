# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for AWS SigV4 auth handler."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
from botocore.credentials import Credentials

from dns_aid.sdk.auth.sigv4 import SigV4AuthHandler, _httpx_to_aws_request

# Test credentials (not real — AWS example keys from docs)
_TEST_CREDS = Credentials(
    access_key="AKIAIOSFODNN7EXAMPLE",
    secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # noqa: S106
)


@pytest.fixture
def sigv4_handler() -> SigV4AuthHandler:
    """Create a SigV4 handler with test credentials."""
    with patch("boto3.Session") as mock_session_cls:
        mock_session = mock_session_cls.return_value
        mock_creds = mock_session.get_credentials.return_value
        mock_creds.get_frozen_credentials.return_value = _TEST_CREDS
        return SigV4AuthHandler(region="us-east-1", service="vpc-lattice-svcs")


class TestSigV4AuthHandler:
    @pytest.mark.asyncio
    async def test_signs_request_with_authorization_header(
        self, sigv4_handler: SigV4AuthHandler
    ) -> None:
        request = httpx.Request(
            "POST",
            "https://agent.lattice.example.com/mcp",
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        result = await sigv4_handler.apply(request)

        assert "authorization" in result.headers
        auth_header = result.headers["authorization"]
        assert auth_header.startswith("AWS4-HMAC-SHA256")
        assert "Credential=AKIAIOSFODNN7EXAMPLE" in auth_header
        assert "vpc-lattice-svcs" in auth_header

    @pytest.mark.asyncio
    async def test_adds_amz_date_header(self, sigv4_handler: SigV4AuthHandler) -> None:
        request = httpx.Request("GET", "https://agent.lattice.example.com/health")
        result = await sigv4_handler.apply(request)

        assert "x-amz-date" in result.headers

    @pytest.mark.asyncio
    async def test_signs_with_api_gateway_service(self) -> None:
        with patch("boto3.Session") as mock_session_cls:
            mock_session = mock_session_cls.return_value
            mock_creds = mock_session.get_credentials.return_value
            mock_creds.get_frozen_credentials.return_value = _TEST_CREDS

            handler = SigV4AuthHandler(region="us-west-2", service="execute-api")

        request = httpx.Request("POST", "https://api.example.com/invoke")
        result = await handler.apply(request)

        assert "execute-api" in result.headers["authorization"]
        assert "us-west-2" in result.headers["authorization"]

    def test_auth_type(self, sigv4_handler: SigV4AuthHandler) -> None:
        assert sigv4_handler.auth_type == "sigv4"


class TestHttpxToAWSRequest:
    def test_converts_post_request(self) -> None:
        request = httpx.Request(
            "POST",
            "https://agent.example.com/mcp?foo=bar",
            json={"method": "tools/list"},
            headers={"Content-Type": "application/json"},
        )
        aws_req = _httpx_to_aws_request(request)

        assert aws_req.method == "POST"
        assert "agent.example.com" in aws_req.url
        assert "foo=bar" in aws_req.url
        assert aws_req.headers.get("Content-Type") == "application/json"

    def test_converts_get_request_without_body(self) -> None:
        request = httpx.Request("GET", "https://agent.example.com/health")
        aws_req = _httpx_to_aws_request(request)

        assert aws_req.method == "GET"
        assert aws_req.data is None


class TestSigV4Registry:
    def test_registry_resolves_sigv4(self) -> None:
        from dns_aid.sdk.auth.registry import resolve_auth_handler

        with patch("boto3.Session") as mock_session_cls:
            mock_session = mock_session_cls.return_value
            mock_creds = mock_session.get_credentials.return_value
            mock_creds.get_frozen_credentials.return_value = _TEST_CREDS

            handler = resolve_auth_handler(
                "sigv4",
                auth_config={"region": "us-east-1", "service": "vpc-lattice-svcs"},
            )
        assert handler.auth_type == "sigv4"

    def test_registry_requires_region(self) -> None:
        from dns_aid.sdk.auth.registry import resolve_auth_handler

        with pytest.raises(ValueError, match="requires 'region'"):
            resolve_auth_handler("sigv4", auth_config={})
