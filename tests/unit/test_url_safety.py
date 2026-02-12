"""Tests for URL safety validation (SSRF protection)."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from dns_aid.utils.url_safety import UnsafeURLError, validate_fetch_url


class TestValidateFetchUrl:
    """Tests for validate_fetch_url()."""

    def test_https_url_passes(self):
        """HTTPS URLs with public hosts should pass."""
        # Use a well-known public DNS name
        url = "https://example.com/cap.json"
        # Will resolve to public IP, should pass
        result = validate_fetch_url(url)
        assert result == url

    def test_http_url_blocked(self):
        """HTTP (non-HTTPS) URLs must be blocked."""
        with pytest.raises(UnsafeURLError, match="Only HTTPS"):
            validate_fetch_url("http://example.com/cap.json")

    def test_file_scheme_blocked(self):
        """file:// scheme must be blocked."""
        with pytest.raises(UnsafeURLError, match="Only HTTPS"):
            validate_fetch_url("file:///etc/passwd")

    def test_ftp_scheme_blocked(self):
        """ftp:// scheme must be blocked."""
        with pytest.raises(UnsafeURLError, match="Only HTTPS"):
            validate_fetch_url("ftp://evil.com/data")

    def test_no_hostname_blocked(self):
        """URLs without a hostname must be blocked."""
        with pytest.raises(UnsafeURLError, match="no hostname"):
            validate_fetch_url("https://")

    def test_loopback_ipv4_blocked(self):
        """127.0.0.1 must be blocked."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://127.0.0.1/secret")

    def test_loopback_localhost_blocked(self):
        """localhost must be blocked (resolves to 127.0.0.1)."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://localhost/secret")

    def test_private_ip_10_blocked(self):
        """10.x.x.x private IPs must be blocked."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://10.0.0.1/internal")

    def test_private_ip_172_blocked(self):
        """172.16.x.x private IPs must be blocked."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://172.16.0.1/internal")

    def test_private_ip_192_blocked(self):
        """192.168.x.x private IPs must be blocked."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://192.168.1.1/admin")

    def test_link_local_blocked(self):
        """169.254.x.x (AWS metadata) must be blocked."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://169.254.169.254/latest/meta-data/")

    def test_unresolvable_hostname(self):
        """Unresolvable hostnames should raise UnsafeURLError."""
        with pytest.raises(UnsafeURLError, match="Cannot resolve"):
            validate_fetch_url("https://this-domain-definitely-does-not-exist-12345.invalid/cap")

    def test_allowlist_bypasses_ip_check(self):
        """Hosts in DNS_AID_FETCH_ALLOWLIST should bypass IP checks."""
        with patch.dict(os.environ, {"DNS_AID_FETCH_ALLOWLIST": "localhost,127.0.0.1"}):
            # localhost would normally be blocked, but allowlist overrides
            result = validate_fetch_url("https://localhost/test")
            assert result == "https://localhost/test"

    def test_allowlist_case_insensitive(self):
        """Allowlist matching should be case-insensitive."""
        with patch.dict(os.environ, {"DNS_AID_FETCH_ALLOWLIST": "LocalHost"}):
            result = validate_fetch_url("https://localhost/test")
            assert result == "https://localhost/test"


class TestCapSha256Verification:
    """Tests for cap_sha256 integrity verification in cap_fetcher."""

    @pytest.mark.asyncio
    async def test_hash_match_passes(self):
        """Correct hash should allow document to be returned."""
        import base64
        import hashlib

        from unittest.mock import AsyncMock

        import httpx

        from dns_aid.core.cap_fetcher import fetch_cap_document

        content = b'{"capabilities": ["test"]}'
        expected_hash = (
            base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
        )

        mock_response = AsyncMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.content = content
        mock_response.json.return_value = {"capabilities": ["test"]}

        with patch("dns_aid.utils.url_safety.validate_fetch_url", return_value="https://ok.com"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client_cls.return_value = mock_client

                doc = await fetch_cap_document(
                    "https://ok.com/cap.json",
                    expected_sha256=expected_hash,
                )
                assert doc is not None
                assert doc.capabilities == ["test"]

    @pytest.mark.asyncio
    async def test_hash_mismatch_returns_none(self):
        """Wrong hash should cause fetch to return None."""
        from unittest.mock import AsyncMock

        import httpx

        from dns_aid.core.cap_fetcher import fetch_cap_document

        content = b'{"capabilities": ["test"]}'

        mock_response = AsyncMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.content = content
        mock_response.json.return_value = {"capabilities": ["test"]}

        with patch("dns_aid.utils.url_safety.validate_fetch_url", return_value="https://ok.com"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client_cls.return_value = mock_client

                doc = await fetch_cap_document(
                    "https://ok.com/cap.json",
                    expected_sha256="WRONG_HASH",
                )
                assert doc is None

    @pytest.mark.asyncio
    async def test_no_hash_skips_verification(self):
        """When expected_sha256 is None, skip verification."""
        from unittest.mock import AsyncMock

        import httpx

        from dns_aid.core.cap_fetcher import fetch_cap_document

        content = b'{"capabilities": ["test"]}'

        mock_response = AsyncMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.content = content
        mock_response.json.return_value = {"capabilities": ["test"]}

        with patch("dns_aid.utils.url_safety.validate_fetch_url", return_value="https://ok.com"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client_cls.return_value = mock_client

                doc = await fetch_cap_document(
                    "https://ok.com/cap.json",
                    expected_sha256=None,
                )
                assert doc is not None
                assert doc.capabilities == ["test"]
