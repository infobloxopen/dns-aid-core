# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""AWS SigV4 auth handler for VPC Lattice and API Gateway IAM auth."""

from __future__ import annotations

from io import BytesIO
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from dns_aid.sdk.auth.base import AuthHandler

logger = structlog.get_logger(__name__)

# Headers that SigV4 produces and we copy back to the httpx request.
_SIGV4_HEADERS = ("authorization", "x-amz-date", "x-amz-security-token", "x-amz-content-sha256")


class SigV4AuthHandler(AuthHandler):
    """Sign requests with AWS Signature Version 4.

    Used for agents behind **VPC Lattice** (``connect-class=lattice``)
    or **API Gateway with IAM auth**.

    Credentials are resolved via the standard boto3 credential chain
    (env vars → config files → IAM role → instance metadata).

    Args:
        region: AWS region (e.g., ``"us-east-1"``).
        service: AWS service name for signing scope.  Defaults to
            ``"vpc-lattice-svcs"`` for VPC Lattice.  Use
            ``"execute-api"`` for API Gateway.
        profile_name: Optional AWS profile name for credential resolution.
    """

    def __init__(
        self,
        region: str,
        *,
        service: str = "vpc-lattice-svcs",
        profile_name: str | None = None,
    ) -> None:
        self._region = region
        self._service = service
        self._signer, self._credentials = _create_signer(region, service, profile_name)

    @property
    def auth_type(self) -> str:
        return "sigv4"

    async def apply(self, request: httpx.Request) -> httpx.Request:
        # Refresh credentials if they're from an assumed role / instance profile
        frozen = self._credentials.get_frozen_credentials()
        self._signer, _ = _create_signer_from_frozen(frozen, self._region, self._service)

        aws_request = _httpx_to_aws_request(request)
        self._signer.add_auth(aws_request)

        # Copy SigV4 headers back to httpx request
        for header in _SIGV4_HEADERS:
            value = aws_request.headers.get(header)
            if value:
                request.headers[header] = value

        logger.debug(
            "sigv4.signed",
            service=self._service,
            region=self._region,
            method=request.method,
        )
        return request


def _create_signer(region: str, service: str, profile_name: str | None) -> tuple[Any, Any]:
    """Create a SigV4Auth signer from boto3 session credentials."""
    try:
        import boto3
        from botocore.auth import SigV4Auth
    except ImportError:
        raise ImportError(
            "SigV4 signing requires 'boto3'. Install with: pip install dns-aid[route53]"
        ) from None

    session = boto3.Session(profile_name=profile_name)
    credentials = session.get_credentials()
    if not credentials:
        raise ValueError(
            "No AWS credentials found. Configure via environment variables, "
            "AWS config files, or IAM role."
        )
    frozen = credentials.get_frozen_credentials()
    signer = SigV4Auth(frozen, service, region)
    return signer, credentials


def _create_signer_from_frozen(frozen: Any, region: str, service: str) -> tuple[Any, Any]:
    """Create a SigV4Auth signer from already-frozen credentials."""
    from botocore.auth import SigV4Auth

    return SigV4Auth(frozen, service, region), frozen


def _httpx_to_aws_request(request: httpx.Request) -> Any:
    """Convert an httpx Request to a botocore AWSRequest for signing."""
    from botocore.awsrequest import AWSRequest

    parsed = urlparse(str(request.url))
    url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        url = f"{url}?{parsed.query}"

    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}

    return AWSRequest(
        method=request.method,
        url=url,
        headers=headers,
        data=BytesIO(request.content) if request.content else None,
    )
