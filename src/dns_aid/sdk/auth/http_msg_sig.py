# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""HTTP Message Signatures auth handler (RFC 9421 / Web Bot Auth)."""

from __future__ import annotations

import base64
import hashlib
import time
from email.utils import formatdate
from typing import Any
from typing import Protocol as TypingProtocol

import httpx
import structlog

from dns_aid.sdk.auth.base import AuthHandler


class _Signer(TypingProtocol):
    """Structural type for Ed25519 signing backends."""

    def sign(self, data: bytes) -> bytes: ...


logger = structlog.get_logger(__name__)


class HttpMsgSigAuthHandler(AuthHandler):
    """Sign outgoing requests per RFC 9421 (HTTP Message Signatures).

    This handler produces ``Signature`` and ``Signature-Input`` headers
    using the caller's Ed25519 private key.  The target agent can verify
    the signature using the caller's JWKS at ``key_directory_url``.

    Args:
        private_key_pem: PEM-encoded Ed25519 private key.
        key_id: Key identifier (``kid``) published in the caller's JWKS.
        covered_components: HTTP message components to sign.
            Defaults to ``("@method", "@target-uri", "content-digest")``.
    """

    def __init__(
        self,
        private_key_pem: str,
        key_id: str,
        *,
        covered_components: tuple[str, ...] = (
            "@method",
            "@target-uri",
            "content-digest",
        ),
    ) -> None:
        self._key_id = key_id
        self._covered_components = covered_components
        self._signing_key: _Signer = _load_ed25519_private_key(private_key_pem)

    @property
    def auth_type(self) -> str:
        return "http_msg_sig"

    async def apply(self, request: httpx.Request) -> httpx.Request:
        # Ensure Date header is present (required by many signature profiles)
        if "date" not in request.headers:
            request.headers["date"] = formatdate(usegmt=True)

        # Add Content-Digest for requests with a body (RFC 9530)
        if request.content and "content-digest" not in request.headers:
            digest = hashlib.sha256(request.content).digest()
            b64 = base64.b64encode(digest).decode()
            request.headers["content-digest"] = f"sha-256=:{b64}:"

        # Build signature base string
        sig_base = _build_signature_base(request, self._covered_components)

        # Sign with Ed25519
        signature_bytes = self._signing_key.sign(sig_base.encode())
        sig_b64 = base64.b64encode(signature_bytes).decode()

        # Build Signature-Input and Signature headers
        created = int(time.time())
        components_str = " ".join(f'"{c}"' for c in self._covered_components)
        sig_input = (
            f'sig1=({components_str});created={created};keyid="{self._key_id}";alg="ed25519"'
        )

        request.headers["signature-input"] = sig_input
        request.headers["signature"] = f"sig1=:{sig_b64}:"

        logger.debug(
            "http_msg_sig.signed",
            key_id=self._key_id,
            components=self._covered_components,
        )
        return request


def _build_signature_base(
    request: httpx.Request,
    components: tuple[str, ...],
) -> str:
    """Build the signature base string per RFC 9421 §2.5."""
    lines: list[str] = []
    for component in components:
        if component == "@method":
            lines.append(f'"@method": {request.method}')
        elif component == "@target-uri":
            lines.append(f'"@target-uri": {request.url}')
        elif component == "@authority":
            lines.append(f'"@authority": {request.url.host}')
        elif component == "@path":
            lines.append(f'"@path": {request.url.raw_path.decode()}')
        else:
            # Regular header
            value = request.headers.get(component, "")
            lines.append(f'"{component}": {value}')
    return "\n".join(lines)


def _load_ed25519_private_key(pem: str) -> _Signer:
    """Load an Ed25519 private key from PEM.

    Returns an object with a ``.sign(data)`` method.
    Uses ``cryptography`` if available, falls back to ``nacl``.
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(pem.encode(), password=None)
        # Wrap to provide a simple .sign() interface
        return _CryptographyEd25519Signer(key)
    except ImportError:
        pass

    try:
        import base64 as b64mod

        from nacl.encoding import RawEncoder
        from nacl.signing import SigningKey

        # Extract raw 32-byte seed from PEM
        lines = [line for line in pem.strip().splitlines() if not line.startswith("-----")]
        raw = b64mod.b64decode("".join(lines))
        # PKCS#8 Ed25519 private key: last 32 bytes are the seed
        seed = raw[-32:]
        return _NaClEd25519Signer(SigningKey(seed, encoder=RawEncoder))
    except ImportError:
        raise ImportError(
            "HTTP Message Signatures require either 'cryptography' or 'PyNaCl'. "
            "Install with: pip install cryptography"
        ) from None


class _CryptographyEd25519Signer:
    """Adapter: cryptography Ed25519PrivateKey → .sign(data) → 64-byte signature."""

    def __init__(self, private_key: Any) -> None:
        self._key = private_key

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


class _NaClEd25519Signer:
    """Adapter: PyNaCl SigningKey → .sign(data) → 64-byte signature only.

    PyNaCl's ``SigningKey.sign()`` returns signature+message (96+ bytes).
    We strip the message suffix to return just the 64-byte Ed25519 signature,
    matching the behavior of the ``cryptography`` adapter.
    """

    def __init__(self, signing_key: Any) -> None:
        self._key = signing_key

    def sign(self, data: bytes) -> bytes:
        signed = self._key.sign(data)
        return signed.signature  # 64 bytes, no message suffix
