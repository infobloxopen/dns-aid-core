# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""HTTP Message Signatures auth handler (RFC 9421 / Web Bot Auth).

Supports Ed25519 (default) and ML-DSA-65 (post-quantum, via ``pqcrypto``).
"""

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

# Supported signing algorithms
SUPPORTED_ALGORITHMS = ("ed25519", "ml-dsa-65")


class _Signer(TypingProtocol):
    """Structural type for signing backends (Ed25519, ML-DSA, etc.)."""

    def sign(self, data: bytes) -> bytes: ...


logger = structlog.get_logger(__name__)


class HttpMsgSigAuthHandler(AuthHandler):
    """Sign outgoing requests per RFC 9421 (HTTP Message Signatures).

    Produces ``Signature`` and ``Signature-Input`` headers using the
    caller's private key. Supports **Ed25519** (classical) and
    **ML-DSA-65** (post-quantum, FIPS 204).

    Args:
        private_key_pem: PEM-encoded private key (Ed25519) or raw secret
            key bytes (ML-DSA-65, base64-encoded).
        key_id: Key identifier (``kid``) published in the caller's JWKS.
        algorithm: Signing algorithm. One of ``"ed25519"`` (default) or
            ``"ml-dsa-65"`` (post-quantum).
        covered_components: HTTP message components to sign.
            Defaults to ``("@method", "@target-uri", "content-digest")``.
    """

    def __init__(
        self,
        private_key_pem: str,
        key_id: str,
        *,
        algorithm: str = "ed25519",
        covered_components: tuple[str, ...] = (
            "@method",
            "@target-uri",
            "content-digest",
        ),
    ) -> None:
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: {algorithm!r}. "
                f"Supported: {', '.join(SUPPORTED_ALGORITHMS)}"
            )
        self._key_id = key_id
        self._algorithm = algorithm
        self._covered_components = covered_components
        self._signing_key: _Signer = _load_private_key(private_key_pem, algorithm)

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

        # Sign
        signature_bytes = self._signing_key.sign(sig_base.encode())
        sig_b64 = base64.b64encode(signature_bytes).decode()

        # Build Signature-Input and Signature headers
        created = int(time.time())
        components_str = " ".join(f'"{c}"' for c in self._covered_components)
        sig_input = (
            f"sig1=({components_str});created={created}"
            f';keyid="{self._key_id}";alg="{self._algorithm}"'
        )

        request.headers["signature-input"] = sig_input
        request.headers["signature"] = f"sig1=:{sig_b64}:"

        logger.debug(
            "http_msg_sig.signed",
            key_id=self._key_id,
            algorithm=self._algorithm,
            components=self._covered_components,
            signature_bytes=len(signature_bytes),
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


# ---------------------------------------------------------------------------
# Key loaders
# ---------------------------------------------------------------------------


def _load_private_key(key_material: str, algorithm: str) -> _Signer:
    """Load a private key for the given algorithm.

    Args:
        key_material: PEM-encoded key (Ed25519) or base64-encoded raw
            secret key (ML-DSA-65).
        algorithm: ``"ed25519"`` or ``"ml-dsa-65"``.
    """
    if algorithm == "ml-dsa-65":
        return _load_ml_dsa_private_key(key_material)
    return _load_ed25519_private_key(key_material)


def _load_ed25519_private_key(pem: str) -> _Signer:
    """Load an Ed25519 private key from PEM.

    Uses ``cryptography`` if available, falls back to ``nacl``.
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(pem.encode(), password=None)
        return _CryptographyEd25519Signer(key)
    except ImportError:
        pass

    try:
        import base64 as b64mod

        from nacl.encoding import RawEncoder
        from nacl.signing import SigningKey

        lines = [line for line in pem.strip().splitlines() if not line.startswith("-----")]
        raw = b64mod.b64decode("".join(lines))
        seed = raw[-32:]
        return _NaClEd25519Signer(SigningKey(seed, encoder=RawEncoder))
    except ImportError:
        raise ImportError(
            "Ed25519 signing requires either 'cryptography' or 'PyNaCl'. "
            "Install with: pip install cryptography"
        ) from None


def _load_ml_dsa_private_key(key_b64: str) -> _Signer:
    """Load an ML-DSA-65 secret key from base64-encoded raw bytes.

    Requires the ``pqcrypto`` package (FIPS 204 ML-DSA implementation).
    """
    try:
        from pqcrypto.sign import ml_dsa_65
    except ImportError:
        raise ImportError(
            "ML-DSA-65 signing requires 'pqcrypto'. Install with: pip install pqcrypto"
        ) from None

    sk = base64.b64decode(key_b64)
    expected = ml_dsa_65.SECRET_KEY_SIZE
    if len(sk) != expected:
        raise ValueError(f"ML-DSA-65 secret key must be {expected} bytes, got {len(sk)}")
    return _MlDsaSigner(sk)


# ---------------------------------------------------------------------------
# Signer adapters
# ---------------------------------------------------------------------------


class _CryptographyEd25519Signer:
    """Adapter: cryptography Ed25519PrivateKey → .sign(data) → 64-byte signature."""

    def __init__(self, private_key: Any) -> None:
        self._key = private_key

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


class _NaClEd25519Signer:
    """Adapter: PyNaCl SigningKey → .sign(data) → 64-byte signature only."""

    def __init__(self, signing_key: Any) -> None:
        self._key = signing_key

    def sign(self, data: bytes) -> bytes:
        signed = self._key.sign(data)
        return signed.signature  # 64 bytes, no message suffix


class _MlDsaSigner:
    """Adapter: pqcrypto ML-DSA-65 → .sign(data) → 3309-byte signature."""

    def __init__(self, secret_key: bytes) -> None:
        self._sk = secret_key

    def sign(self, data: bytes) -> bytes:
        from pqcrypto.sign import ml_dsa_65

        return ml_dsa_65.sign(self._sk, data)
