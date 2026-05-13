# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for RFC 9460 ``mandatory=`` key enforcement in the SVCB parser.

OWASP MAESTRO T7.6 — publishers declare which keys clients MUST honor; clients
that don't implement a mandatory key MUST skip the record (fail-closed).
"""

from __future__ import annotations

from dns_aid.core.discoverer import (
    _mandatory_keys_satisfied,
    _parse_mandatory_keys,
)

# ---------------------------------------------------------------------------
# _parse_mandatory_keys
# ---------------------------------------------------------------------------


def test_parse_mandatory_empty_record() -> None:
    """No mandatory param → empty list."""
    text = '1 svc.example.com. alpn="mcp" port=443'
    assert _parse_mandatory_keys(text) == []


def test_parse_mandatory_standard_keys() -> None:
    text = '1 svc.example.com. alpn="mcp" port=443 mandatory=alpn,port'
    assert _parse_mandatory_keys(text) == ["alpn", "port"]


def test_parse_mandatory_normalizes_keynnnnn_aliases() -> None:  # noqa: N802 — RFC keyNNNNN
    """key65400 → cap, key65401 → cap-sha256, etc. — normalized."""
    text = '1 svc.example.com. alpn="mcp" mandatory=alpn,key65400,key65401'
    assert _parse_mandatory_keys(text) == ["alpn", "cap", "cap-sha256"]


def test_parse_mandatory_dns_aid_human_names() -> None:
    text = "1 svc.example.com. mandatory=alpn,cap-sha256,bap"
    assert _parse_mandatory_keys(text) == ["alpn", "cap-sha256", "bap"]


# ---------------------------------------------------------------------------
# _mandatory_keys_satisfied — the gate the discoverer uses
# ---------------------------------------------------------------------------


def test_satisfied_no_mandatory_passes() -> None:
    text = '1 svc.example.com. alpn="mcp" port=443'
    ok, unknown = _mandatory_keys_satisfied(text)
    assert ok is True
    assert unknown == []


def test_satisfied_all_keys_known() -> None:
    text = '1 svc.example.com. alpn="mcp" mandatory=alpn,port,cap-sha256'
    ok, unknown = _mandatory_keys_satisfied(text)
    assert ok is True
    assert unknown == []


def test_satisfied_unknown_key_fails() -> None:
    """A publisher requiring something the SDK doesn't implement → record skipped."""
    text = '1 svc.example.com. alpn="mcp" mandatory=alpn,some-future-key'
    ok, unknown = _mandatory_keys_satisfied(text)
    assert ok is False
    assert "some-future-key" in unknown


def test_satisfied_unknown_numeric_key_fails() -> None:
    """Numeric private-use key not in DNS_AID_KEY_MAP → unknown → skip."""
    text = '1 svc.example.com. alpn="mcp" mandatory=alpn,key65500'
    ok, unknown = _mandatory_keys_satisfied(text)
    assert ok is False
    assert "key65500" in unknown


def test_satisfied_mixed_known_and_unknown() -> None:
    text = "1 svc.example.com. mandatory=alpn,cap,unknownX"
    ok, unknown = _mandatory_keys_satisfied(text)
    assert ok is False
    assert unknown == ["unknownx"]  # normalized to lowercase
