# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for ``dns_aid.core.filters.apply_filters``.

Exercises every filter primitive in isolation against fixture ``AgentRecord`` lists. No
DNS, no HTTP — pure list-comp predicates over already-enriched records.
"""

from __future__ import annotations

import pytest

from dns_aid.core.filters import apply_filters
from dns_aid.core.models import AgentRecord, Protocol


def _agent(
    name: str,
    *,
    domain: str = "example.com",
    protocol: Protocol = Protocol.MCP,
    capabilities: list[str] | None = None,
    description: str | None = None,
    use_cases: list[str] | None = None,
    category: str | None = None,
    auth_type: str | None = None,
    realm: str | None = None,
    sig: str | None = None,
    signature_verified: bool | None = None,
    signature_algorithm: str | None = None,
    dnssec_validated: bool = False,
) -> AgentRecord:
    return AgentRecord(
        name=name,
        domain=domain,
        protocol=protocol,
        target_host=f"{name}.{domain}",
        port=443,
        capabilities=capabilities or [],
        description=description,
        use_cases=use_cases or [],
        category=category,
        auth_type=auth_type,
        realm=realm,
        sig=sig,
        signature_verified=signature_verified,
        signature_algorithm=signature_algorithm,
        dnssec_validated=dnssec_validated,
    )


@pytest.fixture
def records() -> list[AgentRecord]:
    return [
        _agent(
            "payments",
            capabilities=["payment-processing", "fraud-detection"],
            description="Process card payments and refunds.",
            category="transaction",
            auth_type="oauth2",
            realm="prod",
            dnssec_validated=True,
            sig="header.payload.signature",
            signature_verified=True,
            signature_algorithm="ES256",
        ),
        _agent(
            "search",
            capabilities=["search", "ranking"],
            description="Indexed full-text search.",
            category="query",
            auth_type="api_key",
            realm="prod",
            dnssec_validated=False,
        ),
        _agent(
            "legacy",
            capabilities=["payment-processing"],
            description="Legacy payment shim.",
            category="transaction",
            auth_type="bearer",
            realm="staging",
            dnssec_validated=False,
            sig="header.payload.signature",
            signature_verified=False,
            signature_algorithm=None,
        ),
        _agent(
            "weak-sig",
            capabilities=["fraud-detection"],
            auth_type="oauth2",
            sig="header.payload.signature",
            signature_verified=True,
            signature_algorithm="HS256",
        ),
    ]


class TestNoConstraintsFastPath:
    def test_returns_input_unchanged(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records)
        assert out is records  # identity, not a copy

    def test_all_none_kwargs_short_circuits(self, records: list[AgentRecord]) -> None:
        out = apply_filters(
            records,
            capabilities=None,
            capabilities_any=None,
            auth_type=None,
            intent=None,
            transport=None,
            realm=None,
            min_dnssec=False,
            text_match=None,
            require_signed=False,
            require_signature_algorithm=None,
        )
        assert out is records


class TestCapabilities:
    def test_all_of_match(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, capabilities=["payment-processing", "fraud-detection"])
        assert [r.name for r in out] == ["payments"]

    def test_all_of_case_insensitive(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, capabilities=["PAYMENT-PROCESSING"])
        assert {r.name for r in out} == {"payments", "legacy"}

    def test_empty_list_explicit_no_match(self, records: list[AgentRecord]) -> None:
        # Per spec: empty list is "explicit no-match" — distinct from None ("no constraint").
        out = apply_filters(records, capabilities=[])
        assert out == []

    def test_empty_any_list_explicit_no_match(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, capabilities_any=[])
        assert out == []

    def test_any_of_match(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, capabilities_any=["search", "fraud-detection"])
        assert {r.name for r in out} == {"payments", "search", "weak-sig"}

    def test_no_match_returns_empty(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, capabilities=["nonexistent-cap"])
        assert out == []


class TestAuthType:
    def test_exact_match_case_insensitive(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, auth_type="OAUTH2")
        assert {r.name for r in out} == {"payments", "weak-sig"}

    def test_no_match(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, auth_type="mtls")
        assert out == []


class TestIntent:
    def test_match_against_category(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, intent="transaction")
        assert {r.name for r in out} == {"payments", "legacy"}

    def test_substring_fallback_against_capabilities(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, intent="search")
        # Matches by category (search) AND substring in capabilities (search/ranking).
        assert {r.name for r in out} == {"search"}


class TestTransport:
    def test_match_against_protocol(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, transport="mcp")
        assert len(out) == len(records)

    def test_no_match(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, transport="streamable-http")
        # Path A doesn't surface streamable-http transport; falls back to protocol value.
        assert out == []


class TestRealm:
    def test_exact_match(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, realm="prod")
        assert {r.name for r in out} == {"payments", "search"}

    def test_no_match(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, realm="missing")
        assert out == []


class TestMinDNSSEC:
    def test_excludes_unvalidated(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, min_dnssec=True)
        assert {r.name for r in out} == {"payments"}

    def test_default_keeps_unvalidated(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, min_dnssec=False)
        assert len(out) == len(records)


class TestTextMatch:
    def test_substring_in_description(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, text_match="payment")
        # Matches "Process card payments" (description), "Legacy payment shim" (description),
        # "payment-processing" (capability).
        assert {r.name for r in out} == {"payments", "legacy"}

    def test_substring_in_capabilities(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, text_match="ranking")
        assert {r.name for r in out} == {"search"}

    def test_case_insensitive(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, text_match="PAYMENT")
        assert {r.name for r in out} == {"payments", "legacy"}

    def test_empty_string_raises(self, records: list[AgentRecord]) -> None:
        with pytest.raises(ValueError, match="text_match cannot be empty"):
            apply_filters(records, text_match="")

    def test_missing_description_safe(self) -> None:
        agent = _agent("noop", description=None, use_cases=[], capabilities=["x"])
        out = apply_filters([agent], text_match="missing")
        assert out == []


class TestRequireSigned:
    def test_only_verified_records_pass(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, require_signed=True)
        assert {r.name for r in out} == {"payments", "weak-sig"}

    def test_unsigned_records_excluded(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, require_signed=True)
        assert "search" not in {r.name for r in out}

    def test_failed_verification_excluded(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, require_signed=True)
        assert "legacy" not in {r.name for r in out}


class TestRequireSignatureAlgorithm:
    def test_allow_list_match(self, records: list[AgentRecord]) -> None:
        out = apply_filters(
            records,
            require_signed=True,
            require_signature_algorithm=["ES256", "Ed25519"],
        )
        assert {r.name for r in out} == {"payments"}

    def test_allow_list_excludes_weak_algorithm(self, records: list[AgentRecord]) -> None:
        out = apply_filters(
            records,
            require_signed=True,
            require_signature_algorithm=["ES256"],
        )
        assert "weak-sig" not in {r.name for r in out}

    def test_algorithm_match_case_insensitive(self, records: list[AgentRecord]) -> None:
        out = apply_filters(
            records,
            require_signed=True,
            require_signature_algorithm=["es256"],
        )
        assert {r.name for r in out} == {"payments"}

    def test_algorithm_without_require_signed_raises(self, records: list[AgentRecord]) -> None:
        with pytest.raises(ValueError, match="require_signed=True"):
            apply_filters(
                records,
                require_signature_algorithm=["ES256"],
            )


class TestComposite:
    def test_multiple_filters_combined(self, records: list[AgentRecord]) -> None:
        out = apply_filters(
            records,
            capabilities=["payment-processing"],
            auth_type="oauth2",
            min_dnssec=True,
            require_signed=True,
        )
        assert {r.name for r in out} == {"payments"}

    def test_returns_new_list_when_filtering(self, records: list[AgentRecord]) -> None:
        out = apply_filters(records, capabilities=["payment-processing"])
        assert out is not records
