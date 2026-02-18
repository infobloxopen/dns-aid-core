# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from dns_aid.backends.infoblox.nios import InfobloxNIOSBackend


@pytest.mark.parametrize(
    ("kwargs", "error_match"),
    [
        ({"host": "", "username": "admin", "password": "secret"}, "NIOS host required"),
        ({"host": "nios.local", "username": "", "password": "secret"}, "NIOS username required"),
        ({"host": "nios.local", "username": "admin", "password": ""}, "NIOS password required"),
    ],
)
def test_constructor_validation_errors(kwargs: dict[str, str], error_match: str) -> None:
    with pytest.raises(ValueError, match=error_match):
        InfobloxNIOSBackend(**kwargs)


def test_svc_parameters_conversion() -> None:
    params = {
        "mandatory": "alpn,port,cap",
        "alpn": "h2,h3",
        "port": "443",
        "bap": "mcp/1,a2a/1",
        "cap": "https://example.com/.well-known/agent-cap.json",
        "sig": "abc123",
    }

    converted = InfobloxNIOSBackend._svc_parameters_from_params(params)
    as_map = {item["svc_key"]: item for item in converted}

    assert as_map["alpn"]["svc_value"] == ["h2", "h3"]
    assert as_map["alpn"]["mandatory"] is True
    assert as_map["key65003"]["svc_value"] == ["mcp/1", "a2a/1"]
    assert as_map["port"]["svc_value"] == ["443"]
    assert as_map["key65001"]["mandatory"] is True
    assert as_map["key65006"]["svc_value"] == ["abc123"]


def test_svc_parameters_conversion_preserves_numeric_keys() -> None:
    converted = InfobloxNIOSBackend._svc_parameters_from_params(
        {"mandatory": "key65003,port", "key65003": "mcp/1,a2a/1", "port": "443"}
    )
    as_map = {item["svc_key"]: item for item in converted}

    assert as_map["key65003"]["mandatory"] is True
    assert as_map["key65003"]["svc_value"] == ["mcp/1", "a2a/1"]
    assert as_map["port"]["mandatory"] is True


@pytest.mark.asyncio
async def test_create_svcb_record_payload_contains_mapped_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")
    calls: list[tuple[str, str, dict | None]] = []

    async def fake_find_record_ref(zone: str, name: str, record_type: str) -> None:
        return None

    async def fake_request(
        method: str,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        json: dict | None = None,
    ) -> dict:
        calls.append((method, endpoint, json))
        return {}

    monkeypatch.setattr(backend, "_find_record_ref", fake_find_record_ref)
    monkeypatch.setattr(backend, "_request", fake_request)

    await backend.create_svcb_record(
        zone="example.com",
        name="_agent._mcp._agents",
        priority=1,
        target="mcp.example.com",
        params={"mandatory": "alpn,port", "alpn": "mcp", "port": "443", "realm": "prod"},
        ttl=900,
    )

    assert calls
    method, endpoint, payload = calls[0]
    assert method == "POST"
    assert endpoint == "record:svcb"
    assert payload is not None
    assert payload["priority"] == 1
    assert payload["target_name"] == "mcp.example.com"
    assert payload["ttl"] == 900
    assert payload["use_ttl"] is True
    assert payload["view"] == "default"
    assert any(param["svc_key"] == "key65005" for param in payload["svc_parameters"])


@pytest.mark.asyncio
async def test_find_record_ref_does_not_use_ref_return_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")

    async def fake_request(
        method: str,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        json: dict | None = None,
    ) -> list[dict[str, str]]:
        assert method == "GET"
        assert endpoint == "record:svcb"
        assert params is not None
        assert "_return_fields" not in params
        return [{"_ref": "record:svcb/ZG5z..."}]

    monkeypatch.setattr(backend, "_request", fake_request)
    ref = await backend._find_record_ref("example.com", "_agent._mcp._agents", "SVCB")
    assert ref == "record:svcb/ZG5z..."


@pytest.mark.asyncio
async def test_strict_fail_on_svcb_validation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")

    async def fake_find_record_ref(zone: str, name: str, record_type: str) -> None:
        return None

    async def fake_request(
        method: str,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        json: dict | None = None,
    ) -> dict:
        raise RuntimeError("NIOS validation failed: invalid svc_key cap")

    monkeypatch.setattr(backend, "_find_record_ref", fake_find_record_ref)
    monkeypatch.setattr(backend, "_request", fake_request)

    with pytest.raises(RuntimeError, match="validation failed"):
        await backend.create_svcb_record(
            zone="example.com",
            name="_agent._mcp._agents",
            priority=1,
            target="mcp.example.com",
            params={"mandatory": "alpn,port", "alpn": "mcp", "port": "443", "cap": "https://x"},
        )


@pytest.mark.asyncio
async def test_txt_create_and_update_upsert(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")
    calls: list[tuple[str, str, dict | None]] = []

    async def fake_request(
        method: str,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        json: dict | None = None,
    ) -> dict:
        calls.append((method, endpoint, json))
        return {}

    monkeypatch.setattr(backend, "_request", fake_request)

    async def missing_ref(zone: str, name: str, record_type: str) -> None:
        return None

    monkeypatch.setattr(backend, "_find_record_ref", missing_ref)
    await backend.create_txt_record("example.com", "_agent._mcp._agents", ["capabilities=chat"], ttl=1200)
    assert calls[-1][0] == "POST"
    assert calls[-1][1] == "record:txt"

    async def existing_ref(zone: str, name: str, record_type: str) -> str:
        return "record:txt/ZG5z..."

    monkeypatch.setattr(backend, "_find_record_ref", existing_ref)
    await backend.create_txt_record("example.com", "_agent._mcp._agents", ["version=1.0.0"], ttl=1200)
    assert calls[-1][0] == "PUT"
    assert calls[-1][1] == "record:txt/ZG5z..."


@pytest.mark.asyncio
async def test_delete_record_found_and_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")
    calls: list[tuple[str, str]] = []

    async def fake_request(
        method: str,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        json: dict | None = None,
    ) -> dict:
        calls.append((method, endpoint))
        return {}

    monkeypatch.setattr(backend, "_request", fake_request)

    async def found_ref(zone: str, name: str, record_type: str) -> str:
        return "record:svcb/ZG5z..."

    monkeypatch.setattr(backend, "_find_record_ref", found_ref)
    deleted = await backend.delete_record("example.com", "_agent._mcp._agents", "SVCB")
    assert deleted is True
    assert calls[-1] == ("DELETE", "record:svcb/ZG5z...")

    async def missing_ref(zone: str, name: str, record_type: str) -> None:
        return None

    monkeypatch.setattr(backend, "_find_record_ref", missing_ref)
    deleted = await backend.delete_record("example.com", "_agent._mcp._agents", "SVCB")
    assert deleted is False


@pytest.mark.asyncio
async def test_zone_exists_true_false(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")

    async def request_found(
        method: str,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        json: dict | None = None,
    ) -> list[dict[str, str]]:
        return [{"_ref": "zone_auth/ZG5z..."}]

    monkeypatch.setattr(backend, "_request", request_found)
    assert await backend.zone_exists("example.com") is True

    async def request_missing(
        method: str,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        json: dict | None = None,
    ) -> list[dict[str, str]]:
        return []

    monkeypatch.setattr(backend, "_request", request_missing)
    assert await backend.zone_exists("example.com") is False


@pytest.mark.asyncio
async def test_list_zones_returns_normalized_zone_objects(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")

    async def fake_request(
        method: str,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        json: dict | None = None,
    ) -> list[dict[str, object]]:
        assert method == "GET"
        assert endpoint == "zone_auth"
        assert params is not None
        assert params["view"] == "default"
        assert "_return_fields" not in params
        return [
            {
                "_ref": "zone_auth/ZG5zLmF1dGhfem9uZSQuX2RlZmF1bHQuZXhhbXBsZS5jb20:example.com/default",
                "fqdn": "example.com.",
                "view": "default",
                "comment": "Primary zone",
                "disable": False,
                "zone_format": "FORWARD",
            }
        ]

    monkeypatch.setattr(backend, "_request", fake_request)
    zones = await backend.list_zones()

    assert len(zones) == 1
    assert zones[0]["name"] == "example.com"
    assert zones[0]["fqdn"] == "example.com."
    assert zones[0]["view"] == "default"
    assert zones[0]["comment"] == "Primary zone"
    assert zones[0]["zone_format"] == "FORWARD"


@pytest.mark.asyncio
async def test_list_records_normalization(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")

    async def fake_request(
        method: str,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        json: dict | None = None,
    ) -> list[dict[str, object]]:
        if endpoint == "record:svcb":
            return [
                {
                    "_ref": "record:svcb/abc",
                    "name": "_agent._mcp._agents.example.com",
                    "ttl": 3600,
                    "priority": 1,
                    "target_name": "mcp.example.com",
                    "svc_parameters": [
                        {"svc_key": "alpn", "svc_value": ["mcp"], "mandatory": True},
                        {"svc_key": "port", "svc_value": ["443"], "mandatory": True},
                        {"svc_key": "key65005", "svc_value": ["prod"], "mandatory": False},
                    ],
                }
            ]

        return [
            {
                "_ref": "record:txt/def",
                "name": "_agent._mcp._agents.example.com",
                "ttl": 3600,
                "text": '"capabilities=chat" "version=1.0.0"',
            }
        ]

    monkeypatch.setattr(backend, "_request", fake_request)

    records = [record async for record in backend.list_records("example.com")]

    assert len(records) == 2
    assert records[0]["type"] == "SVCB"
    assert records[1]["type"] == "TXT"
    assert records[0]["fqdn"] == "_agent._mcp._agents.example.com"
    assert 'port="443"' in records[0]["values"][0]
    assert 'realm="prod"' in records[0]["values"][0]
