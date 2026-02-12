# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for A2A and HTTPS protocol handlers."""

from __future__ import annotations

import httpx
import pytest

from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.a2a import A2AProtocolHandler
from dns_aid.sdk.protocols.https import HTTPSProtocolHandler


class TestA2AProtocolHandler:
    @pytest.fixture
    def handler(self) -> A2AProtocolHandler:
        return A2AProtocolHandler()

    def test_protocol_name(self, handler: A2AProtocolHandler) -> None:
        assert handler.protocol_name == "a2a"

    @pytest.mark.asyncio
    async def test_success(self, handler: A2AProtocolHandler) -> None:
        mock_resp = httpx.Response(200, json={"task_id": "abc", "result": "done"})
        transport = httpx.MockTransport(lambda req: mock_resp)

        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://a2a.example.com/agent",
                method="task",
                arguments={"input": "hello"},
                timeout=5.0,
            )

        assert raw.success is True
        assert raw.status == InvocationStatus.SUCCESS
        assert raw.data == {"task_id": "abc", "result": "done"}

    @pytest.mark.asyncio
    async def test_server_error(self, handler: A2AProtocolHandler) -> None:
        mock_resp = httpx.Response(500, text="Internal Error")
        transport = httpx.MockTransport(lambda req: mock_resp)

        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://a2a.example.com/agent",
                method=None,
                arguments=None,
                timeout=5.0,
            )

        assert raw.success is False
        assert raw.http_status_code == 500

    @pytest.mark.asyncio
    async def test_timeout(self, handler: A2AProtocolHandler) -> None:
        def raise_timeout(req: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out")

        transport = httpx.MockTransport(raise_timeout)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://a2a.example.com/agent",
                method="task",
                arguments=None,
                timeout=0.1,
            )

        assert raw.status == InvocationStatus.TIMEOUT


class TestHTTPSProtocolHandler:
    @pytest.fixture
    def handler(self) -> HTTPSProtocolHandler:
        return HTTPSProtocolHandler()

    def test_protocol_name(self, handler: HTTPSProtocolHandler) -> None:
        assert handler.protocol_name == "https"

    @pytest.mark.asyncio
    async def test_success(self, handler: HTTPSProtocolHandler) -> None:
        mock_resp = httpx.Response(200, json={"status": "ok"})
        transport = httpx.MockTransport(lambda req: mock_resp)

        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://api.example.com",
                method="invoke",
                arguments={"key": "value"},
                timeout=5.0,
            )

        assert raw.success is True
        assert raw.data == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_method_appended_to_url(self, handler: HTTPSProtocolHandler) -> None:
        captured_url = {}

        def capture(req: httpx.Request) -> httpx.Response:
            captured_url["url"] = str(req.url)
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(capture)
        async with httpx.AsyncClient(transport=transport) as client:
            await handler.invoke(
                client=client,
                endpoint="https://api.example.com/v1",
                method="execute",
                arguments=None,
                timeout=5.0,
            )

        assert captured_url["url"] == "https://api.example.com/v1/execute"

    @pytest.mark.asyncio
    async def test_no_method(self, handler: HTTPSProtocolHandler) -> None:
        captured_url = {}

        def capture(req: httpx.Request) -> httpx.Response:
            captured_url["url"] = str(req.url)
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(capture)
        async with httpx.AsyncClient(transport=transport) as client:
            await handler.invoke(
                client=client,
                endpoint="https://api.example.com/v1",
                method=None,
                arguments=None,
                timeout=5.0,
            )

        assert captured_url["url"] == "https://api.example.com/v1"

    @pytest.mark.asyncio
    async def test_connection_refused(self, handler: HTTPSProtocolHandler) -> None:
        def raise_error(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        transport = httpx.MockTransport(raise_error)
        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://api.example.com",
                method=None,
                arguments=None,
                timeout=5.0,
            )

        assert raw.status == InvocationStatus.REFUSED

    @pytest.mark.asyncio
    async def test_plain_text_response(self, handler: HTTPSProtocolHandler) -> None:
        mock_resp = httpx.Response(
            200, content=b"plain text", headers={"content-type": "text/plain"}
        )
        transport = httpx.MockTransport(lambda req: mock_resp)

        async with httpx.AsyncClient(transport=transport) as client:
            raw = await handler.invoke(
                client=client,
                endpoint="https://api.example.com",
                method=None,
                arguments=None,
                timeout=5.0,
            )

        assert raw.success is True
        assert raw.data == "plain text"
