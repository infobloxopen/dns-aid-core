#!/usr/bin/env python3
"""
Integration Test: OpenAI Agents SDK + DNS-AID MCP Server

Validates the OpenAI Agents SDK integration pattern from docs/integrations.md.
Connects to DNS-AID MCP server via MCPServerStdio, lists tools,
and calls discover_agents_via_dns to find the booking agent.

No OpenAI API key required — this tests the MCP transport only.

Usage:
    python examples/integration_openai_agents.py
"""

import asyncio
import sys

from agents.mcp import MCPServerStdio


async def main() -> int:
    print("=" * 60)
    print("DNS-AID Integration Test: OpenAI Agents SDK")
    print("=" * 60)
    errors = 0

    # ── Step 1: Connect to DNS-AID MCP server ──────────────────
    print("\n[1/3] Connecting to DNS-AID MCP server via MCPServerStdio...")

    server = MCPServerStdio(
        params={
            "command": sys.executable,
            "args": ["-m", "dns_aid.mcp.server"],
        },
    )

    async with server:
        # ── Step 2: List available tools ────────────────────────
        print("\n[2/3] Listing MCP tools...")
        tools = await server.list_tools()
        tool_names = [t.name for t in tools]
        print(f"  OK: Got {len(tools)} tools from DNS-AID MCP server:")
        for t in tools:
            desc = t.description or ""
            print(f"      - {t.name}: {desc[:60]}...")

        expected = {"discover_agents_via_dns", "publish_agent_to_dns", "verify_agent_dns"}
        found = expected.intersection(set(tool_names))
        missing = expected - found
        if missing:
            print(f"  FAIL: Missing expected tools: {missing}")
            errors += 1
        else:
            print(f"  OK: All expected tools present ({', '.join(sorted(expected))})")

        # ── Step 3: Call discover_agents_via_dns ────────────────
        print("\n[3/3] Calling discover_agents_via_dns for booking agent...")

        result = await server.call_tool(
            "discover_agents_via_dns",
            {
                "domain": "example.com",
                "protocol": "mcp",
                "name": "booking",
            },
        )

        # result is a CallToolResult with content list
        result_text = ""
        for content in result.content:
            if hasattr(content, "text"):
                result_text += content.text

        print(f"  OK: Tool returned result ({len(result_text)} chars)")

        if "booking" in result_text.lower():
            print("  OK: Result contains 'booking' agent data")
        else:
            print("  FAIL: Result does not mention booking agent")
            print(f"  Got: {result_text[:200]}")
            errors += 1

        if "example.com" in result_text:
            print("  OK: Result contains domain reference")
        else:
            print("  WARN: Domain not found in result")

    # ── Summary ─────────────────────────────────────────────────
    print("\n" + "=" * 60)
    if errors == 0:
        print("ALL CHECKS PASSED — OpenAI Agents SDK integration works")
        print("\nThe docs/integrations.md OpenAI Agents example is validated.")
        print("To use with a real LLM, set OPENAI_API_KEY and create an Agent.")
    else:
        print(f"FAILED — {errors} check(s) failed")
    print("=" * 60)
    return errors


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
