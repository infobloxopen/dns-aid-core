#!/usr/bin/env python3
"""
Integration Test: LangChain + DNS-AID MCP Server

Validates the LangChain integration pattern from docs/integrations.md.
Connects to DNS-AID MCP server via langchain-mcp-adapters, lists tools,
and calls discover_agents_via_dns to find the booking agent.

No LLM API key required — this tests the MCP transport only.

Usage:
    python examples/integration_langchain.py
"""

import asyncio
import sys

from langchain_mcp_adapters.client import MultiServerMCPClient


async def main() -> int:
    print("=" * 60)
    print("DNS-AID Integration Test: LangChain MCP Adapters")
    print("=" * 60)
    errors = 0

    # ── Step 1: Connect to DNS-AID MCP server ──────────────────
    print("\n[1/3] Connecting to DNS-AID MCP server via stdio...")

    client = MultiServerMCPClient(
        {
            "dns-aid": {
                "transport": "stdio",
                "command": sys.executable,
                "args": ["-m", "dns_aid.mcp.server"],
            }
        }
    )

    # ── Step 2: List available tools ────────────────────────
    print("\n[2/3] Listing MCP tools...")
    tools = await client.get_tools()
    tool_names = [t.name for t in tools]
    print(f"  OK: Got {len(tools)} tools from DNS-AID MCP server:")
    for t in tools:
        print(f"      - {t.name}: {t.description[:60]}...")

    # Verify key tools exist
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

    discover_tool = next(t for t in tools if t.name == "discover_agents_via_dns")
    result = await discover_tool.ainvoke(
        {
            "domain": "example.com",
            "protocol": "mcp",
            "name": "booking",
        }
    )

    print(f"  OK: Tool returned result ({len(str(result))} chars)")
    result_str = str(result)
    if "booking" in result_str.lower():
        print("  OK: Result contains 'booking' agent data")
    else:
        print("  FAIL: Result does not mention booking agent")
        print(f"  Got: {result_str[:200]}")
        errors += 1

    if "example.com" in result_str:
        print("  OK: Result contains domain reference")
    else:
        print("  WARN: Domain not found in result")

    # ── Summary ─────────────────────────────────────────────────
    print("\n" + "=" * 60)
    if errors == 0:
        print("ALL CHECKS PASSED — LangChain MCP integration works")
        print("\nThe docs/integrations.md LangChain example is validated.")
        print("To use with a real LLM, add langchain-anthropic and set ANTHROPIC_API_KEY.")
    else:
        print(f"FAILED — {errors} check(s) failed")
    print("=" * 60)
    return errors


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
