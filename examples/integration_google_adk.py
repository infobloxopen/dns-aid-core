#!/usr/bin/env python3
"""
Integration Test: Google ADK + DNS-AID MCP Server

Validates the Google ADK integration pattern from docs/integrations.md.
Connects to DNS-AID MCP server via McpToolset, lists tools,
and calls discover_agents_via_dns to find the booking agent.

No Gemini API key required — this tests the MCP transport only.

Usage:
    python examples/integration_google_adk.py
"""

import asyncio
import sys

from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters


async def main() -> int:
    print("=" * 60)
    print("DNS-AID Integration Test: Google ADK")
    print("=" * 60)
    errors = 0

    # ── Step 1: Connect to DNS-AID MCP server ──────────────────
    print("\n[1/3] Connecting to DNS-AID MCP server via McpToolset...")

    toolset = McpToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command=sys.executable,
                args=["-m", "dns_aid.mcp.server"],
            ),
            timeout=30,
        )
    )

    tools = await toolset.get_tools()
    print(f"  OK: Connected and loaded {len(tools)} tools")

    # ── Step 2: List available tools ────────────────────────────
    print("\n[2/3] Listing MCP tools...")
    tool_names = [t.name for t in tools]
    for t in tools:
        desc = t.description or ""
        print(f"      - {t.name}: {desc[:60]}...")

    expected = {"discover_agents_via_dns", "publish_agent_to_dns", "verify_agent_dns"}
    missing = expected - set(tool_names)
    if missing:
        print(f"  FAIL: Missing expected tools: {missing}")
        errors += 1
    else:
        print(f"  OK: All expected tools present ({', '.join(sorted(expected))})")

    # ── Step 3: Call discover_agents_via_dns ────────────────────
    print("\n[3/3] Calling discover_agents_via_dns for booking agent...")

    # Use the session manager to get an MCP session and call the tool directly
    session = await toolset._mcp_session_manager.create_session()
    result = await session.call_tool(
        "discover_agents_via_dns",
        {
            "domain": "example.com",
            "protocol": "mcp",
            "name": "booking",
        },
    )

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

    # Clean up
    toolset.close()

    # ── Summary ─────────────────────────────────────────────────
    print("\n" + "=" * 60)
    if errors == 0:
        print("ALL CHECKS PASSED — Google ADK MCP integration works")
        print("\nThe docs/integrations.md Google ADK example is validated.")
        print("To use with a real LLM, set GOOGLE_API_KEY and create an Agent.")
    else:
        print(f"FAILED — {errors} check(s) failed")
    print("=" * 60)
    return errors


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
