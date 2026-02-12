# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
MCP server for DNS-AID - enables AI agents to publish/discover via DNS.

Usage:
    # Run as MCP server (stdio transport - default)
    dns-aid-mcp

    # Run with HTTP transport
    dns-aid-mcp --transport http --port 8000

    # Or programmatically
    from dns_aid.mcp import server
    server.mcp.run()
"""

from dns_aid.mcp.server import mcp

__all__ = ["mcp"]
