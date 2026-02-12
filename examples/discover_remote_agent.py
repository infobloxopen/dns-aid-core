#!/usr/bin/env python3
"""
Example: Discover and connect to a DNS-AID published agent.

This script demonstrates how any agent can discover another agent
using only DNS - no hardcoded URLs needed!

Usage:
    python discover_remote_agent.py example.com multiagent a2a

Or with defaults:
    python discover_remote_agent.py
"""

import argparse
import asyncio
import sys

import dns.resolver
import httpx


async def discover_agent(domain: str, agent_name: str, protocol: str):
    """
    Discover an agent via DNS and connect to it.

    This is what any external agent would do to find your agent.
    """
    fqdn = f"_{agent_name}._{protocol}._agents.{domain}"

    print("=" * 60)
    print("DNS-AID AGENT DISCOVERY")
    print("=" * 60)

    # === STEP 1: DNS DISCOVERY ===
    print("\n🔍 STEP 1: Querying DNS")
    print(f"   FQDN: {fqdn}")

    try:
        # Query SVCB record
        answers = dns.resolver.resolve(fqdn, "SVCB")

        for rdata in answers:
            target = str(rdata.target).rstrip(".")
            port_param = rdata.params.get(3)  # Port param key
            port = port_param.port if port_param else 443

            print("\n   ✓ SVCB Record Found:")
            print(f"     Priority: {rdata.priority}")
            print(f"     Target: {target}")
            print(f"     Port: {port}")

            endpoint = f"https://{target}:{port}"

    except dns.resolver.NXDOMAIN:
        print(f"\n   ✗ No DNS record found for {fqdn}")
        print("     Make sure the agent is published to DNS first!")
        sys.exit(1)
    except Exception as e:
        print(f"\n   ✗ DNS query failed: {e}")
        sys.exit(1)

    # Query TXT for capabilities
    try:
        txt_answers = dns.resolver.resolve(fqdn, "TXT")
        capabilities = []
        version = "unknown"

        for rdata in txt_answers:
            for txt in rdata.strings:
                txt_str = txt.decode()
                if txt_str.startswith("capabilities="):
                    capabilities = txt_str.split("=")[1].split(",")
                elif txt_str.startswith("version="):
                    version = txt_str.split("=")[1]

        print("\n   ✓ TXT Record Found:")
        print(f"     Capabilities: {', '.join(capabilities)}")
        print(f"     Version: {version}")

    except Exception:
        print("\n   ○ No TXT record (capabilities unknown)")

    # === STEP 2: CONNECT TO AGENT ===
    print("\n🔗 STEP 2: Connecting to discovered endpoint")
    print(f"   Endpoint: {endpoint}")

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        # Check health
        try:
            resp = await client.get(f"{endpoint}/health")
            health = resp.json()
            print("\n   ✓ Health Check:")
            print(f"     Status: {health.get('status', 'unknown')}")
        except Exception as e:
            print(f"\n   ✗ Health check failed: {e}")

        # Fetch A2A agent card
        try:
            resp = await client.get(f"{endpoint}/.well-known/agent.json")
            agent_card = resp.json()

            print("\n   ✓ A2A Agent Card:")
            print(f"     Name: {agent_card.get('name', 'unknown')}")
            print(f"     Description: {agent_card.get('description', 'N/A')[:60]}...")
            print(f"     Version: {agent_card.get('version', 'unknown')}")

            if "skills" in agent_card:
                print("     Skills:")
                for skill in agent_card["skills"]:
                    tools = skill.get("tools_count", "?")
                    print(f"       - {skill['name']} ({tools} tools)")

        except Exception as e:
            print(f"\n   ○ No A2A agent card: {e}")

        # === STEP 3: EXAMPLE INTERACTION ===
        print("\n💬 STEP 3: Example interaction")

        # Try to list available endpoints
        try:
            resp = await client.get(f"{endpoint}/api/registry")
            if resp.status_code == 200:
                registry = resp.json()
                print("\n   ✓ Agent Registry:")
                if isinstance(registry, dict) and "agents" in registry:
                    for agent in registry.get("agents", [])[:3]:
                        name = agent.get("name", "unknown")
                        status = agent.get("status", "unknown")
                        print(f"       - {name}: {status}")
        except Exception:
            pass

    print("\n" + "=" * 60)
    print("✅ DISCOVERY COMPLETE")
    print("=" * 60)
    print(f"\nThe agent at {domain} was discovered via DNS!")
    print("No hardcoded URLs were used - just DNS queries.")
    print("\nThis is the power of DNS-AID: decentralized agent discovery.")


def main():
    parser = argparse.ArgumentParser(
        description="Discover a DNS-AID published agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com multiagent a2a
  %(prog)s example.com chat mcp
  %(prog)s  # uses defaults
        """,
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default="example.com",
        help="Domain to search (default: example.com)",
    )
    parser.add_argument(
        "agent_name",
        nargs="?",
        default="multiagent",
        help="Agent name (default: multiagent)",
    )
    parser.add_argument(
        "protocol",
        nargs="?",
        default="a2a",
        choices=["a2a", "mcp"],
        help="Protocol (default: a2a)",
    )

    args = parser.parse_args()

    asyncio.run(discover_agent(args.domain, args.agent_name, args.protocol))


if __name__ == "__main__":
    main()
