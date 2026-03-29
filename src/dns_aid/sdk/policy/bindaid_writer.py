# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
bind-aid policy zone writer.

Renders ``CompilationResult.bindaid_directives`` into a policy zone file
for Ingmar's BIND 9 fork (https://github.com/IngmarVG-IB/bind-aid).

bind-aid format:
  - Owner names are appended to the policy zone origin (``$ORIGIN``)
  - ``ACTION:<action>`` directives for domain-level blocking/allowing
  - ``key654xx=op:value`` directives for SvcParam operations (separate TXT records)
  - Multiple TXT records on the same owner are applied in zone file order
"""

from __future__ import annotations

import time

from dns_aid.sdk.policy.compiler import CompilationResult


def write_bindaid_zone(
    result: CompilationResult,
    zone_name: str,
    serial: int | None = None,
    ns_name: str = "localhost.",
    admin_email: str = "hostmaster.localhost.",
    ttl: int = 300,
) -> str:
    """Render a bind-aid policy zone file from compilation result.

    Owner names are written relative to ``$ORIGIN`` so that bind-aid resolves
    them as ``{owner}.{zone_name}.`` per its longest-suffix matching rules.

    Args:
        result: Compilation output from ``PolicyCompiler.compile()``.
        zone_name: Name of the policy zone (e.g., ``rdata-policy.example.com``).
        serial: SOA serial number.  Defaults to epoch seconds.
        ns_name: SOA MNAME / NS target.
        admin_email: SOA RNAME (dot-separated, not @).
        ttl: Default TTL for all records.

    Returns:
        Complete zone file as a string.
    """
    if serial is None:
        serial = int(time.time())

    lines: list[str] = []

    # Header comment
    lines.append(f"; bind-aid policy zone: {zone_name}")
    lines.append(f"; Compiled from policy for: {result.agent_fqdn}")
    lines.append(f"; Directives: {len(result.bindaid_directives)}")
    lines.append("")

    # SOA + NS
    lines.append(f"$TTL {ttl}")
    lines.append(f"$ORIGIN {zone_name}.")
    lines.append("")
    lines.append(f"@  IN  SOA  {ns_name} {admin_email} (")
    lines.append(f"    {serial}  ; serial")
    lines.append("    3600       ; refresh")
    lines.append("    900        ; retry")
    lines.append("    604800     ; expire")
    lines.append(f"    {ttl}        ; minimum")
    lines.append(")")
    lines.append("")
    lines.append(f"@  IN  NS  {ns_name}")
    lines.append("")

    # bind-aid TXT directives
    for directive in result.bindaid_directives:
        if directive.comment:
            lines.append(f"; {directive.comment}")
        if directive.source_rule:
            lines.append(f"; source: {directive.source_rule}")

        # Owner relative to $ORIGIN — bind-aid resolves as {owner}.{zone_name}.
        owner = directive.owner

        # ACTION directive (domain-level block/allow)
        lines.append(f'{owner}  {ttl}  IN  TXT  "ACTION:{directive.action.value}"')

        # SvcParam directives as separate TXT records (applied in order)
        for param_op in directive.param_ops:
            lines.append(f'{owner}  {ttl}  IN  TXT  "{param_op}"')

        lines.append("")

    return "\n".join(lines)
