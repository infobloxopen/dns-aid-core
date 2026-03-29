# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Standard RPZ zone file writer.

Renders ``CompilationResult.rpz_directives`` into a valid RFC 8010 Response
Policy Zone file with SOA, NS, and CNAME records.
"""

from __future__ import annotations

import time

from dns_aid.sdk.policy.compiler import CompilationResult, RPZAction

# CNAME targets per RPZ action (RFC 8010 §2)
_RPZ_CNAME_TARGET: dict[RPZAction, str] = {
    RPZAction.NXDOMAIN: ".",
    RPZAction.NODATA: "*.",
    RPZAction.PASSTHRU: "rpz-passthru.",
    RPZAction.DROP: "rpz-drop.",
}


def write_rpz_zone(
    result: CompilationResult,
    zone_name: str,
    serial: int | None = None,
    ns_name: str = "localhost.",
    admin_email: str = "hostmaster.localhost.",
    ttl: int = 300,
) -> str:
    """Render an RPZ zone file from compilation result.

    Args:
        result: Compilation output from ``PolicyCompiler.compile()``.
        zone_name: Name of the RPZ zone (e.g., ``rpz.example.com``).
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
    lines.append(f"; RPZ zone: {zone_name}")
    lines.append(f"; Compiled from policy for: {result.agent_fqdn}")
    lines.append(f"; Directives: {len(result.rpz_directives)}")
    lines.append("")

    # SOA record
    lines.append(f"$TTL {ttl}")
    lines.append(f"@  IN  SOA  {ns_name} {admin_email} (")
    lines.append(f"    {serial}  ; serial")
    lines.append("    3600       ; refresh")
    lines.append("    900        ; retry")
    lines.append("    604800     ; expire")
    lines.append(f"    {ttl}        ; minimum")
    lines.append(")")
    lines.append("")

    # NS record
    lines.append(f"@  IN  NS  {ns_name}")
    lines.append("")

    # RPZ CNAME directives
    for directive in result.rpz_directives:
        target = _RPZ_CNAME_TARGET[directive.action]
        if directive.comment:
            lines.append(f"; {directive.comment}")
        if directive.source_rule:
            lines.append(f"; source: {directive.source_rule}")
        lines.append(f"{directive.owner}  {ttl}  IN  CNAME  {target}")
        lines.append("")

    return "\n".join(lines)
