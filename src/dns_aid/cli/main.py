# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Command Line Interface.

Usage:
    dns-aid publish         Publish an agent to DNS
    dns-aid discover        Discover agents at a domain
    dns-aid verify          Verify agent DNS records
    dns-aid list            List DNS-AID records
    dns-aid zones           List available DNS zones
    dns-aid delete          Delete an agent from DNS
    dns-aid index list      List agents in domain's index
    dns-aid index sync      Sync index with actual DNS records
"""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="dns-aid",
    help="DNS-based Agent Identification and Discovery",
    no_args_is_help=True,
)

console = Console()
error_console = Console(stderr=True)


def run_async(coro):
    """Run async function in sync context."""
    return asyncio.run(coro)


# ============================================================================
# PUBLISH COMMAND
# ============================================================================


@app.command()
def publish(
    name: Annotated[str, typer.Option("--name", "-n", help="Agent name (e.g., 'chat', 'network')")],
    domain: Annotated[str, typer.Option("--domain", "-d", help="Domain to publish under")],
    protocol: Annotated[str, typer.Option("--protocol", "-p", help="Protocol: mcp or a2a")] = "mcp",
    endpoint: Annotated[
        str | None, typer.Option("--endpoint", "-e", help="Agent endpoint hostname")
    ] = None,
    port: Annotated[int, typer.Option("--port", help="Port number")] = 443,
    capability: Annotated[
        list[str] | None,
        typer.Option("--capability", "-c", help="Agent capability (repeatable)"),
    ] = None,
    version: Annotated[str, typer.Option("--version", "-v", help="Agent version")] = "1.0.0",
    description: Annotated[
        str | None,
        typer.Option("--description", help="Human-readable description of the agent"),
    ] = None,
    use_case: Annotated[
        list[str] | None,
        typer.Option("--use-case", "-u", help="Use case for this agent (repeatable)"),
    ] = None,
    category: Annotated[
        str | None,
        typer.Option("--category", help="Agent category (e.g., 'network', 'security', 'chat')"),
    ] = None,
    transport: Annotated[
        str | None,
        typer.Option(
            "--transport",
            help="Transport: streamable-http, https, ws, stdio, sse",
        ),
    ] = None,
    auth_type: Annotated[
        str | None,
        typer.Option(
            "--auth-type",
            help="Auth type: none, api_key, bearer, oauth2, mtls, http_msg_sig",
        ),
    ] = None,
    ttl: Annotated[int, typer.Option("--ttl", help="DNS TTL in seconds")] = 3600,
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
    cap_uri: Annotated[
        str | None,
        typer.Option("--cap-uri", help="URI to capability document (BANDAID draft-compliant)"),
    ] = None,
    cap_sha256: Annotated[
        str | None,
        typer.Option(
            "--cap-sha256",
            help="Base64url-encoded SHA-256 digest of the capability descriptor for integrity checks",
        ),
    ] = None,
    bap: Annotated[
        str | None,
        typer.Option(
            "--bap", help="Supported bulk agent protocols (comma-separated, e.g., 'mcp,a2a')"
        ),
    ] = None,
    policy_uri: Annotated[
        str | None,
        typer.Option("--policy-uri", help="URI to agent policy document"),
    ] = None,
    realm: Annotated[
        str | None,
        typer.Option("--realm", help="Multi-tenant scope identifier (e.g., 'production', 'demo')"),
    ] = None,
    no_update_index: Annotated[
        bool,
        typer.Option("--no-update-index", help="Don't update the domain's agent index record"),
    ] = False,
    sign: Annotated[
        bool,
        typer.Option("--sign", help="Sign record with JWS (requires --private-key)"),
    ] = False,
    private_key: Annotated[
        str | None,
        typer.Option("--private-key", help="Path to EC P-256 private key PEM for signing"),
    ] = None,
):
    """
    Publish an agent to DNS using DNS-AID protocol.

    Creates SVCB and TXT records that allow other agents to discover this agent.

    Example:
        dns-aid publish -n network-specialist -d example.com -p mcp -e mcp.example.com -c ipam -c dns

        # With metadata:
        dns-aid publish -n billing -d example.com -p mcp \\
          --description "Handles invoicing and payments" \\
          --use-case "Generate invoices" --use-case "Process refunds" \\
          --category finance

        # With BANDAID draft params:
        dns-aid publish -n booking -d example.com -p mcp \\
          --cap-uri https://mcp.example.com/.well-known/agent-cap.json \\
          --bap mcp --realm production

        # With JWS signing (alternative to DNSSEC):
        dns-aid publish -n booking -d example.com -p mcp \\
          --sign --private-key ./keys/private.pem
    """
    from dns_aid.core.publisher import publish as do_publish

    # Default endpoint to {protocol}.{domain}
    if endpoint is None:
        endpoint = f"{protocol}.{domain}"

    # Get backend
    dns_backend = _get_backend(backend)

    console.print("\n[bold]Publishing agent to DNS...[/bold]\n")

    # Parse bap comma-separated string into list
    bap_list = [b.strip() for b in bap.split(",") if b.strip()] if bap else None

    # Validate sign options
    if sign and not private_key:
        error_console.print("[red]✗ --sign requires --private-key[/red]")
        raise typer.Exit(1)

    result = run_async(
        do_publish(
            name=name,
            domain=domain,
            protocol=protocol,
            endpoint=endpoint,
            port=port,
            capabilities=capability or [],
            version=version,
            description=description,
            use_cases=use_case or [],
            category=category,
            ttl=ttl,
            backend=dns_backend,
            cap_uri=cap_uri,
            cap_sha256=cap_sha256,
            bap=bap_list,
            policy_uri=policy_uri,
            realm=realm,
            sign=sign,
            private_key_path=private_key,
        )
    )

    if result.success:
        console.print("[green]✓ Agent published successfully![/green]\n")
        console.print(f"  [bold]FQDN:[/bold] {result.agent.fqdn}")
        console.print(f"  [bold]Endpoint:[/bold] {result.agent.endpoint_url}")
        console.print("\n  [bold]Records created:[/bold]")
        for record in result.records_created:
            console.print(f"    • {record}")

        # Update the domain's agent index
        if not no_update_index:
            from dns_aid.core.indexer import IndexEntry, update_index

            index_result = run_async(
                update_index(
                    domain=domain,
                    backend=dns_backend,
                    add=[IndexEntry(name=name, protocol=protocol)],
                    ttl=ttl,
                )
            )
            if index_result.success:
                action = "Created" if index_result.created else "Updated"
                console.print(
                    f"\n[green]✓ {action} index at _index._agents.{domain} "
                    f"({len(index_result.entries)} agent(s))[/green]"
                )
            else:
                console.print(f"\n[yellow]⚠ Index update failed: {index_result.message}[/yellow]")

        console.print("\n[dim]Verify with:[/dim]")
        console.print(f"  dig {result.agent.fqdn} SVCB")
        console.print(f"  dig {result.agent.fqdn} TXT")
    else:
        error_console.print(f"[red]✗ Failed to publish: {result.message}[/red]")
        raise typer.Exit(1)


# ============================================================================
# DISCOVER COMMAND
# ============================================================================


@app.command()
def discover(
    domain: Annotated[str, typer.Argument(help="Domain to search for agents")],
    protocol: Annotated[
        str | None, typer.Option("--protocol", "-p", help="Filter by protocol")
    ] = None,
    name: Annotated[str | None, typer.Option("--name", "-n", help="Filter by agent name")] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
    use_http_index: Annotated[
        bool,
        typer.Option(
            "--use-http-index",
            "--http",
            help="Use HTTP index endpoint (https://_index._aiagents.{domain}/index-wellknown) instead of DNS-only discovery",
        ),
    ] = False,
    verify_signatures: Annotated[
        bool,
        typer.Option(
            "--verify-signatures",
            "--verify",
            help="Verify JWS signatures on agents (alternative to DNSSEC)",
        ),
    ] = False,
):
    """
    Discover agents at a domain using DNS-AID protocol.

    Queries DNS for SVCB records and returns agent endpoints.

    By default, uses pure DNS discovery. Use --use-http-index to fetch
    agent list from HTTP endpoint with richer metadata.

    Example:
        dns-aid discover example.com
        dns-aid discover example.com --protocol mcp
        dns-aid discover example.com --name chat
        dns-aid discover example.com --use-http-index
    """
    from dns_aid.core.discoverer import discover as do_discover

    method = "HTTP index" if use_http_index else "DNS"
    console.print(f"\n[bold]Discovering agents at {domain} via {method}...[/bold]\n")

    result = run_async(
        do_discover(
            domain=domain,
            protocol=protocol,
            name=name,
            use_http_index=use_http_index,
            verify_signatures=verify_signatures,
        )
    )

    if json_output:
        import json

        output = {
            "domain": result.domain,
            "query": result.query,
            "discovery_method": "http_index" if use_http_index else "dns",
            "agents": [
                {
                    "name": a.name,
                    "protocol": a.protocol.value,
                    "endpoint": a.endpoint_url,
                    "capabilities": a.capabilities,
                    "capability_source": a.capability_source,
                    "cap_uri": a.cap_uri,
                    "cap_sha256": a.cap_sha256,
                    "bap": a.bap if a.bap else None,
                    "policy_uri": a.policy_uri,
                    "realm": a.realm,
                    "description": a.description,
                }
                for a in result.agents
            ],
            "count": result.count,
            "query_time_ms": result.query_time_ms,
        }
        console.print_json(json.dumps(output))
        return

    if result.count == 0:
        console.print(f"[yellow]No agents found at {domain}[/yellow]")
        console.print(f"\n[dim]Query: {result.query}[/dim]")
        console.print(f"[dim]Time: {result.query_time_ms:.2f}ms[/dim]")
        return

    console.print(f"[green]Found {result.count} agent(s) at {domain}:[/green]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Protocol")
    table.add_column("Endpoint")
    table.add_column("Capabilities")
    table.add_column("Cap Source")

    for agent in result.agents:
        table.add_row(
            agent.name,
            agent.protocol.value,
            agent.endpoint_url,
            ", ".join(agent.capabilities) if agent.capabilities else "-",
            agent.capability_source or "-",
        )

    console.print(table)
    console.print(f"\n[dim]Query: {result.query}[/dim]")
    console.print(f"[dim]Time: {result.query_time_ms:.2f}ms[/dim]")


# ============================================================================
# VERIFY COMMAND
# ============================================================================


@app.command()
def verify(
    fqdn: Annotated[
        str, typer.Argument(help="FQDN to verify (e.g., _chat._a2a._agents.example.com)")
    ],
):
    """
    Verify DNS-AID records for an agent.

    Checks DNS record existence, DNSSEC validation, and endpoint health.

    Example:
        dns-aid verify _chat._a2a._agents.example.com
    """
    from dns_aid.core.validator import verify as do_verify

    console.print(f"\n[bold]Verifying {fqdn}...[/bold]\n")

    result = run_async(do_verify(fqdn))

    # Display results
    def status(ok: bool | None) -> str:
        if ok is None:
            return "[yellow]○[/yellow]"
        return "[green]✓[/green]" if ok else "[red]✗[/red]"

    console.print(f"  {status(result.record_exists)} DNS record exists")
    console.print(f"  {status(result.svcb_valid)} SVCB record valid")
    console.print(f"  {status(result.dnssec_valid)} DNSSEC validated")
    console.print(f"  {status(result.dane_valid)} DANE/TLSA configured")
    console.print(f"  {status(result.endpoint_reachable)} Endpoint reachable")

    if result.endpoint_latency_ms:
        console.print(f"    [dim]Latency: {result.endpoint_latency_ms:.0f}ms[/dim]")

    console.print(
        f"\n[bold]Security Score:[/bold] {result.security_score}/100 ({result.security_rating})"
    )


# ============================================================================
# LIST COMMAND
# ============================================================================


@app.command("list")
def list_records(
    domain: Annotated[str, typer.Argument(help="Domain to list records from")],
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
):
    """
    List DNS-AID records in a domain.

    Shows all _agents.* records in the specified zone.

    Example:
        dns-aid list example.com
    """
    dns_backend = _get_backend(backend)

    console.print(f"\n[bold]DNS-AID records in {domain}:[/bold]\n")

    async def list_all():
        records = []
        async for record in dns_backend.list_records(domain, name_pattern="_agents"):
            records.append(record)
        return records

    records = run_async(list_all())

    if not records:
        console.print(f"[yellow]No DNS-AID records found in {domain}[/yellow]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("TTL")
    table.add_column("Value")

    for record in records:
        value = record.get("values", [])
        if isinstance(value, list):
            value = value[0] if value else "-"
        if len(str(value)) > 50:
            value = str(value)[:47] + "..."

        table.add_row(
            record["fqdn"],
            record["type"],
            str(record["ttl"]),
            str(value),
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(records)} record(s)[/dim]")


# ============================================================================
# ZONES COMMAND
# ============================================================================


@app.command()
def zones(
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
):
    """
    List available DNS zones.

    Shows all zones accessible with current credentials.

    Example:
        dns-aid zones
    """
    dns_backend = _get_backend(backend)

    from dns_aid.backends.route53 import Route53Backend

    if not isinstance(dns_backend, Route53Backend):
        error_console.print("[red]Zone listing only supported for route53 backend[/red]")
        raise typer.Exit(1)

    console.print("\n[bold]Available DNS zones (route53):[/bold]\n")

    zone_list = run_async(dns_backend.list_zones())

    table = Table(show_header=True, header_style="bold")
    table.add_column("Domain")
    table.add_column("Zone ID")
    table.add_column("Records")
    table.add_column("Type")

    for zone in zone_list:
        table.add_row(
            zone["name"],
            zone["id"],
            str(zone["record_count"]),
            "Private" if zone["private"] else "Public",
        )

    console.print(table)


# ============================================================================
# DELETE COMMAND
# ============================================================================


@app.command()
def delete(
    name: Annotated[str, typer.Option("--name", "-n", help="Agent name")],
    domain: Annotated[str, typer.Option("--domain", "-d", help="Domain")],
    protocol: Annotated[str, typer.Option("--protocol", "-p", help="Protocol")] = "mcp",
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
    force: Annotated[bool, typer.Option("--force", "-f", help="Skip confirmation")] = False,
    no_update_index: Annotated[
        bool,
        typer.Option("--no-update-index", help="Don't update the domain's agent index record"),
    ] = False,
):
    """
    Delete an agent from DNS.

    Removes SVCB and TXT records for the specified agent.
    By default, also removes the agent from the domain's index record.

    Example:
        dns-aid delete -n chat -d example.com -p a2a
    """
    from dns_aid.core.publisher import unpublish

    fqdn = f"_{name}._{protocol}._agents.{domain}"

    if not force:
        confirm = typer.confirm(f"Delete {fqdn}?")
        if not confirm:
            raise typer.Abort()

    dns_backend = _get_backend(backend)

    console.print(f"\n[bold]Deleting {fqdn}...[/bold]\n")

    result = run_async(
        unpublish(
            name=name,
            domain=domain,
            protocol=protocol,
            backend=dns_backend,
        )
    )

    if result:
        console.print("[green]✓ Agent deleted successfully[/green]")

        # Update the domain's agent index
        if not no_update_index:
            from dns_aid.core.indexer import IndexEntry, update_index

            index_result = run_async(
                update_index(
                    domain=domain,
                    backend=dns_backend,
                    remove=[IndexEntry(name=name, protocol=protocol)],
                )
            )
            if index_result.success:
                console.print(
                    f"[green]✓ Updated index at _index._agents.{domain} "
                    f"({len(index_result.entries)} agent(s))[/green]"
                )
            else:
                console.print(f"[yellow]⚠ Index update failed: {index_result.message}[/yellow]")
    else:
        console.print("[yellow]No records found to delete[/yellow]")


# ============================================================================
# INDEX COMMANDS
# ============================================================================

# Create a sub-app for index commands
index_app = typer.Typer(
    name="index",
    help="Manage domain agent index records",
    no_args_is_help=True,
)
app.add_typer(index_app, name="index")


@index_app.command("list")
def index_list(
    domain: Annotated[str, typer.Argument(help="Domain to list index from")],
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
):
    """
    List agents in a domain's index record.

    Shows all agents listed in _index._agents.{domain}.

    Example:
        dns-aid index list example.com
    """
    from dns_aid.core.indexer import read_index, read_index_via_dns

    dns_backend = _get_backend(backend)

    console.print(f"\n[bold]Agent index for {domain}:[/bold]\n")

    entries = run_async(read_index(domain, dns_backend))

    if not entries:
        # Fallback: try direct DNS query (works without backend credentials)
        entries = run_async(read_index_via_dns(domain))

    if not entries:
        console.print(f"[yellow]No index record found at _index._agents.{domain}[/yellow]")
        console.print(
            "\n[dim]Tip: Publish an agent or run 'dns-aid index sync' to create the index[/dim]"
        )
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Protocol")
    table.add_column("FQDN")

    for entry in sorted(entries, key=lambda e: (e.name, e.protocol)):
        fqdn = f"_{entry.name}._{entry.protocol}._agents.{domain}"
        table.add_row(entry.name, entry.protocol, fqdn)

    console.print(table)
    console.print(f"\n[dim]Total: {len(entries)} agent(s) in index[/dim]")


@index_app.command("sync")
def index_sync(
    domain: Annotated[str, typer.Argument(help="Domain to sync index for")],
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
    ttl: Annotated[int, typer.Option("--ttl", help="TTL for index record")] = 3600,
):
    """
    Sync index with actual DNS records.

    Scans for all _agents.* SVCB records and updates the index to match.

    Example:
        dns-aid index sync example.com
    """
    from dns_aid.core.indexer import sync_index

    dns_backend = _get_backend(backend)

    console.print(f"\n[bold]Syncing index for {domain}...[/bold]\n")

    result = run_async(sync_index(domain, dns_backend, ttl=ttl))

    if result.success:
        if result.entries:
            console.print(f"[green]✓ {result.message}[/green]\n")

            table = Table(show_header=True, header_style="bold")
            table.add_column("Name")
            table.add_column("Protocol")

            for entry in sorted(result.entries, key=lambda e: (e.name, e.protocol)):
                table.add_row(entry.name, entry.protocol)

            console.print(table)

            if result.created:
                console.print(f"\n[dim]Index record created at _index._agents.{domain}[/dim]")
        else:
            console.print("[yellow]No agents found to index[/yellow]")
    else:
        error_console.print(f"[red]✗ Sync failed: {result.message}[/red]")
        raise typer.Exit(1)


# ============================================================================
# KEYS COMMANDS (JWS Signing)
# ============================================================================

keys_app = typer.Typer(
    help="Manage signing keys for JWS verification (alternative to DNSSEC)",
    no_args_is_help=True,
)
app.add_typer(keys_app, name="keys")


@keys_app.command("generate")
def keys_generate(
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output directory for keypair files"),
    ] = ".",
    kid: Annotated[
        str,
        typer.Option("--kid", help="Key ID for the keypair"),
    ] = "dns-aid-default",
    password: Annotated[
        str | None,
        typer.Option("--password", "-p", help="Password to encrypt private key (optional)"),
    ] = None,
):
    """
    Generate an EC P-256 keypair for JWS signing.

    Creates two files:
    - {output}/private.pem: Private key (keep secret!)
    - {output}/public.pem: Public key

    Example:
        dns-aid keys generate --output ./keys --kid dns-aid-2024

        # With password protection:
        dns-aid keys generate -o ./keys -p mypassword
    """
    import os
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization

    from dns_aid.core.jwks import generate_keypair

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print("\n[bold]Generating EC P-256 keypair...[/bold]\n")

    private_key, public_key = generate_keypair()

    # Determine encryption
    encryption: serialization.KeySerializationEncryption
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    private_path = output_dir / "private.pem"
    private_path.write_bytes(private_pem)
    os.chmod(private_path, 0o600)  # Restrict permissions

    # Save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path = output_dir / "public.pem"
    public_path.write_bytes(public_pem)

    console.print("[green]✓ Keypair generated successfully![/green]\n")
    console.print(f"  [bold]Private key:[/bold] {private_path}")
    console.print(f"  [bold]Public key:[/bold] {public_path}")
    console.print(f"  [bold]Key ID:[/bold] {kid}")

    if password:
        console.print("\n  [yellow]Private key is password-protected[/yellow]")
    else:
        console.print("\n  [yellow]⚠ Private key is NOT encrypted - protect this file![/yellow]")

    console.print("\n[dim]Next steps:[/dim]")
    console.print("  1. Export JWKS: dns-aid keys export-jwks -i public.pem")
    console.print("  2. Publish JWKS to: https://yourdomain/.well-known/dns-aid-jwks.json")
    console.print("  3. Sign agents: dns-aid publish --sign --private-key private.pem ...")


@keys_app.command("export-jwks")
def keys_export_jwks(
    input_key: Annotated[
        str,
        typer.Option("--input", "-i", help="Path to public key PEM file"),
    ],
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output file path (stdout if not specified)"),
    ] = None,
    kid: Annotated[
        str,
        typer.Option("--kid", help="Key ID to include in JWKS"),
    ] = "dns-aid-default",
):
    """
    Export a public key as a JWKS document.

    The JWKS document should be published at:
    https://yourdomain/.well-known/dns-aid-jwks.json

    Example:
        # Export to stdout
        dns-aid keys export-jwks -i public.pem

        # Export to file
        dns-aid keys export-jwks -i public.pem -o jwks.json

        # With custom key ID
        dns-aid keys export-jwks -i public.pem --kid dns-aid-2024 -o jwks.json
    """
    import json
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization

    from dns_aid.core.jwks import export_jwks

    # Load public key
    key_path = Path(input_key)
    if not key_path.exists():
        error_console.print(f"[red]✗ Key file not found: {input_key}[/red]")
        raise typer.Exit(1)

    key_data = key_path.read_bytes()

    # Try to load as public key first, then try private key
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )

    try:
        public_key = serialization.load_pem_public_key(key_data)
        if not isinstance(public_key, EllipticCurvePublicKey):
            error_console.print("[red]✗ Key must be an EC (P-256) key[/red]")
            raise typer.Exit(1)
    except Exception:
        # Try loading as private key and extracting public key
        try:
            private_key = serialization.load_pem_private_key(key_data, password=None)
            if not isinstance(private_key, EllipticCurvePrivateKey):
                error_console.print("[red]✗ Key must be an EC (P-256) key[/red]")
                raise typer.Exit(1)
            public_key = private_key.public_key()
        except Exception as e:
            error_console.print(f"[red]✗ Failed to load key: {e}[/red]")
            raise typer.Exit(1) from None

    # Generate JWKS
    jwks = export_jwks(public_key, kid=kid)
    jwks_json = json.dumps(jwks, indent=2)

    if output:
        Path(output).write_text(jwks_json)
        console.print(f"[green]✓ JWKS exported to {output}[/green]")
    else:
        console.print(jwks_json)

    console.print("\n[dim]Publish this file at:[/dim]")
    console.print("  https://yourdomain/.well-known/dns-aid-jwks.json")


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def _get_backend(backend_name: str | None):
    """Get DNS backend by name.

    Falls back to DNS_AID_BACKEND env var when no --backend flag is given.
    """
    import os

    if backend_name is None:
        backend_name = os.environ.get("DNS_AID_BACKEND", "route53")

    backend_name = backend_name.lower()

    if backend_name == "route53":
        from dns_aid.backends.route53 import Route53Backend

        return Route53Backend()
    elif backend_name == "cloudflare":
        from dns_aid.backends.cloudflare import CloudflareBackend

        return CloudflareBackend()
    elif backend_name == "infoblox":
        from dns_aid.backends.infoblox import InfobloxBackend

        return InfobloxBackend()
    elif backend_name == "ddns":
        from dns_aid.backends.ddns import DDNSBackend

        return DDNSBackend()
    elif backend_name == "mock":
        from dns_aid.backends.mock import MockBackend

        return MockBackend()
    else:
        error_console.print(f"[red]Unknown backend: {backend_name}[/red]")
        error_console.print("Available backends: route53, cloudflare, infoblox, ddns, mock")
        raise typer.Exit(1)


# ============================================================================
# VERSION
# ============================================================================


def version_callback(value: bool):
    if value:
        from dns_aid import __version__

        console.print(f"dns-aid version {__version__}")
        raise typer.Exit()


def quiet_callback(value: bool):
    if value:
        from dns_aid.utils.logging import silence_logging

        silence_logging()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=version_callback, is_eager=True, help="Show version"),
    ] = None,
    quiet: Annotated[
        bool | None,
        typer.Option("--quiet", "-q", callback=quiet_callback, is_eager=True, help="Suppress logs"),
    ] = None,
):
    """
    DNS-AID: DNS-based Agent Identification and Discovery

    Publish and discover AI agents using DNS infrastructure.
    """
    from dotenv import load_dotenv

    load_dotenv()


if __name__ == "__main__":
    app()
