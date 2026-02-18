# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
``dns-aid doctor`` — non-interactive environment diagnostics.

Checks Python version, core dependencies, DNS resolution, backend
credentials, optional features, and ``.env`` configuration.
"""

from __future__ import annotations

import importlib
import logging
import os
import platform
import time
from contextlib import contextmanager
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)

# ── formatting helpers ─────────────────────────────────────────────

_PASS = "[green]✓[/green]"  # nosec B105 — Rich markup, not a credential
_FAIL = "[red]✗[/red]"
_WARN = "[yellow]○[/yellow]"


def _ok(label: str, detail: str = "") -> None:
    suffix = f"  [dim]{detail}[/dim]" if detail else ""
    console.print(f"  {_PASS} {label}{suffix}")


def _fail(label: str, detail: str = "") -> None:
    suffix = f"  [dim]{detail}[/dim]" if detail else ""
    console.print(f"  {_FAIL} {label}{suffix}")


def _warn(label: str, detail: str = "") -> None:
    suffix = f"  [dim]{detail}[/dim]" if detail else ""
    console.print(f"  {_WARN} {label}{suffix}")


@contextmanager
def _suppress_logs():
    """Temporarily suppress all logging output (stdlib + structlog)."""
    import structlog

    logging.disable(logging.CRITICAL)
    # structlog may use its own PrintLogger, bypassing stdlib.
    # Wrap the current factory to drop all output.
    prev_factory = structlog.get_config().get("logger_factory")
    structlog.configure(logger_factory=lambda *a, **kw: logging.getLogger("_null"))
    try:
        yield
    finally:
        logging.disable(logging.NOTSET)
        if prev_factory:
            structlog.configure(logger_factory=prev_factory)
        else:
            structlog.reset_defaults()


# ── individual checks ──────────────────────────────────────────────


def _check_core(pass_count: list[int], fail_count: list[int]) -> None:
    """Core: version, Python, required deps."""
    console.print("\n[bold]Core[/bold]")

    # dns-aid version
    try:
        from dns_aid import __version__

        _ok("dns-aid", __version__)
        pass_count[0] += 1
    except Exception as exc:
        _fail("dns-aid", str(exc))
        fail_count[0] += 1

    # Python version
    py = platform.python_version()
    _ok("Python", py)
    pass_count[0] += 1

    # Required dependencies
    for dep in ("dnspython", "httpx", "pydantic", "typer", "rich", "structlog"):
        pkg = dep.replace("-", ".")
        try:
            mod = importlib.import_module(pkg if dep != "dnspython" else "dns")
            ver = getattr(mod, "__version__", getattr(mod, "version", ""))
            if callable(ver):
                ver = ver()
            _ok(dep, str(ver))
            pass_count[0] += 1
        except ImportError:
            _fail(dep, "not installed")
            fail_count[0] += 1


def _check_dns(pass_count: list[int], fail_count: list[int]) -> None:
    """DNS: resolution, SVCB support, and agent discovery via TXT index."""
    console.print("\n[bold]DNS[/bold]")

    # Basic resolution
    try:
        import dns.resolver

        dns.resolver.resolve("example.com", "A")
        _ok("Resolution", "DNS queries working")
        pass_count[0] += 1
    except Exception as exc:
        _fail("Resolution", str(exc))
        fail_count[0] += 1
        return  # skip remaining DNS checks

    # SVCB record type support
    try:
        import dns.rdatatype

        dns.rdatatype.from_text("SVCB")
        _ok("SVCB support", "RFC 9460 record types available")
        pass_count[0] += 1
    except Exception:
        _warn("SVCB support", "dnspython may not support SVCB queries")

    # Agent discovery via lightweight TXT index check
    # Uses read_index_via_dns (single DNS query) instead of full discover()
    # to avoid noisy agent card fetches and HTTP calls
    try:
        import asyncio

        from dns_aid.core.indexer import read_index_via_dns

        domain = os.environ.get("DNS_AID_DOCTOR_DOMAIN", "highvelocitynetworking.com")
        start = time.perf_counter()
        with _suppress_logs():
            entries = asyncio.run(read_index_via_dns(domain))
        elapsed = time.perf_counter() - start

        if entries:
            _ok(
                "Agent discovery",
                f"{len(entries)} agent(s) indexed at {domain} ({elapsed:.0f}ms)",
            )
            pass_count[0] += 1
        else:
            _warn("Agent discovery", f"no agents indexed at {domain}")
    except Exception as exc:
        _warn("Agent discovery", f"TXT index query failed: {exc}")


def _check_backends(pass_count: list[int], fail_count: list[int]) -> None:
    """Backends: deps → env vars for each."""
    from dns_aid.cli.backends import BACKEND_REGISTRY, REAL_BACKEND_NAMES

    console.print("\n[bold]Backends[/bold]")

    for name in REAL_BACKEND_NAMES:
        info = BACKEND_REGISTRY[name]

        # Check optional dependency
        dep_ok = True
        if info.optional_dep:
            try:
                if name == "route53":
                    importlib.import_module("boto3")
                elif name in ("cloudflare", "infoblox", "nios"):
                    importlib.import_module("httpx")
                elif name == "ddns":
                    importlib.import_module("dns.update")
            except ImportError:
                dep_ok = False

        if not dep_ok:
            _fail(info.display_name, f"pip install 'dns-aid[{info.optional_dep}]'")
            fail_count[0] += 1
            continue

        # Check credentials
        if name == "route53":
            # Route 53 uses boto3 credential chain (env, file, IAM role)
            from dns_aid.cli.backends import _has_boto3_credentials

            if _has_boto3_credentials():
                _ok(info.display_name, "credentials configured")
                pass_count[0] += 1
            else:
                _warn(info.display_name, "no AWS credentials found")
        else:
            missing = [v for v in info.required_env if not os.environ.get(v)]
            if missing:
                _warn(info.display_name, f"missing: {', '.join(missing)}")
            else:
                _ok(info.display_name, "credentials configured")
                pass_count[0] += 1


def _check_optional(pass_count: list[int], fail_count: list[int]) -> None:
    """Optional features: MCP, JWS signing, OpenTelemetry."""
    console.print("\n[bold]Optional Features[/bold]")

    # MCP
    try:
        importlib.import_module("mcp")
        _ok("MCP server", "mcp package available")
        pass_count[0] += 1
    except ImportError:
        _warn("MCP server", "pip install 'dns-aid[mcp]'")

    # JWS signing
    try:
        importlib.import_module("cryptography")
        _ok("JWS signing", "cryptography available")
        pass_count[0] += 1
    except ImportError:
        _warn("JWS signing", "pip install 'dns-aid[jws]'")

    # OpenTelemetry
    try:
        importlib.import_module("opentelemetry")
        _ok("OpenTelemetry", "available")
        pass_count[0] += 1
    except ImportError:
        _warn("OpenTelemetry", "pip install opentelemetry-api")


def _check_dotenv(pass_count: list[int], fail_count: list[int]) -> None:
    """Check .env file."""
    console.print("\n[bold]Configuration[/bold]")

    env_path = Path.cwd() / ".env"
    if env_path.exists():
        # Count non-empty, non-comment lines
        lines = [
            ln
            for ln in env_path.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        _ok(".env file", f"{len(lines)} variable(s) set")
        pass_count[0] += 1

        # Check DNS_AID_BACKEND
        backend_val = os.environ.get("DNS_AID_BACKEND")
        if backend_val:
            _ok("DNS_AID_BACKEND", backend_val)
        else:
            _warn("DNS_AID_BACKEND", "not set (will auto-detect or default)")
    else:
        _warn(".env file", "not found — copy .env.example to get started")


# ── main command ───────────────────────────────────────────────────


def doctor():
    """
    Diagnose your DNS-AID environment.

    Checks Python, dependencies, DNS resolution, backend credentials,
    optional features, and .env configuration.

    Example:
        dns-aid doctor
    """
    from dns_aid import __version__

    console.print(
        Panel(
            f"[bold]dns-aid doctor[/bold]  v{__version__}",
            subtitle="[dim]IETF draft-mozleywilliams-dnsop-bandaid-02[/dim]",
            width=56,
        )
    )

    pass_count = [0]
    fail_count = [0]

    _check_core(pass_count, fail_count)
    _check_dns(pass_count, fail_count)
    _check_backends(pass_count, fail_count)
    _check_optional(pass_count, fail_count)
    _check_dotenv(pass_count, fail_count)

    # Summary
    total = pass_count[0] + fail_count[0]
    console.print()

    summary = Table.grid(padding=(0, 1))
    summary.add_column(style="bold")
    summary.add_column()

    if fail_count[0]:
        summary.add_row(
            "Result:",
            f"[green]{pass_count[0]}[/green]/{total} passed, [red]{fail_count[0]} failed[/red]",
        )
    else:
        summary.add_row(
            "Result:",
            f"[green]{pass_count[0]}/{total} passed — all good![/green]",
        )

    legend = "[green]✓[/green] pass  [red]✗[/red] fail  [yellow]○[/yellow] optional/unconfigured"
    summary.add_row("Legend:", f"[dim]{legend}[/dim]")

    console.print(Panel(summary, width=56))
    console.print()
