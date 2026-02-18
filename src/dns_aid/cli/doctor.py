# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
``dns-aid doctor`` — non-interactive environment diagnostics.

Checks Python version, core dependencies, DNS resolution, backend
credentials, optional features, and ``.env`` configuration.
"""

from __future__ import annotations

import importlib
import os
import platform
from pathlib import Path

from rich.console import Console

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
    """DNS: can resolve, can discover agents at demo domain."""
    console.print("\n[bold]DNS Resolution[/bold]")

    # Basic resolution
    try:
        import dns.resolver

        dns.resolver.resolve("example.com", "A")
        _ok("DNS resolution works")
        pass_count[0] += 1
    except Exception as exc:
        _fail("DNS resolution", str(exc))
        fail_count[0] += 1
        return  # skip discovery test if DNS itself fails

    # Discovery at demo domain
    try:
        import asyncio

        from dns_aid.core.discoverer import discover

        result = asyncio.run(discover("highvelocitynetworking.com"))
        _ok("Agent discovery", f"{result.count} agent(s) at highvelocitynetworking.com")
        pass_count[0] += 1
    except Exception as exc:
        _warn("Agent discovery", f"demo domain unreachable: {exc}")


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
    console.print("\n[bold].env Configuration[/bold]")

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

    console.print(f"\n[bold]dns-aid doctor[/bold]  v{__version__}\n")

    pass_count = [0]
    fail_count = [0]

    _check_core(pass_count, fail_count)
    _check_dns(pass_count, fail_count)
    _check_backends(pass_count, fail_count)
    _check_optional(pass_count, fail_count)
    _check_dotenv(pass_count, fail_count)

    # Summary
    total = pass_count[0] + fail_count[0]
    console.print(f"\n[bold]Summary:[/bold] {pass_count[0]}/{total} checks passed", end="")
    if fail_count[0]:
        console.print(f"  [red]({fail_count[0]} failed)[/red]")
    else:
        console.print("  [green]All good![/green]")
    console.print()
