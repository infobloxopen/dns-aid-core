"""Unit tests for CLI commands."""

from unittest.mock import patch

from typer.testing import CliRunner

from dns_aid.cli.main import app

runner = CliRunner()


class TestVersion:
    """Test version display."""

    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "dns-aid version" in result.output

    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # Typer returns exit code 0 for no_args_is_help
        assert "DNS-based Agent Identification" in result.output


class TestGetBackend:
    """Test _get_backend helper."""

    def test_mock_backend(self):
        from dns_aid.cli.main import _get_backend

        backend = _get_backend("mock")
        from dns_aid.backends.mock import MockBackend

        assert isinstance(backend, MockBackend)

    def test_route53_backend(self):
        from dns_aid.cli.main import _get_backend

        backend = _get_backend("route53")
        from dns_aid.backends.route53 import Route53Backend

        assert isinstance(backend, Route53Backend)

    def test_cloudflare_backend(self):
        from dns_aid.cli.main import _get_backend

        backend = _get_backend("cloudflare")
        from dns_aid.backends.cloudflare import CloudflareBackend

        assert isinstance(backend, CloudflareBackend)

    def test_unknown_backend_exits(self):
        import click

        from dns_aid.cli.main import _get_backend

        try:
            _get_backend("nonexistent")
            raise AssertionError("Should have raised")
        except (SystemExit, click.exceptions.Exit):
            pass  # Either exception is acceptable


class TestDiscoverCommand:
    """Test discover CLI command."""

    @patch("dns_aid.cli.main.run_async")
    def test_discover_no_agents(self, mock_run_async):
        from dns_aid.core.models import DiscoveryResult

        mock_run_async.return_value = DiscoveryResult(
            domain="example.com",
            query="_agents.example.com",
            agents=[],
            query_time_ms=10.5,
        )

        result = runner.invoke(app, ["discover", "example.com"])
        assert result.exit_code == 0
        assert "No agents found" in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_discover_with_agents(self, mock_run_async):
        from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol

        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            endpoint_override="https://mcp.example.com",
            port=443,
        )
        mock_run_async.return_value = DiscoveryResult(
            domain="example.com",
            query="_agents.example.com",
            agents=[agent],
            query_time_ms=15.3,
        )

        result = runner.invoke(app, ["discover", "example.com"])
        assert result.exit_code == 0
        assert "Found 1 agent" in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_discover_json_output(self, mock_run_async):
        from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
            endpoint_override="https://chat.example.com",
            port=443,
        )
        mock_run_async.return_value = DiscoveryResult(
            domain="example.com",
            query="_agents.example.com",
            agents=[agent],
            query_time_ms=8.0,
        )

        result = runner.invoke(app, ["discover", "example.com", "--json"])
        assert result.exit_code == 0
        assert "chat" in result.output
        assert "a2a" in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_discover_with_http_index(self, mock_run_async):
        from dns_aid.core.models import DiscoveryResult

        mock_run_async.return_value = DiscoveryResult(
            domain="example.com",
            query="_agents.example.com",
            agents=[],
            query_time_ms=20.0,
        )

        result = runner.invoke(app, ["discover", "example.com", "--use-http-index"])
        assert result.exit_code == 0
        assert "HTTP index" in result.output


class TestVerifyCommand:
    """Test verify CLI command."""

    @patch("dns_aid.cli.main.run_async")
    def test_verify_agent(self, mock_run_async):
        from dns_aid.core.validator import VerifyResult

        mock_run_async.return_value = VerifyResult(
            fqdn="_chat._a2a._agents.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=False,
            dane_valid=None,
            endpoint_reachable=True,
            endpoint_latency_ms=42.0,
        )

        result = runner.invoke(app, ["verify", "_chat._a2a._agents.example.com"])
        assert result.exit_code == 0
        assert "Security Score" in result.output


class TestQuietMode:
    """Test quiet flag."""

    def test_quiet_flag(self):
        result = runner.invoke(app, ["--quiet", "--version"])
        assert result.exit_code == 0
        assert "dns-aid version" in result.output


class TestRunAsync:
    """Test run_async helper."""

    def test_run_async_executes_coroutine(self):
        from dns_aid.cli.main import run_async

        async def simple():
            return 42

        assert run_async(simple()) == 42
