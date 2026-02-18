# Contributing to DNS-AID

Thank you for your interest in contributing to DNS-AID! This project aims to be contributed to the Linux Foundation Agent AI Foundation.

## Quick Start

```bash
# 1. Fork and clone
git clone https://github.com/YOUR-USERNAME/dns-aid-core.git
cd dns-aid-core

# 2. Install with uv (recommended)
uv sync --all-extras

# 3. Verify everything works
uv run dns-aid doctor
uv run pytest tests/unit/ -q
```

> **Don't have uv?** Install it: `curl -LsSf https://astral.sh/uv/install.sh | sh`
>
> **Prefer pip?** That works too:
> ```bash
> python -m venv .venv && source .venv/bin/activate
> pip install -e ".[all]"
> ```

## Project Structure

```
dns-aid-core/
├── src/dns_aid/
│   ├── core/           # Discovery, publishing, validation (Tier 0)
│   ├── backends/       # DNS backends (Route 53, Cloudflare, Infoblox, DDNS, Mock)
│   ├── sdk/            # Telemetry SDK, ranking, protocol handlers (Tier 1)
│   ├── cli/            # CLI commands (publish, discover, verify, list, init, doctor)
│   ├── mcp/            # MCP server for AI agents
│   └── utils/          # Shared utilities
├── tests/
│   ├── unit/           # Fast tests, no network (CI runs these)
│   └── integration/    # Backend tests, need credentials (marked @pytest.mark.live)
├── docs/               # Documentation
└── examples/           # Example scripts
```

**Where does new code go?**
- New DNS backend → `src/dns_aid/backends/` + add to `_BACKEND_CLASSES` in `backends/__init__.py` + register in `cli/backends.py`
- New CLI command → `src/dns_aid/cli/` + register in `cli/main.py`
- New SDK feature → `src/dns_aid/sdk/`
- New MCP tool → `src/dns_aid/mcp/server.py`

## Development Workflow

### 1. Create a feature branch

```bash
git checkout -b feat/your-feature-name
```

### 2. Make changes and run checks locally

```bash
# Tests (730+ unit tests, ~4 seconds)
uv run pytest tests/unit/ -q

# Linting
uv run ruff check src/
uv run ruff format --check src/

# Type checking
uv run mypy src/dns_aid

# Verify your environment
uv run dns-aid doctor
```

### 3. Commit with DCO sign-off

All commits **must** include a `Signed-off-by` line (Linux Foundation requirement):

```bash
git commit -s -m "feat: add DANE certificate matching support"
```

The `-s` flag automatically appends `Signed-off-by: Your Name <your@email.com>` using your git config.

### 4. Push and open a PR

```bash
git push origin feat/your-feature-name
```

Then open a Pull Request against the `main` branch on [infobloxopen/dns-aid-core](https://github.com/infobloxopen/dns-aid-core).

## Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add DANE certificate matching support
fix: Route 53 SVCB custom param demotion to TXT records
docs: update architecture diagram
chore: bump version to 0.6.6
test: add integration tests for Cloudflare backend
refactor: extract credential detection into backends registry
```

## What CI Checks on Your PR

Every PR must pass **8 required checks** before merging:

| Check | What it does | How to run locally |
|-------|-------------|-------------------|
| **Test (Python 3.11)** | Unit tests on 3.11 | `uv run pytest tests/unit/` |
| **Test (Python 3.12)** | Unit tests on 3.12 | (same) |
| **Test (Python 3.13)** | Unit tests on 3.13 | (same) |
| **Lint** | `ruff check` + `ruff format --check` | `uv run ruff check src/ && uv run ruff format --check src/` |
| **Type Check** | `mypy src/dns_aid` | `uv run mypy src/dns_aid` |
| **SAST (Bandit)** | Security static analysis | `uv run bandit -r src/dns_aid -c pyproject.toml` |
| **Dependency Audit** | Known vulnerability scan | `uv run pip-audit` |
| **DCO** | Signed-off-by on all commits | `git commit -s -m "..."` |

Additional non-blocking checks: CodeQL (code scanning), OpenSSF Scorecard, SBOM generation.

**Branch protection also requires 1 approving review** and dismisses stale reviews on new pushes.

## Code Standards

- **Type hints**: All public functions must have type annotations
- **Docstrings**: All public functions documented
- **Line length**: 100 characters max
- **Tests**: New features need tests; maintain >80% coverage
- **Async**: Use `async/await` for I/O operations
- **Logging**: Use `structlog` for structured logging
- **No `__init__.py` in test dirs** — pytest uses `--import-mode=importlib`

## Testing

### Unit Tests

```bash
# All unit tests
uv run pytest tests/unit/ -q

# Specific test file
uv run pytest tests/unit/test_models.py -v

# With coverage
uv run pytest tests/unit/ --cov=dns_aid --cov-report=term-missing
```

### Integration Tests

Integration tests require real DNS backend credentials and are skipped by default in CI. They are marked with `@pytest.mark.live`.

**Route 53** (any [boto3 credential method](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) works):
```bash
aws configure                          # easiest
export DNS_AID_TEST_ZONE="your-zone.com"
uv run pytest tests/integration/test_route53.py -v
```

**Infoblox BloxOne:**
```bash
export INFOBLOX_API_KEY="your-api-key"
export INFOBLOX_TEST_ZONE="your-zone.com"
uv run pytest tests/integration/test_infoblox.py -v
```

> **Warning**: Integration tests create and delete real DNS records. Use a test zone.

## Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Fill out the PR template (auto-populated when you open a PR)
- Add tests for new functionality
- Update documentation if behavior changes
- Update `CHANGELOG.md` for significant changes
- Ensure all 8 CI checks pass

## Release Process

Releases are handled by maintainers:

1. Version is bumped in 4 files: `pyproject.toml`, `src/dns_aid/__init__.py`, `CITATION.cff`, `CHANGELOG.md`
2. `uv lock` updates the lockfile
3. A `v*` tag triggers the [Release workflow](.github/workflows/release.yml):
   - Builds wheel + sdist
   - Generates SBOM (CycloneDX)
   - Signs artifacts with Sigstore
   - Creates GitHub Release with git-cliff changelog
   - Publishes to [PyPI](https://pypi.org/project/dns-aid/) via OIDC trusted publisher

## Reporting Issues

Use the [issue templates](https://github.com/infobloxopen/dns-aid-core/issues/new/choose):
- **Bug Report** — include Python version, OS, dns-aid version, backend, and `dns-aid doctor` output
- **Feature Request** — describe the motivation and proposed solution

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) for contributions, as required by the Linux Foundation.

By submitting a patch, you agree to the DCO. All commits must include a `Signed-off-by` line:

```bash
git commit -s -m "feat: your commit message"
```

This certifies that you wrote or have the right to submit the code under the project's open-source license.

> **Forgot to sign off?** Amend your last commit: `git commit --amend -s --no-edit`

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

## Questions?

- Open a [GitHub Discussion](https://github.com/infobloxopen/dns-aid-core/discussions) for general questions
- Open an [Issue](https://github.com/infobloxopen/dns-aid-core/issues) for bugs or feature requests
