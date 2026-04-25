# Maintainers

This file lists the current maintainers of the DNS-AID project. The project is actively seeking additional maintainers to ensure long-term sustainability under the Linux Foundation.

## Current Maintainers

| Name | GitHub | Affiliation | Role | Since |
|------|--------|-------------|------|-------|
| Igor Racic | [@iracic82](https://github.com/iracic82) | Infoblox | Project Lead | 2024-12 |

## Active Contributors

The following contributors have shipped substantive code or research that informs the implementation. Listing here does not confer maintainer rights or responsibilities — it acknowledges material contribution.

| Name | GitHub | Affiliation | Contribution |
|------|--------|-------------|--------------|
| Ingmar Van Glabbeek | [@ivanglabbeek](https://github.com/ivanglabbeek) | Infoblox | bind-aid (BIND 9 fork integrating the DNS-AID policy layer at Layer 0); related design work on the Trust Engine and Governance phase |

## Desired Roles

The project is looking for maintainers in the following areas:

| Role | Responsibilities | Status |
|------|-----------------|--------|
| DNS Standards Lead | IETF draft alignment, RFC compliance review | **Open** |
| Security Lead | DNSSEC/DANE validation, vulnerability triage | **Open** |
| Backend Maintainer | DNS provider backends (Route53, Cloudflare, Infoblox, DDNS) | **Open** |
| CI/Release Engineer | GitHub Actions, release automation, SBOM generation | **Open** |
| Documentation Lead | User guides, API docs, architecture documentation | **Open** |

## How to Become a Maintainer

See [GOVERNANCE.md](GOVERNANCE.md) for the process. In brief:

1. Contribute sustained, high-quality PRs over at least 3 months
2. Be nominated by an existing maintainer
3. Receive approval via Committer vote

## Sustainability and Bus Factor

DNS-AID is currently a **single-maintainer project** (bus factor = 1). This is acknowledged transparently as the project's most significant sustainability risk and is the reason `MAINTAINERS.md` lists the open roles above.

**Active mitigations**

- **Public open standard** — DNS-AID is a reference implementation of an IETF draft (`draft-mozleywilliams-dnsop-dnsaid`). The protocol is independent of any single implementation, so the standard remains viable even if this implementation pauses.
- **Conservative architecture** — the codebase deliberately favors stdlib, well-known third-party libraries (`dnspython`, `httpx`), and standard DNS records (RFC 9460 SVCB, RFC 4033-4035 DNSSEC, RFC 6698 DANE) over bespoke abstractions. New maintainers should be productive in days, not months.
- **Comprehensive automation** — CI runs lint, type-check, unit tests across Python 3.11/3.12/3.13, mock integration tests, CodeQL SAST, Bandit, OpenSSF Scorecard, dependency audit, SBOM generation, and Sigstore-signed releases on every PR. New contributors get fast, machine-checked feedback.
- **DCO + SPDX** enforced on every commit — keeps provenance unambiguous as the contributor base grows.
- **Backed by Infoblox** — the project is hosted under the [`infobloxopen`](https://github.com/infobloxopen) organization. Infoblox provides the DNS expertise that motivated DNS-AID and has committed engineering time to its development.

**Goals before LF graduation**

- 2+ maintainers from at least 2 organizations
- Documented succession process if the current maintainer becomes unavailable
- An Infoblox employee + a community contributor on the maintainer list

If you are interested in contributing in a maintainer capacity, please open a discussion at [dns-aid-core/discussions](https://github.com/infobloxopen/dns-aid-core/discussions) or contact the project lead directly.

## Release process and namespace ownership

For full transparency:

- **PyPI publishing** — the `dns-aid` package on [PyPI](https://pypi.org/project/dns-aid/) is published exclusively via [PyPI Trusted Publisher OIDC](https://docs.pypi.org/trusted-publishers/) tied to this repository's `.github/workflows/release.yml`. No long-lived API tokens exist. Only commits that land on a `v*` tag in this repo can publish to PyPI.
- **Release artifacts** — every wheel and sdist is signed with [Sigstore](https://www.sigstore.dev/) cosign keyless OIDC during the release workflow. SBOM (`sbom.json`) is generated via `cyclonedx-py` and signed alongside the artifacts.
- **GitHub branch protection** — `main` requires 1 approving review and successful status checks. During the current single-maintainer phase, the project lead admin-merges with documented PR descriptions and mandatory CI as the gate. This will tighten to required external review once a second maintainer joins.

## Contact

- GitHub Issues: [dns-aid-core/issues](https://github.com/infobloxopen/dns-aid-core/issues)
- Discussions: [dns-aid-core/discussions](https://github.com/infobloxopen/dns-aid-core/discussions)
