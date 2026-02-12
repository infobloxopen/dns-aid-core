# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.6.x   | :white_check_mark: |
| < 0.6   | :x:                |

## Reporting a Vulnerability

We take the security of DNS-AID seriously. If you believe you have found a security vulnerability, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities using one of these methods:

1. **GitHub Private Reporting**: Go to the [Security tab](../../security) of this repository, click "Report a vulnerability", and provide a detailed description
2. **Email**: Send details to [iracic82@gmail.com](mailto:iracic82@gmail.com) (interim; will migrate to LF mailing list when provisioned)

### What to Include

- Type of vulnerability (e.g., injection, authentication bypass, DNSSEC bypass)
- Full paths of source file(s) related to the vulnerability
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 30 days for critical issues

## Security Architecture

### DNSSEC Validation

DNS-AID checks the **AD (Authenticated Data) flag** returned by the upstream resolver to determine whether a DNS response was DNSSEC-validated.

**Limitations:**

- DNS-AID does **not** perform independent DNSSEC chain validation (signature verification, key chain walking, or trust anchor management).
- The AD flag reflects the resolver's validation result. If the resolver is compromised or misconfigured, the AD flag may be unreliable.
- A validating resolver (e.g., Unbound, BIND with DNSSEC enabled) is required for meaningful results.

### DANE / TLSA Verification

DNS-AID checks for the **existence of TLSA records** associated with agent endpoints.

**Limitations:**

- DNS-AID does **not** perform certificate matching against TLSA records (i.e., it does not verify that the TLS certificate presented by the endpoint matches the TLSA record's certificate association data).
- TLSA existence is treated as an advisory signal, not a security enforcement mechanism.

### SSRF Protection

All outbound HTTP fetches (capability document retrieval, A2A agent card fetches) are protected against Server-Side Request Forgery:

- **HTTPS-only**: Only `https://` URLs are permitted; `http://` is rejected.
- **Private IP blocking**: Connections to private (RFC 1918), loopback (127.0.0.0/8), and link-local (169.254.0.0/16) addresses are blocked via DNS resolution checks before the request is made.
- **Redirect limits**: HTTP clients enforce `max_redirects=3` to prevent redirect-based SSRF.
- **Allowlist**: The `DNS_AID_FETCH_ALLOWLIST` environment variable can whitelist specific hostnames for testing purposes.

### Capability Document Integrity (cap_sha256)

When a `cap-sha256` (key65002) value is present in an SVCB record, DNS-AID verifies the integrity of the fetched capability document:

- The SHA-256 digest of the fetched document body is computed and base64url-encoded (unpadded).
- The computed digest is compared to the `cap-sha256` value from DNS.
- On mismatch, the capability document is rejected (treated as if the fetch failed).
- When no `cap-sha256` is present, the fetch proceeds without integrity verification.

### SVCB Custom Parameter Keys

DNS-AID uses SVCB SvcParamKeys in the **private-use range** (65001–65534) as defined by RFC 9460:

| Key     | Number   | Purpose                          |
| ------- | -------- | -------------------------------- |
| cap     | key65001 | Capability document URI          |
| cap-sha256 | key65002 | Capability document SHA-256 hash |
| bap     | key65003 | BANDAID Agent Profile URI        |
| policy  | key65004 | Policy document URI              |
| realm   | key65005 | Administrative realm             |
| sig     | key65006 | JWS signature                    |

These key numbers are in the private-use range pending IANA registration through the IETF draft process. The numeric form (`key65001`) is the default wire format; the string form (`cap`) can be enabled via the `DNS_AID_SVCB_STRING_KEYS` environment variable for human-readable debugging.

## Input Validation

All user inputs are validated before use:
- Agent names: alphanumeric with hyphens, max 63 characters
- Domain names: RFC 1035 compliant
- Ports: 1-65535
- TTL: 60-604800 seconds

## Network Security

- **MCP HTTP Transport**: Binds to `127.0.0.1` by default
- **AWS Credentials**: Never logged or exposed; use IAM roles in production
- **TLS/HTTPS**: All endpoint connections use HTTPS by default

## Security Best Practices

When using DNS-AID in production:

1. **Use IAM Roles**: Don't use access keys; use IAM roles for AWS services
2. **Enable DNSSEC**: Sign your zones with DNSSEC for authenticated DNS
3. **Use a Validating Resolver**: The AD flag is only meaningful with a DNSSEC-validating resolver
4. **Network Isolation**: Run MCP servers in isolated network segments
5. **Reverse Proxy**: Use nginx/traefik in front of HTTP transport
6. **Audit Logging**: Enable structlog for audit trails

## Known Security Limitations

- The mock backend is for testing only and should not be used in production
- DNSSEC validation depends on the upstream resolver's AD flag; no independent chain validation is performed
- DANE/TLSA support checks record existence only; no certificate matching is performed
- SVCB custom keys use private-use numbers pending IANA registration

## Security Updates

Security updates will be released as patch versions. Subscribe to releases to stay informed.
