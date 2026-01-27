# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Reporting a Vulnerability

We take the security of DNS-AID seriously. If you believe you have found a security vulnerability, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities using one of these methods:

1. **GitHub Private Reporting**: Go to the [Security tab](../../security) of this repository, click "Report a vulnerability", and provide a detailed description
2. **Email**: Send details to [dns-aid-private@lists.lfaidata.foundation](mailto:dns-aid-private@lists.lfaidata.foundation) (once the LF mailing list is provisioned)

Do not file security vulnerabilities as public GitHub issues.

### What to Include

Please include the following information:

- Type of vulnerability (e.g., injection, authentication bypass, DNSSEC bypass)
- Full paths of source file(s) related to the vulnerability
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 30 days for critical issues

### Security Considerations

DNS-AID handles DNS operations which require special security attention:

#### DNS-Specific Risks

- **DNS Injection**: All domain names and agent names are validated against RFC 1035 standards
- **Zone Transfer Attacks**: The library only performs authorized operations with proper credentials
- **DNSSEC Bypass**: The validator checks DNSSEC status but does not bypass security checks

#### Network Security

- **MCP HTTP Transport**: Binds to `127.0.0.1` by default for security
- **AWS Credentials**: Never logged or exposed; use IAM roles in production
- **TLS/HTTPS**: All endpoint connections use HTTPS by default

#### Input Validation

All user inputs are validated before use:
- Agent names: alphanumeric with hyphens, max 63 characters
- Domain names: RFC 1035 compliant
- Ports: 1-65535
- TTL: 60-604800 seconds

## Security Best Practices

When using DNS-AID in production:

1. **Use IAM Roles**: Don't use access keys; use IAM roles for AWS services
2. **Enable DNSSEC**: Sign your zones with DNSSEC for authenticated DNS
3. **Network Isolation**: Run MCP servers in isolated network segments
4. **Reverse Proxy**: Use nginx/traefik in front of HTTP transport
5. **Audit Logging**: Enable structlog for audit trails

## Known Security Limitations

- The mock backend is for testing only and should not be used in production
- DNSSEC validation requires a validating resolver
- DANE/TLSA support is advisory only

## Security Updates

Security updates will be released as patch versions. Subscribe to releases to stay informed.
