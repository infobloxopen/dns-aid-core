# Contributing to DNS-AID

Thank you for your interest in contributing to DNS-AID! This project aims to be contributed to the Linux Foundation Agent AI Foundation.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/dns-aid-core.git
   cd dns-aid-core
   ```

3. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

4. Install development dependencies:
   ```bash
   pip install -e ".[all]"
   ```

5. Run tests to verify setup:
   ```bash
   pytest
   ```

## Development Workflow

### Code Style

- Follow PEP 8 guidelines
- Use type hints for all public functions
- Keep line length under 100 characters
- Use meaningful variable and function names

We use `ruff` for linting:
```bash
ruff check src/
ruff format src/
```

### Testing

- Write tests for all new functionality
- Maintain test coverage above 80%
- Use pytest for testing

```bash
# Run all unit tests
pytest tests/unit/

# Run with coverage
pytest --cov=dns_aid

# Run specific test file
pytest tests/unit/test_models.py
```

### Integration Tests

Integration tests require real DNS backend credentials and are skipped by default.

**Route 53:**
```bash
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export DNS_AID_TEST_ZONE="your-zone.com"
pytest tests/integration/test_route53.py -v
```

**Infoblox BloxOne:**
```bash
export INFOBLOX_API_KEY="your-api-key"
export INFOBLOX_TEST_ZONE="your-zone.com"
export INFOBLOX_DNS_VIEW="default"
pytest tests/integration/test_infoblox.py -v
```

> **Note**: Integration tests create and delete real DNS records. Use a test zone to avoid affecting production.

### Type Checking

We use mypy for type checking:
```bash
mypy src/dns_aid
```

## Submitting Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit:
   ```bash
   git add .
   git commit -m "Add: brief description of changes"
   ```

3. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. Open a Pull Request against the `main` branch

### Commit Message Guidelines

Use clear, descriptive commit messages:
- `Add: new feature description`
- `Fix: bug description`
- `Update: what was changed`
- `Remove: what was removed`
- `Refactor: what was refactored`

## Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Update documentation if needed
- Add tests for new functionality
- Ensure all tests pass
- Update CHANGELOG.md for significant changes

## Reporting Issues

When reporting issues, please include:
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) for contributions, as required by the Linux Foundation.

By submitting a patch, you agree to the DCO. All commits must include a `Signed-off-by` line:

```bash
git commit -s -m "Your commit message"
```

This certifies that you wrote or have the right to submit the code under the project's open-source license.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

## Questions?

Open an issue for any questions about contributing.
