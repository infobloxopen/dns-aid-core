# DNS-AID MCP Server Docker Image
#
# Build:
#   docker build -t dns-aid-mcp .
#
# Run:
#   docker run -p 8000:8000 dns-aid-mcp
#
# With AWS credentials:
#   docker run -p 8000:8000 \
#     -e AWS_ACCESS_KEY_ID=xxx \
#     -e AWS_SECRET_ACCESS_KEY=xxx \
#     dns-aid-mcp

# Use multi-stage build for smaller final image
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[mcp,route53]"

# Production image
FROM python:3.11-slim AS production

LABEL org.opencontainers.image.title="DNS-AID MCP Server"
LABEL org.opencontainers.image.description="DNS-based Agent Identification and Discovery"
LABEL org.opencontainers.image.source="https://github.com/iracic82/dns-aid"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Create non-root user for security
RUN groupadd --gid 1000 dnsaid \
    && useradd --uid 1000 --gid dnsaid --shell /bin/bash --create-home dnsaid

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/dns-aid* /usr/local/bin/

# Copy application
COPY --chown=dnsaid:dnsaid src/ src/
COPY --chown=dnsaid:dnsaid pyproject.toml README.md ./

# Switch to non-root user
USER dnsaid

# Expose MCP HTTP port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Run MCP server with HTTP transport
# Binds to 0.0.0.0 in container (safe due to container isolation)
ENTRYPOINT ["dns-aid-mcp"]
CMD ["--transport", "http", "--host", "0.0.0.0", "--port", "8000"]
