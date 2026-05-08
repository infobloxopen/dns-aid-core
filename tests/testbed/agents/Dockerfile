FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dns-aid-core from the mounted source in editable mode
# The volume mount happens at runtime; we pre-install deps here so
# the image layer is cached and startup is fast.
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir -e ".[ddns,cli,mcp]"
