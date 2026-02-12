# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
SDK configuration.

Configures the AgentClient behavior including timeouts, exporters, and caller identity.
"""

from __future__ import annotations

import os

from pydantic import BaseModel, Field


class SDKConfig(BaseModel):
    """Configuration for the DNS-AID SDK."""

    # HTTP client settings
    timeout_seconds: float = Field(
        default=30.0,
        description="Default timeout for agent invocations in seconds.",
    )
    max_retries: int = Field(
        default=0,
        description="Max retry attempts on transient failures.",
    )

    # Caller identity (optional, added to signals)
    caller_id: str | None = Field(
        default=None,
        description="Identifier for the calling agent/service.",
    )

    # OTEL settings
    otel_enabled: bool = Field(
        default=False,
        description="Enable OpenTelemetry export.",
    )
    otel_endpoint: str | None = Field(
        default=None,
        description="OTLP endpoint URL.",
    )
    otel_export_format: str = Field(
        default="otlp",
        description="Export format: otlp, console, or noop.",
    )

    # HTTP push (fire-and-forget POST to telemetry API)
    http_push_url: str | None = Field(
        default=None,
        description="URL to POST signals to (e.g., https://api.example.com/api/v1/telemetry/signals). "
        "If set, enables HTTP push automatically.",
    )

    # Console logging
    console_signals: bool = Field(
        default=False,
        description="Print signals to console/log for debugging.",
    )

    # Telemetry API for fetching community rankings
    telemetry_api_url: str | None = Field(
        default=None,
        description="Base URL for telemetry API to fetch community-wide rankings. "
        "If not set, fetch_rankings() returns an empty list.",
    )

    @classmethod
    def from_env(cls) -> SDKConfig:
        """Build config from environment variables."""
        return cls(
            timeout_seconds=float(os.getenv("DNS_AID_SDK_TIMEOUT", "30")),
            max_retries=int(os.getenv("DNS_AID_SDK_MAX_RETRIES", "0")),
            caller_id=os.getenv("DNS_AID_SDK_CALLER_ID"),
            http_push_url=os.getenv("DNS_AID_SDK_HTTP_PUSH_URL"),
            otel_enabled=os.getenv("DNS_AID_SDK_OTEL_ENABLED", "").lower() == "true",
            otel_endpoint=os.getenv("DNS_AID_SDK_OTEL_ENDPOINT"),
            otel_export_format=os.getenv("DNS_AID_SDK_OTEL_EXPORT_FORMAT", "otlp"),
            console_signals=os.getenv("DNS_AID_SDK_CONSOLE_SIGNALS", "").lower() == "true",
            telemetry_api_url=os.getenv("DNS_AID_SDK_TELEMETRY_API_URL"),
        )
