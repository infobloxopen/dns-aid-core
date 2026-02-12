# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
OpenTelemetry integration for DNS-AID SDK.

Provides span and metric export for agent invocations.
Completely opt-in — works as no-op when opentelemetry is not installed.
"""

from __future__ import annotations

from typing import Any

import structlog

from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.models import InvocationSignal

logger = structlog.get_logger(__name__)

# Check if OpenTelemetry is available
_otel_available = False
try:
    from opentelemetry import metrics, trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import (
        ConsoleMetricExporter,
        PeriodicExportingMetricReader,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        ConsoleSpanExporter,
        SimpleSpanProcessor,
    )
    from opentelemetry.trace import StatusCode

    _otel_available = True
except ImportError:
    pass


# Span attribute names
ATTR_AGENT_NAME = "dns_aid.agent.name"
ATTR_AGENT_DOMAIN = "dns_aid.agent.domain"
ATTR_AGENT_PROTOCOL = "dns_aid.agent.protocol"
ATTR_AGENT_ENDPOINT = "dns_aid.agent.endpoint"
ATTR_INVOCATION_METHOD = "dns_aid.invocation.method"
ATTR_INVOCATION_STATUS = "dns_aid.invocation.status"
ATTR_INVOCATION_LATENCY = "dns_aid.invocation.latency_ms"
ATTR_INVOCATION_COST = "dns_aid.invocation.cost_units"
ATTR_SECURITY_DNSSEC = "dns_aid.security.dnssec"


def _parse_signal_fqdn(fqdn: str) -> tuple[str | None, str | None]:
    """Parse agent_name and domain from an FQDN like ``_name._proto._agents.domain``."""
    parts = fqdn.split("._agents.")
    if len(parts) == 2:
        name_parts = parts[0].lstrip("_").split("._")
        agent_name = name_parts[0] if name_parts else None
        return agent_name, parts[1]
    return None, None


class TelemetryManager:
    """
    Manages OpenTelemetry TracerProvider and MeterProvider for DNS-AID SDK.

    Singleton — shared across AgentClient instances.
    """

    _instance: TelemetryManager | None = None

    def __init__(self, config: SDKConfig) -> None:
        self._config = config
        self._initialized = False
        self._tracer: Any = None
        self._tracer_provider: Any = None
        self._meter_provider: Any = None
        self._duration_histogram: Any = None
        self._invocation_counter: Any = None
        self._error_counter: Any = None
        self._cost_counter: Any = None

    @classmethod
    def get_or_create(cls, config: SDKConfig) -> TelemetryManager:
        """Get or create the singleton TelemetryManager."""
        if cls._instance is None:
            cls._instance = cls(config)
            if config.otel_enabled:
                cls._instance._initialize()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Shut down OTEL providers and reset the singleton (for testing)."""
        if cls._instance is not None:
            cls._instance.shutdown()
        cls._instance = None

    def shutdown(self) -> None:
        """Gracefully shut down OTEL providers, flushing pending exports."""
        import contextlib

        if self._meter_provider is not None:
            with contextlib.suppress(Exception):
                self._meter_provider.shutdown()
            self._meter_provider = None
        if self._tracer_provider is not None:
            with contextlib.suppress(Exception):
                self._tracer_provider.shutdown()
            self._tracer_provider = None
        self._initialized = False

    @property
    def is_available(self) -> bool:
        return _otel_available and self._initialized

    def _initialize(self) -> None:
        """Initialize OTEL providers based on config."""
        if not _otel_available:
            logger.warning("OpenTelemetry not installed — OTEL export disabled")
            return

        resource = Resource.create(
            {
                "service.name": "dns-aid-sdk",
                "service.version": "0.4.9",
            }
        )

        export_format = self._config.otel_export_format

        # Trace provider
        tracer_provider = TracerProvider(resource=resource)

        if export_format == "console":
            tracer_provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        elif export_format == "otlp" and self._config.otel_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                    OTLPSpanExporter,
                )

                otlp_exporter = OTLPSpanExporter(endpoint=self._config.otel_endpoint)
                tracer_provider.add_span_processor(SimpleSpanProcessor(otlp_exporter))
            except ImportError:
                logger.warning("OTLP exporter not installed — using console")
                tracer_provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

        trace.set_tracer_provider(tracer_provider)
        self._tracer_provider = tracer_provider
        self._tracer = trace.get_tracer("dns-aid-sdk")

        # Meter provider
        if export_format == "console":
            reader = PeriodicExportingMetricReader(
                ConsoleMetricExporter(),
                export_interval_millis=10000,
            )
        elif export_format == "otlp" and self._config.otel_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                    OTLPMetricExporter,
                )

                otlp_metric_exporter = OTLPMetricExporter(endpoint=self._config.otel_endpoint)
                reader = PeriodicExportingMetricReader(otlp_metric_exporter)
            except ImportError:
                reader = PeriodicExportingMetricReader(ConsoleMetricExporter())
        else:
            reader = PeriodicExportingMetricReader(
                ConsoleMetricExporter(),
                export_interval_millis=60000,
            )

        meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(meter_provider)
        self._meter_provider = meter_provider
        meter = metrics.get_meter("dns-aid-sdk")

        # Create instruments
        self._duration_histogram = meter.create_histogram(
            name="dns_aid.invocation.duration",
            description="Agent invocation duration in milliseconds",
            unit="ms",
        )
        self._invocation_counter = meter.create_counter(
            name="dns_aid.invocation.count",
            description="Number of agent invocations by status",
        )
        self._error_counter = meter.create_counter(
            name="dns_aid.invocation.error_count",
            description="Number of failed agent invocations",
        )
        self._cost_counter = meter.create_counter(
            name="dns_aid.invocation.cost",
            description="Cumulative invocation cost in cost_units",
        )

        self._initialized = True
        logger.info(
            "OTEL initialized",
            export_format=export_format,
            endpoint=self._config.otel_endpoint,
        )

    @staticmethod
    def _build_span_attributes(signal: InvocationSignal) -> dict[str, Any]:
        """Build OTEL span attribute dict from an invocation signal."""
        attributes: dict[str, Any] = {
            ATTR_AGENT_ENDPOINT: signal.agent_endpoint,
            ATTR_AGENT_PROTOCOL: signal.protocol,
            ATTR_INVOCATION_STATUS: signal.status.value,
            ATTR_INVOCATION_LATENCY: signal.invocation_latency_ms,
            ATTR_SECURITY_DNSSEC: signal.dnssec_validated,
        }
        if signal.method:
            attributes[ATTR_INVOCATION_METHOD] = signal.method
        if signal.cost_units is not None:
            attributes[ATTR_INVOCATION_COST] = signal.cost_units

        agent_name, agent_domain = _parse_signal_fqdn(signal.agent_fqdn)
        if agent_domain:
            attributes[ATTR_AGENT_DOMAIN] = agent_domain
        if agent_name:
            attributes[ATTR_AGENT_NAME] = agent_name

        return attributes

    def record_signal(self, signal: InvocationSignal) -> None:
        """Record a signal as an OTEL span and update metrics."""
        if not self.is_available:
            return

        attributes = self._build_span_attributes(signal)

        with self._tracer.start_as_current_span(
            name=f"dns-aid.invoke {signal.agent_fqdn}",
            attributes=attributes,
        ) as span:
            if signal.status.value != "success":
                span.set_status(StatusCode.ERROR, signal.error_message or "")

        label_attrs = {
            "protocol": signal.protocol,
            "status": signal.status.value,
        }

        if self._duration_histogram:
            self._duration_histogram.record(signal.invocation_latency_ms, label_attrs)

        if self._invocation_counter:
            self._invocation_counter.add(1, label_attrs)

        if signal.status.value in ("error", "timeout", "refused") and self._error_counter:
            self._error_counter.add(1, label_attrs)

        if signal.cost_units is not None and self._cost_counter:
            self._cost_counter.add(signal.cost_units, {"protocol": signal.protocol})
