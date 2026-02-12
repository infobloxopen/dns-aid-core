# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Logging configuration for DNS-AID.

Uses structlog for structured logging with configurable output levels.
"""

from __future__ import annotations

import logging
import os
import sys

import structlog


def configure_logging(
    level: str = "INFO",
    json_output: bool = False,
) -> None:
    """
    Configure logging for DNS-AID.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        json_output: If True, output logs as JSON
    """
    # Get level from environment or parameter
    level = os.environ.get("DNS_AID_LOG_LEVEL", level).upper()

    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=getattr(logging, level, logging.INFO),
    )

    # Configure structlog
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,  # type: ignore[arg-type]
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level, logging.INFO)),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def silence_logging() -> None:
    """Silence all logging (for CLI in quiet mode)."""
    logging.disable(logging.CRITICAL)
    # Use CRITICAL level which is the highest valid level
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL),
    )
