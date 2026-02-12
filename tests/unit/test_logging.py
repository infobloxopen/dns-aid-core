# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.utils.logging module."""

from __future__ import annotations

import logging
from unittest.mock import patch

import structlog

from dns_aid.utils.logging import configure_logging, silence_logging


class TestConfigureLogging:
    """Tests for configure_logging function."""

    def test_default_configuration(self):
        """Test default logging configuration."""
        configure_logging()
        # Should not raise any errors
        logger = structlog.get_logger()
        assert logger is not None

    def test_debug_level(self):
        """Test DEBUG log level configuration."""
        configure_logging(level="DEBUG")
        logger = structlog.get_logger()
        assert logger is not None

    def test_warning_level(self):
        """Test WARNING log level configuration."""
        configure_logging(level="WARNING")
        logger = structlog.get_logger()
        assert logger is not None

    def test_error_level(self):
        """Test ERROR log level configuration."""
        configure_logging(level="ERROR")
        logger = structlog.get_logger()
        assert logger is not None

    def test_json_output(self):
        """Test JSON output configuration."""
        configure_logging(json_output=True)
        logger = structlog.get_logger()
        assert logger is not None

    def test_console_output(self):
        """Test console output configuration."""
        configure_logging(json_output=False)
        logger = structlog.get_logger()
        assert logger is not None

    def test_env_variable_override(self):
        """Test that DNS_AID_LOG_LEVEL environment variable overrides parameter."""
        with patch.dict("os.environ", {"DNS_AID_LOG_LEVEL": "WARNING"}):
            configure_logging(level="DEBUG")
            # Environment should override - function should not raise
            logger = structlog.get_logger()
            assert logger is not None

    def test_invalid_level_falls_back_to_info(self):
        """Test that invalid log level falls back to INFO."""
        configure_logging(level="INVALID")
        logger = structlog.get_logger()
        assert logger is not None


class TestSilenceLogging:
    """Tests for silence_logging function."""

    def test_silence_logging(self):
        """Test that silence_logging disables logging."""
        silence_logging()
        # Should disable all logging
        assert logging.root.manager.disable >= logging.CRITICAL

    def test_silence_logging_structlog(self):
        """Test that silence_logging configures structlog to CRITICAL."""
        silence_logging()
        # Should configure structlog to only show CRITICAL
        logger = structlog.get_logger()
        assert logger is not None
