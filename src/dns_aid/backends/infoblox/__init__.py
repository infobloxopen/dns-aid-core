# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Infoblox DNS backends for DNS-AID.

Supports both Infoblox platforms:
- BloxOne DDI (cloud): InfobloxBloxOneBackend
- NIOS (on-prem): InfobloxNIOSBackend (planned)

Example:
    >>> from dns_aid.backends.infoblox import InfobloxBloxOneBackend
    >>> backend = InfobloxBloxOneBackend(api_key="your-api-key")
    >>> await backend.create_svcb_record(...)
"""

from dns_aid.backends.infoblox.bloxone import InfobloxBloxOneBackend

# Alias for convenience
InfobloxBackend = InfobloxBloxOneBackend

__all__ = [
    "InfobloxBloxOneBackend",
    "InfobloxBackend",
    # "InfobloxNIOSBackend",  # Coming soon
]
