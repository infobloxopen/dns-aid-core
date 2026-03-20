# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Provider-managed DNS-AID record publishers."""

from dns_aid.sdk.publishers.apphub import AppHubPublisher, run_polling_sync
from dns_aid.sdk.publishers.base import AgentRecordPublisher
from dns_aid.sdk.publishers.harness import DiscoveryBootstrapResult, DiscoveryValidationHarness
from dns_aid.sdk.publishers.lattice import LatticePublisher, run_startup_sync
from dns_aid.sdk.publishers.models import (
    AppHubPublisherConfig,
    AppHubServiceRef,
    AppHubServiceSnapshot,
    LatticePublisherConfig,
    LatticeServiceRef,
    LatticeServiceSnapshot,
    PublishedAgentState,
    SyncResult,
)

__all__ = [
    "AgentRecordPublisher",
    "SyncResult",
    "PublishedAgentState",
    "AppHubPublisher",
    "AppHubPublisherConfig",
    "AppHubServiceRef",
    "AppHubServiceSnapshot",
    "LatticePublisher",
    "LatticePublisherConfig",
    "LatticeServiceRef",
    "LatticeServiceSnapshot",
    "DiscoveryValidationHarness",
    "DiscoveryBootstrapResult",
    "run_polling_sync",
    "run_startup_sync",
]
