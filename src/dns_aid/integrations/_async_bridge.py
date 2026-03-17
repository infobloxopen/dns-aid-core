# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Async/sync bridge for framework integrations."""

from __future__ import annotations

import asyncio
from typing import Any, Coroutine


def run_async(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run an async coroutine from a sync context.

    Handles the case where an event loop is already running
    (e.g., Jupyter, FastAPI) by running in a separate thread.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)
