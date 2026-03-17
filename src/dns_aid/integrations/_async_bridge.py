# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Async/sync bridge for framework integrations.

This module provides a safe way to call async coroutines from synchronous
contexts, handling edge cases like nested event loops in Jupyter, FastAPI,
and ASGI frameworks.
"""

from __future__ import annotations

import asyncio
import contextvars
import threading
from typing import Any, Coroutine, TypeVar

T = TypeVar("T")


def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """Run an async coroutine from a sync context.

    Handles the case where an event loop is already running
    (e.g., Jupyter, FastAPI, ASGI) by running in a dedicated thread
    with its own event loop that propagates context variables.

    This avoids the deadlock that occurs with ``asyncio.run()`` inside
    a ``ThreadPoolExecutor`` when ``uvloop`` is installed, and properly
    copies ``contextvars`` so ASGI middleware context is preserved.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # We're inside an existing event loop (Jupyter, FastAPI, etc.).
        # Spawn a dedicated thread with a fresh loop to avoid deadlocks.
        ctx = contextvars.copy_context()
        result: Any = None
        exception: BaseException | None = None

        def _run_in_thread() -> None:
            nonlocal result, exception
            try:
                result = ctx.run(asyncio.run, coro)
            except BaseException as exc:
                exception = exc

        thread = threading.Thread(target=_run_in_thread, daemon=True)
        thread.start()
        thread.join()

        if exception is not None:
            raise exception
        return result  # type: ignore[return-value]
    else:
        return asyncio.run(coro)
