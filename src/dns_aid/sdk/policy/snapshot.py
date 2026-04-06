# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
RPZ zone snapshot and rollback.

Captures the state of RPZ directives before a push so they can be
restored if something goes wrong.  Snapshots are stored as timestamped
JSON files under ``.dns-aid/snapshots/``.

Usage::

    # Before pushing, save a snapshot
    path = save_snapshot(result, rpz_zone="rpz.nordstrom.com", backend="nios")

    # Later, restore from the most recent snapshot
    snapshot = load_latest_snapshot(rpz_zone="rpz.nordstrom.com")
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

SNAPSHOT_DIR = Path(".dns-aid/snapshots")


class RPZSnapshot(BaseModel):
    """A point-in-time capture of RPZ directives for a zone."""

    timestamp: str
    rpz_zone: str
    backend: str
    mode: str
    directives: list[dict[str, str]] = Field(default_factory=list)

    @property
    def directive_count(self) -> int:
        return len(self.directives)


def save_snapshot(
    rpz_directives: list,
    *,
    rpz_zone: str,
    backend: str,
    mode: str,
    snapshot_dir: Path = SNAPSHOT_DIR,
) -> Path:
    """Save current RPZ directives to a timestamped snapshot file.

    Args:
        rpz_directives: List of RPZDirective objects to snapshot.
        rpz_zone: The RPZ zone name.
        backend: Backend name (nios, infoblox, file).
        mode: Enforcement mode (shadow, enforce).
        snapshot_dir: Directory to write snapshots to.

    Returns:
        Path to the written snapshot file.
    """
    now = datetime.now(UTC)
    snapshot = RPZSnapshot(
        timestamp=now.isoformat(),
        rpz_zone=rpz_zone,
        backend=backend,
        mode=mode,
        directives=[
            {
                "owner": d.owner,
                "action": d.action.value,
                "comment": d.comment,
                "source_rule": d.source_rule,
            }
            for d in rpz_directives
        ],
    )

    snapshot_dir.mkdir(parents=True, exist_ok=True)
    safe_zone = rpz_zone.replace(".", "-")
    filename = f"{safe_zone}_{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    path = snapshot_dir / filename
    path.write_text(json.dumps(snapshot.model_dump(), indent=2))
    return path


def load_latest_snapshot(
    rpz_zone: str,
    *,
    snapshot_dir: Path = SNAPSHOT_DIR,
) -> RPZSnapshot | None:
    """Load the most recent snapshot for a given RPZ zone.

    Returns None if no snapshots exist for the zone.
    """
    if not snapshot_dir.exists():
        return None

    safe_zone = rpz_zone.replace(".", "-")
    candidates = sorted(
        snapshot_dir.glob(f"{safe_zone}_*.json"),
        reverse=True,
    )
    if not candidates:
        return None

    raw = json.loads(candidates[0].read_text())
    return RPZSnapshot.model_validate(raw)


def list_snapshots(
    rpz_zone: str | None = None,
    *,
    snapshot_dir: Path = SNAPSHOT_DIR,
) -> list[RPZSnapshot]:
    """List all snapshots, optionally filtered by zone.  Most recent first."""
    if not snapshot_dir.exists():
        return []

    pattern = "*.json"
    if rpz_zone:
        safe_zone = rpz_zone.replace(".", "-")
        pattern = f"{safe_zone}_*.json"

    snapshots = []
    for path in sorted(snapshot_dir.glob(pattern), reverse=True):
        raw = json.loads(path.read_text())
        snapshots.append(RPZSnapshot.model_validate(raw))
    return snapshots
