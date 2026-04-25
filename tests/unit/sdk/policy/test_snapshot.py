# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for RPZ snapshot and rollback."""

from __future__ import annotations

import json

from dns_aid.sdk.policy.compiler import RPZAction, RPZDirective
from dns_aid.sdk.policy.snapshot import (
    list_snapshots,
    load_latest_snapshot,
    save_snapshot,
)


def _make_directives(count: int = 3) -> list[RPZDirective]:
    return [
        RPZDirective(
            owner=f"evil{i}.example.com",
            action=RPZAction.NXDOMAIN,
            comment=f"Block evil{i}",
            source_rule="blocked_caller_domains",
        )
        for i in range(count)
    ]


class TestSaveSnapshot:
    def test_creates_snapshot_file(self, tmp_path) -> None:
        directives = _make_directives()
        path = save_snapshot(
            directives,
            rpz_zone="rpz.example.com",
            backend="nios",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        assert path.exists()
        assert path.suffix == ".json"

    def test_snapshot_content(self, tmp_path) -> None:
        directives = _make_directives(2)
        path = save_snapshot(
            directives,
            rpz_zone="rpz.test.com",
            backend="infoblox",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        data = json.loads(path.read_text())
        assert data["rpz_zone"] == "rpz.test.com"
        assert data["backend"] == "infoblox"
        assert data["mode"] == "enforce"
        assert len(data["directives"]) == 2
        assert data["directives"][0]["owner"] == "evil0.example.com"
        assert data["directives"][0]["action"] == "NXDOMAIN"

    def test_snapshot_filename_contains_zone(self, tmp_path) -> None:
        save_snapshot(
            _make_directives(1),
            rpz_zone="rpz.example.com",
            backend="nios",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        files = list(tmp_path.glob("rpz-example-com_*.json"))
        assert len(files) == 1


class TestLoadLatestSnapshot:
    def test_returns_none_when_no_snapshots(self, tmp_path) -> None:
        result = load_latest_snapshot("rpz.test.com", snapshot_dir=tmp_path)
        assert result is None

    def test_returns_none_when_dir_missing(self, tmp_path) -> None:
        result = load_latest_snapshot("rpz.test.com", snapshot_dir=tmp_path / "nope")
        assert result is None

    def test_loads_most_recent(self, tmp_path) -> None:
        # Save two snapshots — second should be "latest"
        save_snapshot(
            _make_directives(1),
            rpz_zone="rpz.test.com",
            backend="nios",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        save_snapshot(
            _make_directives(5),
            rpz_zone="rpz.test.com",
            backend="nios",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        latest = load_latest_snapshot("rpz.test.com", snapshot_dir=tmp_path)
        assert latest is not None
        assert latest.directive_count == 5

    def test_filters_by_zone(self, tmp_path) -> None:
        save_snapshot(
            _make_directives(2),
            rpz_zone="rpz.alpha.com",
            backend="nios",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        save_snapshot(
            _make_directives(4),
            rpz_zone="rpz.beta.com",
            backend="nios",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        alpha = load_latest_snapshot("rpz.alpha.com", snapshot_dir=tmp_path)
        beta = load_latest_snapshot("rpz.beta.com", snapshot_dir=tmp_path)
        assert alpha is not None and alpha.directive_count == 2
        assert beta is not None and beta.directive_count == 4


class TestListSnapshots:
    def test_empty_when_no_dir(self, tmp_path) -> None:
        assert list_snapshots(snapshot_dir=tmp_path / "nope") == []

    def test_lists_all(self, tmp_path) -> None:
        save_snapshot(
            _make_directives(1),
            rpz_zone="rpz.a.com",
            backend="nios",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        save_snapshot(
            _make_directives(2),
            rpz_zone="rpz.b.com",
            backend="nios",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        all_snaps = list_snapshots(snapshot_dir=tmp_path)
        assert len(all_snaps) == 2

    def test_filter_by_zone(self, tmp_path) -> None:
        save_snapshot(
            _make_directives(1),
            rpz_zone="rpz.a.com",
            backend="nios",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        save_snapshot(
            _make_directives(2),
            rpz_zone="rpz.b.com",
            backend="nios",
            mode="enforce",
            snapshot_dir=tmp_path,
        )
        a_snaps = list_snapshots("rpz.a.com", snapshot_dir=tmp_path)
        assert len(a_snaps) == 1
        assert a_snaps[0].rpz_zone == "rpz.a.com"
