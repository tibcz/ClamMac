"""Isolating files, putting them back, and getting rid of them."""

from __future__ import annotations

import stat

import pytest

from clammac.core.quarantine import Quarantine, QuarantineError


@pytest.fixture
def store(tmp_path):
    return Quarantine(root=tmp_path / "Quarantine")


@pytest.fixture
def suspect(tmp_path):
    target = tmp_path / "work" / "dropper.sh"
    target.parent.mkdir(parents=True)
    target.write_text("#!/bin/sh\necho nope\n")
    target.chmod(0o755)
    return target


class TestIsolating:
    def test_moves_the_file_out_of_the_way(self, store, suspect):
        entry = store.add(suspect, "Unix.Trojan.Test-1")
        assert not suspect.exists()
        assert store.payload_path(entry).exists()
        assert store.count() == 1

    def test_records_where_it_came_from(self, store, suspect):
        entry = store.add(suspect, "Unix.Trojan.Test-1", scan_id="abc123")
        assert entry.original_path == str(suspect)
        assert entry.signature == "Unix.Trojan.Test-1"
        assert entry.scan_id == "abc123"
        assert entry.original_mode == 0o755
        assert len(entry.sha256) == 64

    def test_the_stored_copy_cannot_be_read_or_run(self, store, suspect):
        entry = store.add(suspect, "Unix.Trojan.Test-1")
        mode = store.payload_path(entry).stat().st_mode
        assert not mode & (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

    def test_the_store_directory_is_private(self, store, suspect):
        store.add(suspect, "X")
        assert store.root.stat().st_mode & 0o077 == 0

    def test_refuses_a_directory(self, store, tmp_path):
        with pytest.raises(QuarantineError, match="directories cannot"):
            store.add(tmp_path, "X")

    def test_refuses_a_file_that_is_gone(self, store, tmp_path):
        with pytest.raises(QuarantineError, match="no longer exists"):
            store.add(tmp_path / "vanished", "X")

    def test_refuses_to_quarantine_the_quarantine(self, store, suspect):
        entry = store.add(suspect, "X")
        with pytest.raises(QuarantineError, match="already in quarantine"):
            store.add(store.payload_path(entry), "X")

    def test_reports_the_space_it_is_using(self, store, suspect):
        entry = store.add(suspect, "X")
        assert store.total_bytes() == entry.size > 0


class TestRestoring:
    def test_puts_the_file_back_with_its_permissions(self, store, suspect):
        original = suspect.read_text()
        entry = store.add(suspect, "X")

        restored = store.restore(entry.entry_id)
        assert restored == suspect
        assert restored.read_text() == original
        assert restored.stat().st_mode & 0o777 == 0o755
        assert store.count() == 0

    def test_does_not_overwrite_something_that_took_the_name(self, store, suspect):
        entry = store.add(suspect, "X")
        suspect.write_text("a different file lives here now")

        restored = store.restore(entry.entry_id)
        assert restored != suspect
        assert suspect.read_text() == "a different file lives here now"
        assert restored.exists()

    def test_can_restore_somewhere_else(self, store, suspect, tmp_path):
        entry = store.add(suspect, "X")
        elsewhere = tmp_path / "elsewhere" / "recovered.sh"
        assert store.restore(entry.entry_id, elsewhere) == elsewhere
        assert elsewhere.exists()

    def test_unknown_entry_raises(self, store):
        with pytest.raises(QuarantineError, match="no longer exists"):
            store.restore("not-a-real-id")


class TestDeleting:
    def test_removes_the_file_and_the_record(self, store, suspect):
        entry = store.add(suspect, "X")
        store.delete(entry.entry_id)
        assert not store.payload_path(entry).exists()
        assert store.count() == 0

    def test_shredding_overwrites_before_unlinking(self, store, tmp_path):
        target = tmp_path / "big.bin"
        target.write_bytes(b"A" * 8192)
        entry = store.add(target, "X")
        store.delete(entry.entry_id, shred=True)
        assert not store.payload_path(entry).exists()

    def test_deleting_several_reports_what_failed(self, store, suspect, tmp_path):
        second = tmp_path / "work" / "another.sh"
        second.write_text("x")
        first_id = store.add(suspect, "X").entry_id
        second_id = store.add(second, "Y").entry_id

        deleted, problems = store.delete_many([first_id, second_id, "bogus"])
        assert deleted == 2
        assert len(problems) == 1

    def test_emptying_removes_everything(self, store, tmp_path):
        for index in range(4):
            item = tmp_path / f"item{index}.bin"
            item.write_text("x")
            store.add(item, "X")
        assert store.empty() == 4
        assert store.count() == 0


class TestIndexHealth:
    def test_survives_a_corrupt_index(self, store, suspect):
        store.add(suspect, "X")
        store.index_path.write_text("{ not json at all")
        assert store.entries() == []

    def test_reports_entries_whose_file_vanished(self, store, suspect):
        entry = store.add(suspect, "X")
        store.payload_path(entry).unlink()
        assert [e.entry_id for e in store.verify()] == [entry.entry_id]

    def test_pruning_drops_them(self, store, suspect):
        entry = store.add(suspect, "X")
        store.payload_path(entry).unlink()
        assert store.prune_missing() == 1
        assert store.count() == 0

    def test_entries_are_newest_first(self, store, tmp_path):
        import time

        for index in range(3):
            item = tmp_path / f"item{index}.bin"
            item.write_text("x")
            store.add(item, f"Sig{index}")
            time.sleep(1.05)  # the stored timestamp has one-second resolution
        assert [e.signature for e in store.entries()] == ["Sig2", "Sig1", "Sig0"]
