"""Issue #118: pending-file deletion must not race the budget scans.

Regression for the Codex P2 on PR #115: a worker-completion thread
calling _delete_paid_pending() without _PENDING_LOCK could unlink a
file after a budget scan's glob discovered it but before p.stat()
ran, raising FileNotFoundError into consent creation (uncaught 500).
"""
import pathlib
import threading
import uuid

import pytest

from app import main


@pytest.fixture
def pending_dir(monkeypatch, tmp_path):
    d = tmp_path / "pending"
    d.mkdir()
    monkeypatch.setattr(main, "_PAID_PENDING_DIR", str(d))
    return d


def _vanishing_glob(real_glob_owner):
    """Wrap Path.glob so that, starting with the SECOND pending-*.bin
    glob (the first is cleanup_pending_uploads, which already
    tolerates the race), each discovered file is unlinked after the
    glob yields it but before the caller stats it — the exact
    interleaving from the finding."""
    real_glob = pathlib.Path.glob
    calls = {"n": 0}

    def glob(self, pattern):
        if pattern == "pending-*.bin":
            calls["n"] += 1
        vanish = pattern == "pending-*.bin" and calls["n"] >= 2
        found = list(real_glob(self, pattern))
        if vanish:
            # Snapshot taken; a racing deleter unlinks everything
            # before the caller stats any of it.
            for p in found:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
        yield from found

    return glob


def test_store_paid_pending_survives_mid_scan_delete(pending_dir, monkeypatch):
    main._store_paid_pending("a" * 32, "a.log", b"x" * 16)
    monkeypatch.setattr(pathlib.Path, "glob", _vanishing_glob(pathlib.Path))
    # Pre-fix tree: FileNotFoundError propagates out of the budget scan.
    main._store_paid_pending("b" * 32, "b.log", b"y" * 16)


def test_store_compare_pending_survives_mid_scan_delete(pending_dir, monkeypatch):
    main._store_compare_pending(str(uuid.uuid4()), "a.log", b"x" * 8, "b.log", b"y" * 8)
    monkeypatch.setattr(pathlib.Path, "glob", _vanishing_glob(pathlib.Path))
    main._store_compare_pending(str(uuid.uuid4()), "a.log", b"x" * 8, "b.log", b"y" * 8)


def test_delete_paid_pending_serialized_on_pending_lock(pending_dir):
    main._store_paid_pending("e" * 32, "e.log", b"z" * 8)
    path = pathlib.Path(main._paid_pending_path("e" * 32))
    assert path.exists()
    done = threading.Event()

    def deleter():
        main._delete_paid_pending("e" * 32)
        done.set()

    with main._PENDING_LOCK:
        t = threading.Thread(target=deleter)
        t.start()
        # While the lock is held, the delete must not complete.
        assert not done.wait(timeout=1.0)
        assert path.exists()
    t.join(timeout=5)
    assert done.is_set()
    assert not path.exists()
