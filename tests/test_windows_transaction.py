from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from windows_local_mcp.windows_transaction import (
    transactional_delete,
    transactional_write_bytes,
    windows_file_identity,
)

pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Transactional NTFS is the Windows workspace commit security boundary",
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _assert_normal_writer_blocked(path: Path, payload: bytes) -> None:
    with pytest.raises(OSError):
        path.write_bytes(payload)


def test_transactional_write_blocks_writer_until_commit(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"before")
    identity = windows_file_identity(target)
    hook_ran = False

    def race() -> None:
        nonlocal hook_ran
        hook_ran = True
        _assert_normal_writer_blocked(target, b"intruder")

    committed = transactional_write_bytes(
        target,
        b"after",
        expected_identity=(identity.volume_serial, identity.file_index),
        expected_size=identity.size,
        expected_sha256=_digest(b"before"),
        _before_commit=race,
    )

    assert hook_ran
    assert target.read_bytes() == b"after"
    assert (committed.volume_serial, committed.file_index) == (
        identity.volume_serial,
        identity.file_index,
    )


def test_transactional_write_rejects_same_bytes_with_replaced_identity(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"same")
    expected = windows_file_identity(target)

    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"same")
    replacement_identity = windows_file_identity(replacement)
    assert (replacement_identity.volume_serial, replacement_identity.file_index) != (
        expected.volume_serial,
        expected.file_index,
    )
    os.replace(replacement, target)

    with pytest.raises(RuntimeError, match="target changed"):
        transactional_write_bytes(
            target,
            b"new",
            expected_identity=(expected.volume_serial, expected.file_index),
            expected_size=expected.size,
            expected_sha256=_digest(b"same"),
        )

    assert target.read_bytes() == b"same"
    live = windows_file_identity(target)
    assert (live.volume_serial, live.file_index) == (
        replacement_identity.volume_serial,
        replacement_identity.file_index,
    )


def test_transactional_create_reserves_missing_name(tmp_path: Path) -> None:
    target = tmp_path / "new.bin"
    hook_ran = False

    def race() -> None:
        nonlocal hook_ran
        hook_ran = True
        _assert_normal_writer_blocked(target, b"intruder")

    committed = transactional_write_bytes(
        target,
        b"created",
        expected_identity=None,
        expected_size=None,
        expected_sha256=None,
        _before_commit=race,
    )

    assert hook_ran
    assert target.read_bytes() == b"created"
    live = windows_file_identity(target)
    assert (live.volume_serial, live.file_index) == (
        committed.volume_serial,
        committed.file_index,
    )


def test_transactional_delete_blocks_writer_until_commit(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"before")
    identity = windows_file_identity(target)
    hook_ran = False

    def race() -> None:
        nonlocal hook_ran
        hook_ran = True
        _assert_normal_writer_blocked(target, b"intruder")

    transactional_delete(
        target,
        expected_identity=(identity.volume_serial, identity.file_index),
        expected_size=identity.size,
        expected_sha256=_digest(b"before"),
        _before_commit=race,
    )

    assert hook_ran
    assert not target.exists()
