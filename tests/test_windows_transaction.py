from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from windows_local_mcp.windows_transaction import (
    transactional_copy_file,
    transactional_delete,
    transactional_move_file,
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


def _identity_tuple(path: Path) -> tuple[int, int]:
    identity = windows_file_identity(path)
    return identity.volume_serial, identity.file_index


def test_transactional_copy_blocks_source_replacement_and_publishes_exact_bytes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    replacement = tmp_path / "replacement.bin"
    source.write_bytes(b"source")
    replacement.write_bytes(b"replacement")
    source_identity = windows_file_identity(source)

    def race() -> None:
        with pytest.raises(OSError):
            os.replace(replacement, source)

    transactional_copy_file(
        source,
        destination,
        expected_source_identity=_identity_tuple(source),
        expected_source_size=source_identity.size,
        expected_source_sha256=_digest(b"source"),
        expected_source_parent_identity=_identity_tuple(tmp_path),
        expected_destination_parent_identity=_identity_tuple(tmp_path),
        max_bytes=64,
        _before_commit=race,
    )

    assert source.read_bytes() == b"source"
    assert destination.read_bytes() == b"source"


def test_transactional_copy_destination_creation_race_never_overwrites(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source.write_bytes(b"source")
    source_identity = windows_file_identity(source)

    def race() -> None:
        destination.write_bytes(b"intruder")

    with pytest.raises(OSError):
        transactional_copy_file(
            source,
            destination,
            expected_source_identity=_identity_tuple(source),
            expected_source_size=source_identity.size,
            expected_source_sha256=_digest(b"source"),
            expected_source_parent_identity=_identity_tuple(tmp_path),
            expected_destination_parent_identity=_identity_tuple(tmp_path),
            max_bytes=64,
            _before_commit=race,
        )

    assert source.read_bytes() == b"source"
    assert destination.read_bytes() == b"intruder"


def test_transactional_move_destination_creation_race_never_overwrites(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source.write_bytes(b"source")
    source_identity = windows_file_identity(source)

    def race() -> None:
        destination.write_bytes(b"intruder")

    with pytest.raises(OSError):
        transactional_move_file(
            source,
            destination,
            expected_source_identity=_identity_tuple(source),
            expected_source_size=source_identity.size,
            expected_source_sha256=_digest(b"source"),
            expected_source_parent_identity=_identity_tuple(tmp_path),
            expected_destination_parent_identity=_identity_tuple(tmp_path),
            _before_commit=race,
        )

    assert source.read_bytes() == b"source"
    assert destination.read_bytes() == b"intruder"


def test_transactional_move_source_replacement_cannot_select_a_new_identity(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    replacement = tmp_path / "replacement.bin"
    source.write_bytes(b"source")
    replacement.write_bytes(b"replacement")
    source_identity = windows_file_identity(source)
    replacement_succeeded = False

    def race() -> None:
        nonlocal replacement_succeeded
        try:
            os.replace(replacement, source)
            replacement_succeeded = True
        except OSError:
            replacement_succeeded = False

    try:
        transactional_move_file(
            source,
            destination,
            expected_source_identity=_identity_tuple(source),
            expected_source_size=source_identity.size,
            expected_source_sha256=_digest(b"source"),
            expected_source_parent_identity=_identity_tuple(tmp_path),
            expected_destination_parent_identity=_identity_tuple(tmp_path),
            _before_commit=race,
        )
    except OSError:
        assert replacement_succeeded
        assert source.read_bytes() == b"replacement"
        assert not destination.exists()
    else:
        assert not replacement_succeeded
        assert not source.exists()
        assert destination.read_bytes() == b"source"


def test_transactional_delete_blocks_replacement_until_commit(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    replacement = tmp_path / "replacement.bin"
    target.write_bytes(b"before")
    replacement.write_bytes(b"replacement")
    identity = windows_file_identity(target)

    def race() -> None:
        with pytest.raises(OSError):
            os.replace(replacement, target)

    transactional_delete(
        target,
        expected_identity=_identity_tuple(target),
        expected_size=identity.size,
        expected_sha256=_digest(b"before"),
        _before_commit=race,
    )

    assert not target.exists()
    assert replacement.read_bytes() == b"replacement"
