from __future__ import annotations

import ctypes
import hashlib
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from windows_local_mcp import windows_transaction
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


def _assert_destination_creation_blocked(path: Path) -> None:
    # PythonのCRT経由では6800がerrno=EINVALへ変換されるため、Win32の
    # エラーを直接確認し、権限不足など別の失敗を競合拒否として扱わない。
    kernel32 = windows_transaction._kernel32()
    handle = kernel32.CreateFileW(
        str(path),
        windows_transaction._GENERIC_WRITE,
        windows_transaction._FILE_SHARE_READ
        | windows_transaction._FILE_SHARE_WRITE
        | windows_transaction._FILE_SHARE_DELETE,
        None,
        windows_transaction._CREATE_NEW,
        windows_transaction._FILE_ATTRIBUTE_NORMAL,
        None,
    )
    error = ctypes.get_last_error()
    if handle not in (None, windows_transaction._invalid_handle()):
        kernel32.CloseHandle(handle)
        pytest.fail("another writer created the transaction's reserved destination")
    # TxFの競合拒否、または通常の共有モードによる拒否だけを受け入れる。
    assert error in {32, 6800}, f"unexpected destination creation error: {error}"


def _destination_race_hook(
    monkeypatch: pytest.MonkeyPatch,
    race: Callable[[], None],
    *,
    after_handles_closed: bool,
) -> Callable[[], None] | None:
    if not after_handles_closed:
        return race
    finish_transaction = windows_transaction._finish_transaction

    def finish_with_race(transaction: Any, *, commit: bool) -> None:
        # ファイルHANDLEを閉じた後も、CommitTransactionまで予約が有効か確認する。
        if commit:
            race()
        finish_transaction(transaction, commit=commit)

    monkeypatch.setattr(windows_transaction, "_finish_transaction", finish_with_race)
    return None


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


@pytest.mark.parametrize("after_handles_closed", [False, True], ids=["staged", "handles-closed"])
def test_transactional_copy_destination_creation_race_never_overwrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_handles_closed: bool,
) -> None:
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source.write_bytes(b"source")
    source_identity = windows_file_identity(source)
    source_key = _identity_tuple(source)
    race_calls = 0

    def race() -> None:
        nonlocal race_calls
        race_calls += 1
        _assert_destination_creation_blocked(destination)

    committed = transactional_copy_file(
        source,
        destination,
        expected_source_identity=source_key,
        expected_source_size=source_identity.size,
        expected_source_sha256=_digest(b"source"),
        expected_source_parent_identity=_identity_tuple(tmp_path),
        expected_destination_parent_identity=_identity_tuple(tmp_path),
        max_bytes=64,
        _before_commit=_destination_race_hook(
            monkeypatch, race, after_handles_closed=after_handles_closed,
        ),
    )

    assert race_calls == 1
    assert source.read_bytes() == b"source"
    assert _identity_tuple(source) == source_key
    assert destination.read_bytes() == b"source"
    assert _identity_tuple(destination) == (committed.volume_serial, committed.file_index)
    assert _identity_tuple(destination) != source_key


@pytest.mark.parametrize("after_handles_closed", [False, True], ids=["staged", "handles-closed"])
def test_transactional_move_destination_creation_race_never_overwrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_handles_closed: bool,
) -> None:
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source.write_bytes(b"source")
    source_identity = windows_file_identity(source)
    source_key = _identity_tuple(source)
    race_calls = 0

    def race() -> None:
        nonlocal race_calls
        race_calls += 1
        _assert_destination_creation_blocked(destination)

    committed = transactional_move_file(
        source,
        destination,
        expected_source_identity=source_key,
        expected_source_size=source_identity.size,
        expected_source_sha256=_digest(b"source"),
        expected_source_parent_identity=_identity_tuple(tmp_path),
        expected_destination_parent_identity=_identity_tuple(tmp_path),
        _before_commit=_destination_race_hook(
            monkeypatch, race, after_handles_closed=after_handles_closed,
        ),
    )

    assert race_calls == 1
    assert not source.exists()
    assert destination.read_bytes() == b"source"
    assert _identity_tuple(destination) == source_key
    assert (committed.volume_serial, committed.file_index) == source_key


@pytest.mark.parametrize("operation", ["copy", "move"])
def test_transactional_destination_created_before_reservation_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source.write_bytes(b"source")
    source_key = _identity_tuple(source)
    competitor_key: tuple[int, int] | None = None

    def create_competitor() -> None:
        nonlocal competitor_key
        assert competitor_key is None
        destination.write_bytes(b"intruder")
        competitor_key = _identity_tuple(destination)

    # 存在確認の後、実際のWin32による名前の確保の直前に競合を成立させる。
    # API自体は置き換えず、既存ファイルを上書きせず拒否することを確認する。
    if operation == "copy":
        open_transacted = windows_transaction._open_transacted

        def open_with_race(path: Path, transaction: Any, **kwargs: Any) -> Any:
            if path == destination and not kwargs["exists"]:
                create_competitor()
            return open_transacted(path, transaction, **kwargs)

        monkeypatch.setattr(windows_transaction, "_open_transacted", open_with_race)
        action = transactional_copy_file
        expected_error = "CreateFileTransactedW failed"
    else:
        move_transacted = windows_transaction._move_transacted

        def move_with_race(
            kernel32: Any, source_path: Path, destination_path: Path, transaction: Any,
        ) -> None:
            assert destination_path == destination
            create_competitor()
            move_transacted(kernel32, source_path, destination_path, transaction)

        monkeypatch.setattr(windows_transaction, "_move_transacted", move_with_race)
        action = transactional_move_file
        expected_error = "MoveFileTransactedW failed"

    with pytest.raises(OSError, match=expected_error):
        action(
            source,
            destination,
            expected_source_identity=source_key,
            expected_source_size=len(b"source"),
            expected_source_sha256=_digest(b"source"),
            expected_source_parent_identity=_identity_tuple(tmp_path),
            expected_destination_parent_identity=_identity_tuple(tmp_path),
        )

    assert competitor_key is not None
    assert source.read_bytes() == b"source"
    assert _identity_tuple(source) == source_key
    assert destination.read_bytes() == b"intruder"
    assert _identity_tuple(destination) == competitor_key


@pytest.mark.parametrize("operation", ["copy", "move"])
def test_transactional_destination_reservation_released_after_callback_failure(
    tmp_path: Path, operation: str,
) -> None:
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source.write_bytes(b"source")
    source_key = _identity_tuple(source)
    action = transactional_copy_file if operation == "copy" else transactional_move_file
    injected_error = OSError("injected callback failure after destination reservation")
    race_calls = 0

    def fail_before_commit() -> None:
        nonlocal race_calls
        race_calls += 1
        _assert_destination_creation_blocked(destination)
        raise injected_error

    with pytest.raises(OSError) as caught:
        action(
            source,
            destination,
            expected_source_identity=source_key,
            expected_source_size=len(b"source"),
            expected_source_sha256=_digest(b"source"),
            _before_commit=fail_before_commit,
        )

    # 旧テストのようなコールバック例外は本体の失敗とは分けて記録する。
    assert caught.value is injected_error
    assert race_calls == 1
    assert source.read_bytes() == b"source"
    assert _identity_tuple(source) == source_key
    assert not destination.exists()
    # 失敗後に同じパスへ再実行でき、予約やHANDLEが残っていないことも確認する。
    action(
        source,
        destination,
        expected_source_identity=source_key,
        expected_source_size=len(b"source"),
        expected_source_sha256=_digest(b"source"),
    )
    assert destination.read_bytes() == b"source"
    if operation == "copy":
        assert source.read_bytes() == b"source"
        assert _identity_tuple(source) == source_key
    else:
        assert not source.exists()
        assert _identity_tuple(destination) == source_key


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
