from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import Self

import pytest

from windows_local_mcp.transfer_receipts import (
    RECEIPT_BYTES,
    append_receipt,
    find_receipt,
)

_RECEIPT = struct.Struct("<QQ32s")


def _make_root(tmp_path: Path) -> Path:
    root = tmp_path / "transfer"
    root.mkdir()
    (root / "chunks.bin").write_bytes(b"")
    return root


def _record(offset: int, payload: bytes) -> bytes:
    return _RECEIPT.pack(offset, len(payload), hashlib.sha256(payload).digest())


def test_append_and_find_receipts(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    payload = b"first payload"
    append_receipt(root, 0, 0, payload)
    assert find_receipt(root, 1, 0) == (
        len(payload),
        hashlib.sha256(payload).hexdigest(),
    )
    assert find_receipt(root, 1, 999) is None
    assert (root / "chunks.bin").stat().st_size == RECEIPT_BYTES


def test_append_preserves_old_receipt_and_replaces_crash_suffix(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    old = b"old"
    new = b"new payload"
    (root / "chunks.bin").write_bytes(_record(10, old) + b"crash suffix")
    append_receipt(root, 1, 20, new)

    data = (root / "chunks.bin").read_bytes()
    assert data[:RECEIPT_BYTES] == _record(10, old)
    assert data[RECEIPT_BYTES:] == _record(20, new)
    assert find_receipt(root, 1, 10) == (len(old), hashlib.sha256(old).hexdigest())
    assert find_receipt(root, 2, 20) == (len(new), hashlib.sha256(new).hexdigest())


@pytest.mark.parametrize(
    "setup,expected",
    [
        ("missing", "receipt index is missing"),
        ("truncated", "receipt index is truncated"),
        ("oversized", "receipt index has an invalid size"),
    ],
)
def test_missing_truncated_and_oversized_index_are_rejected(
    tmp_path: Path, setup: str, expected: str
) -> None:
    root = tmp_path / "transfer"
    root.mkdir()
    index = root / "chunks.bin"
    if setup == "truncated":
        index.write_bytes(b"x" * (RECEIPT_BYTES - 1))
    elif setup == "oversized":
        index.write_bytes(b"x" * (RECEIPT_BYTES * 3))
    with pytest.raises(ValueError, match=f"^{expected}$"):
        find_receipt(root, 1, 0)


@pytest.mark.parametrize("value", [-1, True, 1.0, "1"])
def test_invalid_count_is_rejected(tmp_path: Path, value: object) -> None:
    root = _make_root(tmp_path)
    with pytest.raises(ValueError, match="receipt count"):
        find_receipt(root, value, 0)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [-1, True, 1.0, "1"])
def test_invalid_offset_is_rejected(tmp_path: Path, value: object) -> None:
    root = _make_root(tmp_path)
    with pytest.raises(ValueError, match="receipt offset"):
        find_receipt(root, 0, value)  # type: ignore[arg-type]


def test_invalid_payload_is_rejected(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    with pytest.raises(ValueError, match="receipt payload"):
        append_receipt(root, 0, 0, b"")
    with pytest.raises(ValueError, match="receipt payload"):
        append_receipt(root, 0, 0, "payload")  # type: ignore[arg-type]


def test_extra_crash_suffix_is_ignored_by_search(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    payload = b"confirmed"
    (root / "chunks.bin").write_bytes(_record(7, payload) + b"x")
    assert find_receipt(root, 1, 7) == (
        len(payload),
        hashlib.sha256(payload).hexdigest(),
    )
    assert find_receipt(root, 1, 8) is None


def test_preallocated_index_finds_confirmed_prefix_and_does_not_truncate(
    tmp_path: Path,
) -> None:
    root = _make_root(tmp_path)
    capacity = 4
    index = root / "chunks.bin"
    index.write_bytes(b"\0" * (capacity * RECEIPT_BYTES))
    append_receipt(root, 0, 7, b"preallocated", max_records=capacity)

    assert index.stat().st_size == capacity * RECEIPT_BYTES
    assert find_receipt(root, 1, 7, max_records=capacity) == (
        len(b"preallocated"),
        hashlib.sha256(b"preallocated").hexdigest(),
    )
    # Unused zero slots are outside the confirmed prefix and are never searched.
    assert find_receipt(root, 1, 0, max_records=capacity) is None


def test_preallocated_append_preserves_confirmed_receipts_and_unused_slots(
    tmp_path: Path,
) -> None:
    root = _make_root(tmp_path)
    old = b"confirmed"
    new = b"next"
    capacity = 3
    index = root / "chunks.bin"
    index.write_bytes(_record(10, old) + b"\0" * ((capacity - 1) * RECEIPT_BYTES))
    before = index.read_bytes()

    append_receipt(root, 1, 20, new, max_records=capacity)

    after = index.read_bytes()
    assert len(after) == len(before)
    assert after[:RECEIPT_BYTES] == before[:RECEIPT_BYTES]
    assert after[2 * RECEIPT_BYTES :] == before[2 * RECEIPT_BYTES :]
    assert find_receipt(root, 1, 10, max_records=capacity) == (
        len(old),
        hashlib.sha256(old).hexdigest(),
    )
    assert find_receipt(root, 2, 20, max_records=capacity) == (
        len(new),
        hashlib.sha256(new).hexdigest(),
    )


@pytest.mark.parametrize(
    "count,max_records,actual_bytes,operation,expected",
    [
        (2, 1, 2 * RECEIPT_BYTES, "find", "max_records must be greater"),
        (1, 1, 1 * RECEIPT_BYTES, "append", "max_records must reserve"),
        (1, 3, RECEIPT_BYTES + 1, "find", "receipt index has an invalid size"),
        (1, 3, 0, "find", "receipt index is truncated"),
        (1, 2, 3 * RECEIPT_BYTES, "find", "receipt index exceeds reserved capacity"),
        (1, 3, 1 * RECEIPT_BYTES, "append", "receipt index has insufficient reserved capacity"),
    ],
)
def test_preallocated_capacity_is_validated(
    tmp_path: Path,
    count: int,
    max_records: int,
    actual_bytes: int,
    operation: str,
    expected: str,
) -> None:
    root = _make_root(tmp_path)
    (root / "chunks.bin").write_bytes(b"\0" * actual_bytes)
    with pytest.raises(ValueError, match=expected):
        if operation == "find":
            find_receipt(root, count, 0, max_records=max_records)
        else:
            append_receipt(root, count, 0, b"payload", max_records=max_records)


@pytest.mark.parametrize("value", [-1, True, 1.0, "2"])
def test_invalid_max_records_is_rejected(tmp_path: Path, value: object) -> None:
    root = _make_root(tmp_path)
    with pytest.raises(ValueError, match="max_records"):
        find_receipt(root, 0, 0, max_records=value)  # type: ignore[arg-type]


def test_large_index_search_does_not_read_the_whole_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _make_root(tmp_path)
    count = 1 << 15
    target = count - 1
    with (root / "chunks.bin").open("wb") as output:
        for offset in range(count):
            output.write(_record(offset, bytes([offset & 0xFF]) or b"x"))

    original_read = Path.open
    reads = 0

    class CountingFile:
        def __init__(self, file: object) -> None:
            self._file = file

        def __enter__(self) -> Self:
            self._file.__enter__()
            return self

        def __exit__(self, *args: object) -> object:
            return self._file.__exit__(*args)

        def seek(self, position: int) -> object:
            return self._file.seek(position)

        def read(self, size: int) -> bytes:
            nonlocal reads
            reads += 1
            return self._file.read(size)

    def counting_open(self: Path, *args: object, **kwargs: object) -> CountingFile:
        return CountingFile(original_read(self, *args, **kwargs))

    monkeypatch.setattr(Path, "open", counting_open)
    assert find_receipt(root, count, target) == (
        1,
        hashlib.sha256(b"\xff").hexdigest(),
    )
    assert reads <= count.bit_length()


def test_symlink_and_hardlink_index_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "transfer"
    root.mkdir()
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    try:
        os.symlink(source, root / "chunks.bin")
    except (NotImplementedError, OSError):
        pytest.skip("symbolic links are unavailable")
    with pytest.raises(ValueError, match="receipt index has an unsafe identity"):
        find_receipt(root, 0, 0)

    (root / "chunks.bin").unlink()
    try:
        os.link(source, root / "chunks.bin")
    except OSError:
        pytest.skip("hard links are unavailable")
    with pytest.raises(ValueError, match="receipt index has an unsafe identity"):
        find_receipt(root, 0, 0)
