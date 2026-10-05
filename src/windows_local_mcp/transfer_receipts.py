"""Durable fixed-size receipts used to retry upload chunks idempotently.

The transfer server owns the control-plane root, lifecycle lock, manifest, and quota
checks.  This module only validates the sidecar's local file identity and stores or
looks up the bounded receipt records that the server has already authorized.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
from pathlib import Path

# Q offset, Q payload length, and the raw 32-byte SHA-256 digest.
RECEIPT_BYTES = 48
_RECEIPT = struct.Struct("<QQ32s")
_MAX_UINT64 = (1 << 64) - 1
_MAX_FILE_OFFSET = (1 << 63) - 1
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _invalid(message: str) -> ValueError:
    """Build a stable validation error without exposing filesystem details."""

    return ValueError(message)


def _validate_count(count: int, *, name: str = "receipt count") -> int:
    if type(count) is not int or count < 0:
        raise _invalid(f"{name} must be a non-negative integer")
    required = count * RECEIPT_BYTES
    # Python integers do not overflow, but the file APIs on supported platforms use
    # signed 64-bit offsets.  Reject an impossible seek before opening the sidecar.
    if required > _MAX_FILE_OFFSET:
        raise _invalid(f"{name} is outside the supported file range")
    return required


def _validate_offset(offset: int) -> None:
    if type(offset) is not int or offset < 0 or offset > _MAX_UINT64:
        raise _invalid("receipt offset must be a non-negative 64-bit integer")


def _is_reparse(info: os.stat_result) -> bool:
    return bool(int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT)


def _validate_root(root: Path) -> Path:
    try:
        root = Path(root)
        info = root.lstat()
    except (FileNotFoundError, NotADirectoryError):
        raise _invalid("receipt root is missing") from None
    except (OSError, TypeError, ValueError):
        raise _invalid("receipt root is unavailable") from None
    if root.is_symlink() or _is_reparse(info):
        raise _invalid("receipt root has an unsafe identity")
    if not stat.S_ISDIR(info.st_mode):
        raise _invalid("receipt root is not a directory")
    return root


def _validated_index(
    root: Path,
    count: int,
    max_records: int | None,
    *,
    for_append: bool = False,
) -> tuple[Path, int]:
    """Validate the sidecar identity and its crash-consistent bounded size."""

    required = _validate_count(count)
    capacity: int | None = None
    if max_records is not None:
        capacity = _validate_count(max_records, name="max_records")
        if max_records < count:
            raise _invalid("max_records must be greater than or equal to receipt count")
        if for_append and max_records <= count:
            raise _invalid("max_records must reserve one additional receipt")
    root = _validate_root(root)
    index = root / "chunks.bin"
    try:
        info = index.lstat()
    except (FileNotFoundError, NotADirectoryError):
        raise _invalid("receipt index is missing") from None
    except (OSError, TypeError, ValueError):
        raise _invalid("receipt index is unavailable") from None
    if index.is_symlink() or _is_reparse(info):
        raise _invalid("receipt index has an unsafe identity")
    if not stat.S_ISREG(info.st_mode):
        raise _invalid("receipt index is not a regular file")
    if int(getattr(info, "st_nlink", 0)) != 1:
        raise _invalid("receipt index has an unsafe identity")
    actual = int(info.st_size)
    if actual < required:
        raise _invalid("receipt index is truncated")
    if capacity is None:
        # A record may have been made durable before its manifest count was advanced.
        # A partial write can leave a short suffix; append_receipt replaces that suffix.
        if actual - required > RECEIPT_BYTES:
            raise _invalid("receipt index has an invalid size")
    else:
        # A reserved index is always a whole-record allocation.  Unused zero records
        # are intentionally ignored because only the confirmed manifest prefix is
        # searched or replaced.
        if actual % RECEIPT_BYTES != 0:
            raise _invalid("receipt index has an invalid size")
        if actual > capacity:
            raise _invalid("receipt index exceeds reserved capacity")
        if for_append and actual < required + RECEIPT_BYTES:
            raise _invalid("receipt index has insufficient reserved capacity")
    return index, required


def _read_record(handle: object, position: int) -> tuple[int, int, bytes]:
    # The caller supplies a binary file opened for reading.  Keeping this helper
    # small also ensures the binary-search path never loads the whole sidecar.
    try:
        handle.seek(position)
        raw = handle.read(RECEIPT_BYTES)
    except (OSError, ValueError):
        raise _invalid("receipt index could not be read") from None
    if not isinstance(raw, bytes) or len(raw) != RECEIPT_BYTES:
        raise _invalid("receipt index is truncated")
    try:
        offset, length, digest = _RECEIPT.unpack(raw)
    except struct.error:
        raise _invalid("receipt index contains an invalid record") from None
    if length == 0:
        raise _invalid("receipt index contains an invalid record")
    return offset, length, digest


def find_receipt(
    root: Path,
    count: int,
    offset: int,
    *,
    max_records: int | None = None,
) -> tuple[int, str] | None:
    """Find one offset in the confirmed receipt prefix using binary search.

    ``count`` comes from the durable manifest. Without reservation, at most one
    unconfirmed record or partial suffix is allowed. With ``max_records``, unused
    reserved slots are also allowed. Only the confirmed prefix is searched.
    """

    _validate_offset(offset)
    index, _required = _validated_index(root, count, max_records)
    low, high = 0, count
    try:
        with index.open("rb") as handle:
            while low < high:
                middle = (low + high) // 2
                record_offset, length, digest = _read_record(
                    handle, middle * RECEIPT_BYTES
                )
                if record_offset == offset:
                    return length, digest.hex()
                if record_offset < offset:
                    low = middle + 1
                else:
                    high = middle
    except FileNotFoundError:
        raise _invalid("receipt index is missing") from None
    except (NotADirectoryError, OSError):
        raise _invalid("receipt index could not be read") from None
    return None


def append_receipt(
    root: Path,
    count: int,
    offset: int,
    payload: bytes,
    *,
    max_records: int | None = None,
) -> None:
    """Persist one receipt at the manifest's next record position.

    Only the unconfirmed suffix is written.  This preserves all records already
    covered by ``count`` while replacing a receipt left behind by a prior crash.
    """

    _validate_offset(offset)
    if not isinstance(payload, bytes) or not payload:
        raise _invalid("receipt payload must be non-empty bytes")
    if len(payload) > _MAX_UINT64:
        raise _invalid("receipt payload is too large")
    index, position = _validated_index(root, count, max_records, for_append=True)
    record = _RECEIPT.pack(offset, len(payload), hashlib.sha256(payload).digest())
    try:
        with index.open("r+b") as handle:
            handle.seek(position)
            written = handle.write(record)
            if written != RECEIPT_BYTES:
                raise OSError("short receipt index write")
            # Without preallocation, trim a crash suffix after replacing it.  A
            # reserved index keeps all slots so the next append can use them.
            if max_records is None:
                handle.truncate(position + RECEIPT_BYTES)
            # The manifest is written by the caller after this returns.  Flush the
            # replacement record and its final size before exposing that count.
            handle.flush()
            os.fsync(handle.fileno())
    except FileNotFoundError:
        raise _invalid("receipt index is missing") from None
    except (NotADirectoryError, OSError) as error:
        # Keep the public path-validation errors fixed while preserving a useful
        # stable message for I/O failures that the caller may classify.
        if isinstance(error, OSError) and str(error) == "short receipt index write":
            raise _invalid("receipt index could not be written") from None
        raise _invalid("receipt index could not be written") from None
