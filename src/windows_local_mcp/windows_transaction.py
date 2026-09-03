from __future__ import annotations

import ctypes
import hashlib
import os
import stat
from collections.abc import Callable
from ctypes import get_last_error, wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE = 0x00010000
_FILE_LIST_DIRECTORY = 0x00000001
_FILE_READ_ATTRIBUTES = 0x00000080
_SYNCHRONIZE = 0x00100000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_BEGIN = 0
_FILE_DISPOSITION_INFO_CLASS = 4
_TRANSACTION_DO_NOT_PROMOTE = 0x00000001
_MOVEFILE_WRITE_THROUGH = 0x00000008
_READ_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class WindowsFileIdentity:
    volume_serial: int
    file_index: int
    size: int
    link_count: int
    attributes: int


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOL)]


def _kernel32() -> Any:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileTransactedW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.USHORT),
        wintypes.LPVOID,
    ]
    kernel32.CreateFileTransactedW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.SetFilePointerEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    ]
    kernel32.SetFilePointerEx.restype = wintypes.BOOL
    kernel32.SetEndOfFile.argtypes = [wintypes.HANDLE]
    kernel32.SetEndOfFile.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL
    kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.MoveFileTransactedW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.MoveFileTransactedW.restype = wintypes.BOOL
    kernel32.CreateDirectoryTransactedW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.HANDLE,
    ]
    kernel32.CreateDirectoryTransactedW.restype = wintypes.BOOL
    kernel32.RemoveDirectoryTransactedW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE]
    kernel32.RemoveDirectoryTransactedW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _ktm() -> Any:
    ktm = ctypes.WinDLL("KtmW32", use_last_error=True)
    ktm.CreateTransaction.argtypes = [
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPWSTR,
    ]
    ktm.CreateTransaction.restype = wintypes.HANDLE
    ktm.CommitTransaction.argtypes = [wintypes.HANDLE]
    ktm.CommitTransaction.restype = wintypes.BOOL
    ktm.RollbackTransaction.argtypes = [wintypes.HANDLE]
    ktm.RollbackTransaction.restype = wintypes.BOOL
    return ktm


def _invalid_handle() -> int:
    return int(wintypes.HANDLE(-1).value)


def _raise_last_error(action: str, path: Path | None = None) -> None:
    error = get_last_error()
    suffix = f": {path}" if path is not None else ""
    raise OSError(error, f"{action} failed{suffix}")


def _identity_from_handle(handle: Any) -> WindowsFileIdentity:
    information = _ByHandleFileInformation()
    kernel32 = _kernel32()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        _raise_last_error("GetFileInformationByHandle")
    return WindowsFileIdentity(
        volume_serial=int(information.dwVolumeSerialNumber),
        file_index=(int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow),
        size=(int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow),
        link_count=int(information.nNumberOfLinks),
        attributes=int(information.dwFileAttributes),
    )


def windows_file_identity(path: Path) -> WindowsFileIdentity:
    if os.name != "nt":
        raise OSError("Windows file identity is available only on Windows")
    kernel32 = _kernel32()
    # FILE_FLAG_BACKUP_SEMANTICS is required to open directories.  Keeping
    # FILE_FLAG_OPEN_REPARSE_POINT means identity is collected for the named
    # object itself and never by following a junction or symbolic link.
    flags = _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS
    handle = kernel32.CreateFileW(
        str(path),
        0x00000080,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    if handle in (None, _invalid_handle()):
        _raise_last_error("CreateFileW", path)
    try:
        return _identity_from_handle(handle)
    finally:
        kernel32.CloseHandle(handle)


def _validate_regular_identity(
    handle: Any,
    *,
    expected_identity: tuple[int, int] | None,
    expected_size: int | None,
    path: Path,
) -> WindowsFileIdentity:
    identity = _identity_from_handle(handle)
    if identity.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise PermissionError(f"transaction target became a reparse point: {path}")
    if identity.attributes & _FILE_ATTRIBUTE_DIRECTORY:
        raise IsADirectoryError(f"transaction target is not a regular file: {path}")
    if identity.link_count != 1:
        raise PermissionError(f"transaction target has multiple hard links: {path}")
    if expected_identity is not None and (
        identity.volume_serial,
        identity.file_index,
    ) != expected_identity:
        raise RuntimeError(
            "write target changed before transactional commit; target is stale or concurrently modified"
        )
    if expected_size is not None and identity.size != expected_size:
        raise RuntimeError(
            "write target size changed before transactional commit; target is stale or concurrently modified"
        )
    return identity


def _seek_start(handle: Any) -> None:
    if not _kernel32().SetFilePointerEx(handle, 0, None, _FILE_BEGIN):
        _raise_last_error("SetFilePointerEx")


def _hash_handle(handle: Any, *, max_bytes: int) -> tuple[str, int]:
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    kernel32 = _kernel32()
    _seek_start(handle)
    digest = hashlib.sha256()
    total = 0
    buffer = ctypes.create_string_buffer(_READ_CHUNK_BYTES)
    while True:
        read = wintypes.DWORD()
        if not kernel32.ReadFile(handle, buffer, len(buffer), ctypes.byref(read), None):
            _raise_last_error("ReadFile")
        if not read.value:
            return digest.hexdigest(), total
        total += int(read.value)
        if total > max_bytes:
            raise RuntimeError("transaction target exceeded its expected size while hashing")
        digest.update(buffer.raw[: read.value])


def _write_handle(handle: Any, data: bytes) -> None:
    kernel32 = _kernel32()
    _seek_start(handle)
    if not kernel32.SetEndOfFile(handle):
        _raise_last_error("SetEndOfFile")
    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + _READ_CHUNK_BYTES]
        buffer = ctypes.create_string_buffer(chunk)
        written = wintypes.DWORD()
        if not kernel32.WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None):
            _raise_last_error("WriteFile")
        if written.value != len(chunk):
            raise OSError("short WriteFile during transactional commit")
        offset += int(written.value)
    if not kernel32.FlushFileBuffers(handle):
        _raise_last_error("FlushFileBuffers")


def _create_transaction(description: str) -> Any:
    transaction = _ktm().CreateTransaction(
        None,
        None,
        _TRANSACTION_DO_NOT_PROMOTE,
        0,
        0,
        0,
        description,
    )
    if transaction in (None, _invalid_handle()):
        _raise_last_error("CreateTransaction")
    return transaction


def _open_transacted(
    path: Path,
    transaction: Any,
    *,
    exists: bool,
    delete: bool,
    directory: bool = False,
    share_write: bool = True,
    share_delete: bool = True,
    desired_access: int | None = None,
) -> Any:
    kernel32 = _kernel32()
    access = (
        _GENERIC_READ | _GENERIC_WRITE | (_DELETE if delete else 0)
        if desired_access is None
        else desired_access
    )
    share_mode = _FILE_SHARE_READ
    if share_write:
        share_mode |= _FILE_SHARE_WRITE
    if share_delete:
        share_mode |= _FILE_SHARE_DELETE
    flags = _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    handle = kernel32.CreateFileTransactedW(
        str(path),
        access,
        share_mode,
        None,
        _OPEN_EXISTING if exists else _CREATE_NEW,
        flags,
        None,
        transaction,
        None,
        None,
    )
    if handle in (None, _invalid_handle()):
        _raise_last_error("CreateFileTransactedW", path)
    return handle


def _open_transacted_directory(
    path: Path, transaction: Any, *, share_delete: bool = False
) -> Any:
    """Open an existing directory without following reparse points.

    The handle normally omits FILE_SHARE_DELETE.  Retaining it until the
    transaction is committed pins the validated namespace parent against a
    concurrent rename or removal.  New children may still be created; the
    transactional create/rename operation detects a resulting name collision.
    A directory being removed is opened with ``share_delete=True`` and closed
    before RemoveDirectoryTransactedW, avoiding a self-imposed sharing conflict.
    """

    return _open_transacted(
        path,
        transaction,
        exists=True,
        delete=False,
        directory=True,
        share_write=True,
        share_delete=share_delete,
        desired_access=_FILE_READ_ATTRIBUTES | _FILE_LIST_DIRECTORY | _SYNCHRONIZE,
    )


def _finish_transaction(transaction: Any, *, commit: bool) -> None:
    ktm = _ktm()
    if commit:
        if not ktm.CommitTransaction(transaction):
            _raise_last_error("CommitTransaction")
    else:
        ktm.RollbackTransaction(transaction)


def _absolute_path(path: Path) -> Path:
    """Return a lexical absolute path without resolving reparse targets."""

    return Path(os.path.abspath(os.path.normpath(os.fspath(path))))


def _identity_key(identity: WindowsFileIdentity) -> tuple[int, int]:
    return identity.volume_serial, identity.file_index


def _path_exists(path: Path) -> bool:
    """Check namespace presence without following a symlink/reparse target."""

    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def _validate_source_snapshot(
    handle: Any,
    *,
    path: Path,
    expected_identity: tuple[int, int],
    expected_size: int,
    expected_sha256: str,
) -> WindowsFileIdentity:
    """Bind a regular source to one handle, including content and post-hash identity."""

    if expected_size < 0:
        raise ValueError("expected_size must be non-negative")
    before = _validate_regular_identity(
        handle,
        expected_identity=expected_identity,
        expected_size=expected_size,
        path=path,
    )
    digest, size = _hash_handle(handle, max_bytes=expected_size)
    if size != expected_size or digest != expected_sha256:
        raise RuntimeError(
            "transaction source content changed before commit; target is stale or concurrently modified"
        )
    # The source handle is opened without write/delete sharing by move/copy.  The
    # second identity read nevertheless makes the binding explicit and catches
    # unexpected filesystem behavior before a mutation is staged.
    after = _validate_regular_identity(
        handle,
        expected_identity=expected_identity,
        expected_size=expected_size,
        path=path,
    )
    if _identity_key(before) != _identity_key(after) or before.size != after.size:
        raise RuntimeError("transaction source identity changed before commit")
    return after


def _read_handle(handle: Any, *, max_bytes: int) -> bytes:
    """Read a bounded byte sequence from a validated Windows HANDLE."""

    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    kernel32 = _kernel32()
    _seek_start(handle)
    output = bytearray()
    buffer = ctypes.create_string_buffer(_READ_CHUNK_BYTES)
    while True:
        read = wintypes.DWORD()
        if not kernel32.ReadFile(handle, buffer, len(buffer), ctypes.byref(read), None):
            _raise_last_error("ReadFile")
        if not read.value:
            return bytes(output)
        output.extend(buffer.raw[: read.value])
        if len(output) > max_bytes:
            raise RuntimeError("transaction source exceeded its expected size while copying")


def _move_transacted(kernel32: Any, source: Path, destination: Path, transaction: Any) -> None:
    if not kernel32.MoveFileTransactedW(
        str(source),
        str(destination),
        None,
        None,
        _MOVEFILE_WRITE_THROUGH,
        transaction,
    ):
        _raise_last_error("MoveFileTransactedW", destination)


def _temporary_sibling(path: Path) -> Path:
    """Choose a deterministic-per-process, non-user-facing staging name."""

    # The source parent directory handle and the transaction make the final
    # collision check authoritative.  This name only exists for case-only
    # renames, and is never exposed after commit.
    for index in range(100):
        candidate = path.parent / f".wlmcp-case-rename-{os.getpid()}-{id(path)}-{index}.tmp"
        if not _path_exists(candidate):
            return candidate
    raise RuntimeError("could not reserve a case-only rename staging name")


def transactional_move_file(
    source: Path,
    destination: Path,
    *,
    expected_source_identity: tuple[int, int],
    expected_source_size: int,
    expected_source_sha256: str,
    expected_source_parent_identity: tuple[int, int] | None = None,
    expected_destination_parent_identity: tuple[int, int] | None = None,
    _before_commit: Callable[[], None] | None = None,
) -> WindowsFileIdentity:
    """Atomically move one validated regular file inside one TxF transaction.

    The source is opened with a single transacted HANDLE that disallows external
    write/delete sharing.  Its native identity, size, and SHA-256 are checked
    before and after hashing.  Destination replacement is never enabled: a
    destination that exists is rejected, except for a Windows case-only rename
    of the same source name.  Source and destination parents are pinned against
    namespace replacement and must be on the same volume.

    The non-Windows branch exists only for test portability.  It repeats the
    identity/content checks and refuses an already-present destination, but it
    cannot provide the Windows TxF isolation guarantee.
    """

    source = _absolute_path(source)
    destination = _absolute_path(destination)
    source_text = os.path.normpath(os.fspath(source))
    destination_text = os.path.normpath(os.fspath(destination))
    if source_text == destination_text:
        raise ValueError("source and destination must not be the same path")
    same_casefold = source_text.casefold() == destination_text.casefold()
    case_only = os.name == "nt" and same_casefold

    if os.name != "nt":
        return _transactional_move_non_windows(
            source,
            destination,
            expected_source_identity=expected_source_identity,
            expected_source_size=expected_source_size,
            expected_source_sha256=expected_source_sha256,
            expected_source_parent_identity=expected_source_parent_identity,
            expected_destination_parent_identity=expected_destination_parent_identity,
            _before_commit=_before_commit,
        )

    # The destination is allowed to exist only when it is the same NTFS name
    # with different casing.  All other collisions, including reparse points
    # and hard-link aliases, fail before any transactional mutation is staged.
    destination_exists = _path_exists(destination)
    if destination_exists and not case_only:
        raise FileExistsError(f"move destination already exists: {destination}")
    if case_only:
        try:
            destination_identity = windows_file_identity(destination)
        except OSError as error:
            raise RuntimeError("case-only move destination could not be inspected") from error
        if _identity_key(destination_identity) != expected_source_identity:
            raise FileExistsError("case-only move destination is not the validated source")

    kernel32 = _kernel32()
    transaction = _create_transaction("Windows Local MCP workspace move")
    source_parent_handle: Any | None = None
    destination_parent_handle: Any | None = None
    source_handle: Any | None = None
    committed = False
    committed_identity: WindowsFileIdentity | None = None
    try:
        source_parent_handle = _open_transacted_directory(source.parent, transaction)
        source_parent_identity = _identity_from_handle(source_parent_handle)
        if source_parent_identity.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError(f"move source parent is a reparse point: {source.parent}")
        if not source_parent_identity.attributes & _FILE_ATTRIBUTE_DIRECTORY:
            raise NotADirectoryError(f"move source parent is not a directory: {source.parent}")
        if expected_source_parent_identity is not None and _identity_key(
            source_parent_identity
        ) != expected_source_parent_identity:
            raise RuntimeError("move source parent changed before commit")

        destination_parent_handle = _open_transacted_directory(destination.parent, transaction)
        destination_parent_identity = _identity_from_handle(destination_parent_handle)
        if destination_parent_identity.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError(
                f"move destination parent is a reparse point: {destination.parent}"
            )
        if not destination_parent_identity.attributes & _FILE_ATTRIBUTE_DIRECTORY:
            raise NotADirectoryError(
                f"move destination parent is not a directory: {destination.parent}"
            )
        if expected_destination_parent_identity is not None and _identity_key(
            destination_parent_identity
        ) != expected_destination_parent_identity:
            raise RuntimeError("move destination parent changed before commit")
        if source_parent_identity.volume_serial != destination_parent_identity.volume_serial:
            raise OSError("cross-volume file move is not supported by the Broker primitive")

        # MoveFileTransactedW needs delete sharing on an already-open source. The
        # transacted HANDLE still binds identity/content, and a concurrent namespace
        # change conflicts with the transaction instead of selecting another object.
        source_handle = _open_transacted(
            source,
            transaction,
            exists=True,
            delete=True,
            share_write=False,
            share_delete=True,
            desired_access=_GENERIC_READ | _DELETE,
        )
        committed_identity = _validate_source_snapshot(
            source_handle,
            path=source,
            expected_identity=expected_source_identity,
            expected_size=expected_source_size,
            expected_sha256=expected_source_sha256,
        )

        # Recheck a destination that was absent at the initial lexical check in
        # the transaction view.  MoveFileTransactedW is called without a replace
        # flag, so a concurrent create causes transaction commit failure rather
        # than an overwrite.
        if not case_only and _path_exists(destination):
            raise FileExistsError(f"move destination already exists: {destination}")

        if case_only:
            # Some Windows versions treat a case-only source/destination pair as
            # the same name and reject a direct move.  A temporary sibling keeps
            # both steps in the same transaction and therefore remains atomic.
            staging = _temporary_sibling(source)
            _move_transacted(kernel32, source, staging, transaction)
            _move_transacted(kernel32, staging, destination, transaction)
        else:
            _move_transacted(kernel32, source, destination, transaction)

        if _before_commit is not None:
            _before_commit()
        # TxF commit may be unable to reconcile a destination created outside
        # this transaction.  Close the moved-file handle before committing, but
        # retain both parent handles until CommitTransaction returns so an
        # ancestor cannot be replaced during the commit boundary.
        kernel32.CloseHandle(source_handle)
        source_handle = None
        _finish_transaction(transaction, commit=True)
        committed = True

        # Return the identity observed from the validated source HANDLE.  A
        # best-effort postcondition check catches unexpected TxF behavior while
        # preserving the stable identity even if a later caller races the path.
        try:
            live = windows_file_identity(destination)
        except OSError as error:
            raise RuntimeError("move committed but destination postcondition could not be verified") from error
        if _identity_key(live) != _identity_key(committed_identity):
            raise RuntimeError("move committed with an unexpected destination identity")
        if live.attributes & (_FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY):
            raise RuntimeError("move committed to a non-regular destination")
        if live.link_count != 1:
            raise RuntimeError("move committed to a multiply linked destination")
        return live
    finally:
        for handle in (source_handle, destination_parent_handle, source_parent_handle):
            if handle is not None:
                kernel32.CloseHandle(handle)
        if not committed:
            _finish_transaction(transaction, commit=False)
        kernel32.CloseHandle(transaction)


def _transactional_move_non_windows(
    source: Path,
    destination: Path,
    *,
    expected_source_identity: tuple[int, int],
    expected_source_size: int,
    expected_source_sha256: str,
    expected_source_parent_identity: tuple[int, int] | None,
    expected_destination_parent_identity: tuple[int, int] | None,
    _before_commit: Callable[[], None] | None,
) -> WindowsFileIdentity:
    """Portable test fallback for move; Windows production uses TxF above."""

    source_stat = os.stat(source, follow_symlinks=False)
    if not os.path.isfile(source) or os.path.islink(source) or source_stat.st_nlink != 1:
        raise PermissionError("transaction source must be one regular, non-linked file")
    actual_key = (int(source_stat.st_dev), int(source_stat.st_ino))
    if actual_key != expected_source_identity:
        raise RuntimeError("transaction source identity changed before commit")
    if source_stat.st_size != expected_source_size:
        raise RuntimeError("transaction source size changed before commit")
    with source.open("rb") as input_file:
        data = input_file.read(expected_source_size + 1)
    if len(data) != expected_source_size or hashlib.sha256(data).hexdigest() != expected_source_sha256:
        raise RuntimeError("transaction source content changed before commit")
    if expected_source_parent_identity is not None:
        parent_stat = os.stat(source.parent, follow_symlinks=False)
        if (int(parent_stat.st_dev), int(parent_stat.st_ino)) != expected_source_parent_identity:
            raise RuntimeError("move source parent changed before commit")
    destination_parent_stat = os.stat(destination.parent, follow_symlinks=False)
    if not stat.S_ISDIR(destination_parent_stat.st_mode):
        raise NotADirectoryError(f"move destination parent is not a directory: {destination.parent}")
    if expected_destination_parent_identity is not None and (
        int(destination_parent_stat.st_dev), int(destination_parent_stat.st_ino)
    ) != expected_destination_parent_identity:
        raise RuntimeError("move destination parent changed before commit")
    if int(source_stat.st_dev) != int(destination_parent_stat.st_dev):
        raise OSError("cross-volume file move is not supported by the Broker primitive")
    if _path_exists(destination):
        raise FileExistsError(f"move destination already exists: {destination}")
    if _before_commit is not None:
        _before_commit()
    if _path_exists(destination):
        raise FileExistsError(f"move destination was created during validation: {destination}")
    os.rename(source, destination)
    live = os.stat(destination, follow_symlinks=False)
    if (int(live.st_dev), int(live.st_ino)) != actual_key or live.st_size != expected_source_size:
        raise RuntimeError("move committed with an unexpected destination identity")
    return WindowsFileIdentity(
        volume_serial=int(live.st_dev),
        file_index=int(live.st_ino),
        size=int(live.st_size),
        link_count=int(live.st_nlink),
        attributes=0,
    )


def transactional_copy_file(
    source: Path,
    destination: Path,
    *,
    expected_source_identity: tuple[int, int],
    expected_source_size: int,
    expected_source_sha256: str,
    expected_source_parent_identity: tuple[int, int] | None = None,
    expected_destination_parent_identity: tuple[int, int] | None = None,
    max_bytes: int | None = None,
    _before_commit: Callable[[], None] | None = None,
) -> WindowsFileIdentity:
    """Copy one regular file to a new destination inside one TxF transaction.

    Metadata is intentionally not copied: the primitive guarantees byte-exact
    content only.  ACLs, alternate data streams, and timestamps remain those of
    the newly created destination according to the host filesystem defaults.
    """

    source = _absolute_path(source)
    destination = _absolute_path(destination)
    if os.path.normpath(os.fspath(source)) == os.path.normpath(os.fspath(destination)):
        raise ValueError("source and destination must not be the same path")
    if max_bytes is None:
        max_bytes = expected_source_size
    if max_bytes < expected_source_size:
        raise ValueError("copy source exceeds max_bytes")
    if os.name != "nt":
        return _transactional_copy_non_windows(
            source,
            destination,
            expected_source_identity=expected_source_identity,
            expected_source_size=expected_source_size,
            expected_source_sha256=expected_source_sha256,
            expected_source_parent_identity=expected_source_parent_identity,
            expected_destination_parent_identity=expected_destination_parent_identity,
            _before_commit=_before_commit,
        )
    if _path_exists(destination):
        raise FileExistsError(f"copy destination already exists: {destination}")

    kernel32 = _kernel32()
    transaction = _create_transaction("Windows Local MCP workspace copy")
    source_parent_handle: Any | None = None
    destination_parent_handle: Any | None = None
    source_handle: Any | None = None
    destination_handle: Any | None = None
    committed = False
    committed_identity: WindowsFileIdentity | None = None
    try:
        source_parent_handle = _open_transacted_directory(source.parent, transaction)
        source_parent_identity = _identity_from_handle(source_parent_handle)
        if source_parent_identity.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError(f"copy source parent is a reparse point: {source.parent}")
        if expected_source_parent_identity is not None and _identity_key(
            source_parent_identity
        ) != expected_source_parent_identity:
            raise RuntimeError("copy source parent changed before commit")
        destination_parent_handle = _open_transacted_directory(destination.parent, transaction)
        destination_parent_identity = _identity_from_handle(destination_parent_handle)
        if destination_parent_identity.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError(
                f"copy destination parent is a reparse point: {destination.parent}"
            )
        if expected_destination_parent_identity is not None and _identity_key(
            destination_parent_identity
        ) != expected_destination_parent_identity:
            raise RuntimeError("copy destination parent changed before commit")
        if source_parent_identity.volume_serial != destination_parent_identity.volume_serial:
            raise OSError("cross-volume file copy is not supported by the Broker primitive")

        source_handle = _open_transacted(
            source,
            transaction,
            exists=True,
            delete=False,
            share_write=False,
            share_delete=False,
            desired_access=_GENERIC_READ,
        )
        source_identity = _validate_source_snapshot(
            source_handle,
            path=source,
            expected_identity=expected_source_identity,
            expected_size=expected_source_size,
            expected_sha256=expected_source_sha256,
        )
        data = _read_handle(source_handle, max_bytes=max_bytes)
        if len(data) != expected_source_size:
            raise RuntimeError("copy source size changed during read")
        destination_handle = _open_transacted(
            destination,
            transaction,
            exists=False,
            delete=False,
            share_write=False,
            share_delete=False,
        )
        _write_handle(destination_handle, data)
        destination_digest, destination_size = _hash_handle(
            destination_handle, max_bytes=max_bytes
        )
        if destination_size != expected_source_size or destination_digest != expected_source_sha256:
            raise RuntimeError("copy destination content verification failed")
        committed_identity = _identity_from_handle(destination_handle)
        if committed_identity.attributes & (
            _FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY
        ) or committed_identity.link_count != 1:
            raise RuntimeError("copy destination is not a regular, singly linked file")
        if _before_commit is not None:
            _before_commit()
        # A destination created concurrently outside this transaction remains a
        # collision at TxF commit; no replacement flag is ever used.
        kernel32.CloseHandle(destination_handle)
        destination_handle = None
        kernel32.CloseHandle(source_handle)
        source_handle = None
        _finish_transaction(transaction, commit=True)
        committed = True
        live = windows_file_identity(destination)
        if _identity_key(live) != _identity_key(committed_identity):
            raise RuntimeError("copy committed with an unexpected destination identity")
        if live.size != source_identity.size:
            raise RuntimeError("copy committed with an unexpected destination size")
        return live
    finally:
        for handle in (
            destination_handle,
            source_handle,
            destination_parent_handle,
            source_parent_handle,
        ):
            if handle is not None:
                kernel32.CloseHandle(handle)
        if not committed:
            _finish_transaction(transaction, commit=False)
        kernel32.CloseHandle(transaction)


def _transactional_copy_non_windows(
    source: Path,
    destination: Path,
    *,
    expected_source_identity: tuple[int, int],
    expected_source_size: int,
    expected_source_sha256: str,
    expected_source_parent_identity: tuple[int, int] | None,
    expected_destination_parent_identity: tuple[int, int] | None,
    _before_commit: Callable[[], None] | None,
) -> WindowsFileIdentity:
    """Portable copy fallback used by unit tests only."""

    source_stat = os.stat(source, follow_symlinks=False)
    if not os.path.isfile(source) or os.path.islink(source) or source_stat.st_nlink != 1:
        raise PermissionError("transaction source must be one regular, non-linked file")
    source_key = (int(source_stat.st_dev), int(source_stat.st_ino))
    if source_key != expected_source_identity or source_stat.st_size != expected_source_size:
        raise RuntimeError("transaction source identity or size changed before commit")
    data = source.read_bytes()
    if len(data) != expected_source_size or hashlib.sha256(data).hexdigest() != expected_source_sha256:
        raise RuntimeError("transaction source content changed before commit")
    source_parent = os.stat(source.parent, follow_symlinks=False)
    destination_parent = os.stat(destination.parent, follow_symlinks=False)
    if expected_source_parent_identity is not None and (
        int(source_parent.st_dev), int(source_parent.st_ino)
    ) != expected_source_parent_identity:
        raise RuntimeError("copy source parent changed before commit")
    if expected_destination_parent_identity is not None and (
        int(destination_parent.st_dev), int(destination_parent.st_ino)
    ) != expected_destination_parent_identity:
        raise RuntimeError("copy destination parent changed before commit")
    if int(source_parent.st_dev) != int(destination_parent.st_dev):
        raise OSError("cross-volume file copy is not supported by the Broker primitive")
    if _path_exists(destination):
        raise FileExistsError(f"copy destination already exists: {destination}")
    if _before_commit is not None:
        _before_commit()
    if _path_exists(destination):
        raise FileExistsError(f"copy destination was created during validation: {destination}")
    temporary: Path | None = None
    try:
        with open(destination.parent / f".wlmcp-copy-{os.getpid()}-{id(destination)}", "xb") as out:
            temporary = Path(out.name)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.rename(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    live = os.stat(destination, follow_symlinks=False)
    if live.st_size != expected_source_size:
        raise RuntimeError("copy committed with an unexpected destination size")
    if hashlib.sha256(destination.read_bytes()).hexdigest() != expected_source_sha256:
        raise RuntimeError("copy committed with unexpected destination content")
    return WindowsFileIdentity(
        volume_serial=int(live.st_dev),
        file_index=int(live.st_ino),
        size=int(live.st_size),
        link_count=int(live.st_nlink),
        attributes=0,
    )


# Short aliases keep the public vocabulary aligned with the Broker tool names.
transactional_move = transactional_move_file
transactional_copy = transactional_copy_file


def _directory_parts(path: Path) -> tuple[Path, ...]:
    """Return lexical components below a filesystem anchor."""

    anchor = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    current = anchor
    output: list[Path] = []
    for part in parts:
        current /= part
        output.append(current)
    if not output:
        raise ValueError("directory path must identify a child of a filesystem root")
    return tuple(output)


def _directory_is_reparse(path: Path, details: os.stat_result | None = None) -> bool:
    if details is None:
        details = os.lstat(path)
    attributes = int(getattr(details, "st_file_attributes", 0))
    return path.is_symlink() or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _validate_existing_directory(path: Path) -> os.stat_result:
    details = os.lstat(path)
    if _directory_is_reparse(path, details):
        raise PermissionError(f"symlink, junction, or reparse point is denied: {path}")
    if not stat.S_ISDIR(details.st_mode):
        raise NotADirectoryError(f"path component is not a directory: {path}")
    return details


def _rollback_created_directories(created: list[Path]) -> None:
    """Best-effort reverse cleanup for the non-Windows test fallback only."""

    for path in reversed(created):
        try:
            path.rmdir()
        except OSError:
            # Never recurse or remove a directory that became non-empty.  The
            # caller receives the original failure and the remaining state is
            # intentionally visible for recovery/audit.
            continue


def transactional_create_directories(
    path: Path,
    *,
    parents: bool = False,
    exist_ok: bool = False,
    expected_parent_identity: tuple[int, int] | None = None,
    _before_commit: Callable[[], None] | None = None,
) -> tuple[Path, ...]:
    """Create a directory chain atomically in one TxF transaction.

    Existing components must be real directories and are never returned as
    created entries.  ``parents=False`` requires the immediate parent to exist;
    ``exist_ok=True`` makes an already-existing final directory a verified no-op
    (an existing file or reparse point always fails).  The identity supplied for
    the nearest existing parent is checked before creation and held until the
    transaction commits.
    """

    path = _absolute_path(path)
    components = _directory_parts(path)
    existing: list[Path] = []
    missing: list[Path] = []
    first_missing_index: int | None = None
    for index, component in enumerate(components):
        try:
            details = os.lstat(component)
        except FileNotFoundError:
            if first_missing_index is None:
                first_missing_index = index
            missing.append(component)
            continue
        if first_missing_index is not None:
            # An object appearing below an absent parent cannot be reached
            # through this lexical path without a race or a reparse trick.
            raise RuntimeError(f"directory chain changed during validation: {component}")
        _validate_existing_directory(component)
        existing.append(component)

    if first_missing_index is None:
        if not stat.S_ISDIR(os.lstat(path).st_mode) or _directory_is_reparse(path):
            raise FileExistsError(f"directory target is not a safe directory: {path}")
        if not exist_ok:
            raise FileExistsError(f"directory already exists: {path}")
        nearest = existing[-1] if existing else Path(path.anchor)
        if expected_parent_identity is not None:
            if os.name == "nt":
                native = windows_file_identity(nearest)
                if _identity_key(native) != expected_parent_identity:
                    raise RuntimeError("directory parent changed before commit")
            else:
                details = os.stat(nearest, follow_symlinks=False)
                if (int(details.st_dev), int(details.st_ino)) != expected_parent_identity:
                    raise RuntimeError("directory parent changed before commit")
        return ()

    if not parents and len(missing) != 1:
        raise FileNotFoundError(f"directory parent does not exist: {path.parent}")
    nearest = existing[-1] if existing else Path(path.anchor)
    if not _path_exists(nearest):
        raise FileNotFoundError(f"directory parent does not exist: {nearest}")
    _validate_existing_directory(nearest)

    if os.name != "nt":
        return _transactional_create_directories_non_windows(
            path,
            missing,
            nearest=nearest,
            expected_parent_identity=expected_parent_identity,
            _before_commit=_before_commit,
        )

    kernel32 = _kernel32()
    transaction = _create_transaction("Windows Local MCP workspace directory create")
    held_handles: list[Any] = []
    created_handles: list[Any] = []
    committed = False
    try:
        # Hold every existing component, not only the leaf parent: replacement
        # of an ancestor must not redirect the CreateDirectoryTransactedW path.
        for component in existing:
            handle = _open_transacted_directory(component, transaction)
            identity = _identity_from_handle(handle)
            if identity.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                raise PermissionError(f"directory component is a reparse point: {component}")
            if not identity.attributes & _FILE_ATTRIBUTE_DIRECTORY:
                raise NotADirectoryError(f"directory component is not a directory: {component}")
            held_handles.append(handle)
        nearest_identity = _identity_from_handle(held_handles[-1]) if held_handles else None
        if expected_parent_identity is not None and (
            nearest_identity is None
            or _identity_key(nearest_identity) != expected_parent_identity
        ):
            raise RuntimeError("directory parent changed before commit")
        for component in missing:
            if not kernel32.CreateDirectoryTransactedW(None, str(component), None, transaction):
                _raise_last_error("CreateDirectoryTransactedW", component)
            created_handle = _open_transacted_directory(component, transaction)
            created_identity = _identity_from_handle(created_handle)
            if created_identity.attributes & _FILE_ATTRIBUTE_REPARSE_POINT or not (
                created_identity.attributes & _FILE_ATTRIBUTE_DIRECTORY
            ):
                raise RuntimeError(f"created directory is not a safe directory: {component}")
            created_handles.append(created_handle)

        if _before_commit is not None:
            _before_commit()
        for handle in reversed(created_handles):
            kernel32.CloseHandle(handle)
        created_handles.clear()
        # Existing component handles remain open through CommitTransaction so
        # an ancestor cannot be replaced between validation and publication.
        _finish_transaction(transaction, commit=True)
        committed = True
        for component in missing:
            try:
                details = os.lstat(component)
            except OSError as error:
                raise RuntimeError(
                    f"directory create committed but postcondition could not be verified: {component}"
                ) from error
            if _directory_is_reparse(component, details) or not stat.S_ISDIR(details.st_mode):
                raise RuntimeError(f"directory create committed an unsafe entry: {component}")
        return tuple(missing)
    finally:
        for handle in reversed(created_handles):
            kernel32.CloseHandle(handle)
        for handle in reversed(held_handles):
            kernel32.CloseHandle(handle)
        if not committed:
            _finish_transaction(transaction, commit=False)
        kernel32.CloseHandle(transaction)


def _transactional_create_directories_non_windows(
    path: Path,
    missing: list[Path],
    *,
    nearest: Path,
    expected_parent_identity: tuple[int, int] | None,
    _before_commit: Callable[[], None] | None,
) -> tuple[Path, ...]:
    """Portable directory fallback; every partial mutation is reversed on failure."""

    parent_details = os.stat(nearest, follow_symlinks=False)
    parent_key = (int(parent_details.st_dev), int(parent_details.st_ino))
    if expected_parent_identity is not None and parent_key != expected_parent_identity:
        raise RuntimeError("directory parent changed before commit")
    if _before_commit is not None:
        _before_commit()
    created: list[Path] = []
    try:
        for component in missing:
            if _path_exists(component):
                raise FileExistsError(f"directory target was created during validation: {component}")
            component.mkdir()
            _validate_existing_directory(component)
            created.append(component)
        return tuple(created)
    except Exception:
        _rollback_created_directories(created)
        raise


def transactional_remove_directory(
    path: Path,
    *,
    expected_identity: tuple[int, int],
    expected_parent_identity: tuple[int, int],
    _before_commit: Callable[[], None] | None = None,
) -> None:
    """Remove one verified empty directory without recursive traversal."""

    path = _absolute_path(path)
    if path == Path(path.anchor):
        raise PermissionError("filesystem root cannot be removed")
    if os.name != "nt":
        return _transactional_remove_directory_non_windows(
            path,
            expected_identity=expected_identity,
            expected_parent_identity=expected_parent_identity,
            _before_commit=_before_commit,
        )

    kernel32 = _kernel32()
    transaction = _create_transaction("Windows Local MCP workspace directory remove")
    parent_handle: Any | None = None
    target_handle: Any | None = None
    committed = False
    try:
        parent_handle = _open_transacted_directory(path.parent, transaction)
        parent_identity = _identity_from_handle(parent_handle)
        if parent_identity.attributes & _FILE_ATTRIBUTE_REPARSE_POINT or not (
            parent_identity.attributes & _FILE_ATTRIBUTE_DIRECTORY
        ):
            raise PermissionError(f"directory parent is not a safe directory: {path.parent}")
        if _identity_key(parent_identity) != expected_parent_identity:
            raise RuntimeError("directory parent changed before commit")
        # A removable directory must be opened with delete sharing, then closed
        # before RemoveDirectoryTransactedW.  Retaining a no-delete directory
        # handle here would make the Broker block its own removal.
        target_handle = _open_transacted_directory(path, transaction, share_delete=True)
        target_identity = _identity_from_handle(target_handle)
        if target_identity.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError(f"directory is a reparse point: {path}")
        if not target_identity.attributes & _FILE_ATTRIBUTE_DIRECTORY:
            raise NotADirectoryError(f"not a directory: {path}")
        if _identity_key(target_identity) != expected_identity:
            raise RuntimeError("directory target changed before commit")
        try:
            with os.scandir(path) as entries:
                if next(entries, None) is not None:
                    raise OSError("directory is not empty")
        except FileNotFoundError as error:
            raise RuntimeError("directory target disappeared before commit") from error
        kernel32.CloseHandle(target_handle)
        target_handle = None
        if _before_commit is not None:
            _before_commit()
        if not kernel32.RemoveDirectoryTransactedW(str(path), transaction):
            _raise_last_error("RemoveDirectoryTransactedW", path)
        _finish_transaction(transaction, commit=True)
        committed = True
        if _path_exists(path):
            raise RuntimeError("directory removal committed but target still exists")
    finally:
        if target_handle is not None:
            kernel32.CloseHandle(target_handle)
        if parent_handle is not None:
            kernel32.CloseHandle(parent_handle)
        if not committed:
            _finish_transaction(transaction, commit=False)
        kernel32.CloseHandle(transaction)


def _transactional_remove_directory_non_windows(
    path: Path,
    *,
    expected_identity: tuple[int, int],
    expected_parent_identity: tuple[int, int],
    _before_commit: Callable[[], None] | None,
) -> None:
    """Portable non-recursive rmdir fallback for tests only."""

    details = _validate_existing_directory(path)
    parent = _validate_existing_directory(path.parent)
    if (int(details.st_dev), int(details.st_ino)) != expected_identity:
        raise RuntimeError("directory target changed before commit")
    if (int(parent.st_dev), int(parent.st_ino)) != expected_parent_identity:
        raise RuntimeError("directory parent changed before commit")
    with os.scandir(path) as entries:
        if next(entries, None) is not None:
            raise OSError("directory is not empty")
    if _before_commit is not None:
        _before_commit()
    details = _validate_existing_directory(path)
    parent = _validate_existing_directory(path.parent)
    if (int(details.st_dev), int(details.st_ino)) != expected_identity or (
        int(parent.st_dev), int(parent.st_ino)
    ) != expected_parent_identity:
        raise RuntimeError("directory target changed before commit")
    path.rmdir()
    if _path_exists(path):
        raise RuntimeError("directory removal committed but target still exists")


# Directory aliases mirror the public Broker operation vocabulary.
transactional_mkdir = transactional_create_directories
transactional_remove_dir = transactional_remove_directory


def transactional_write_bytes(
    path: Path,
    data: bytes,
    *,
    expected_identity: tuple[int, int] | None,
    expected_size: int | None,
    expected_sha256: str | None,
    _before_commit: Callable[[], None] | None = None,
) -> WindowsFileIdentity:
    """CAS-style single-file commit inside one TxF transaction.

    The existing target identity, exact size, and SHA-256 are checked on the same transacted
    writer handle that receives the new bytes. TxF transactionally locks that file against
    external writers until CommitTransaction finishes. ``_before_commit`` exists only for
    deterministic race tests and startup probes; production callers leave it unset.
    """
    if os.name != "nt":
        raise OSError("transactional workspace commit requires Windows")
    existing_fields = (expected_identity, expected_size, expected_sha256)
    if any(value is None for value in existing_fields) and any(
        value is not None for value in existing_fields
    ):
        raise ValueError("existing target identity, size, and digest must be supplied together")
    kernel32 = _kernel32()
    transaction = _create_transaction("Windows Local MCP workspace write")
    handle: Any | None = None
    committed = False
    committed_identity: WindowsFileIdentity | None = None
    try:
        exists = expected_identity is not None
        handle = _open_transacted(path, transaction, exists=exists, delete=False)
        identity = _validate_regular_identity(
            handle,
            expected_identity=expected_identity,
            expected_size=expected_size,
            path=path,
        )
        if exists:
            assert expected_size is not None
            digest, size = _hash_handle(handle, max_bytes=expected_size)
            if size != expected_size or digest != expected_sha256:
                raise RuntimeError(
                    "write target content changed before transactional commit; target is stale or concurrently modified"
                )
        elif identity.size != 0:
            raise RuntimeError("new transactional target was not created empty")
        _write_handle(handle, data)
        committed_identity = WindowsFileIdentity(
            volume_serial=identity.volume_serial,
            file_index=identity.file_index,
            size=len(data),
            link_count=identity.link_count,
            attributes=identity.attributes,
        )
        if _before_commit is not None:
            _before_commit()
        kernel32.CloseHandle(handle)
        handle = None
        _finish_transaction(transaction, commit=True)
        committed = True
        return committed_identity
    finally:
        if handle is not None:
            kernel32.CloseHandle(handle)
        if not committed:
            _finish_transaction(transaction, commit=False)
        kernel32.CloseHandle(transaction)


def transactional_delete(
    path: Path,
    *,
    expected_identity: tuple[int, int],
    expected_size: int,
    expected_sha256: str,
    _before_commit: Callable[[], None] | None = None,
) -> None:
    """CAS-style single-file delete inside one TxF transaction."""
    if os.name != "nt":
        raise OSError("transactional workspace delete requires Windows")
    kernel32 = _kernel32()
    transaction = _create_transaction("Windows Local MCP workspace delete")
    handle: Any | None = None
    committed = False
    try:
        handle = _open_transacted(path, transaction, exists=True, delete=True)
        _validate_regular_identity(
            handle,
            expected_identity=expected_identity,
            expected_size=expected_size,
            path=path,
        )
        digest, size = _hash_handle(handle, max_bytes=expected_size)
        if size != expected_size or digest != expected_sha256:
            raise RuntimeError("delete target content changed before transactional commit")
        disposition = _FileDispositionInfo(True)
        if not kernel32.SetFileInformationByHandle(
            handle,
            _FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        ):
            _raise_last_error("SetFileInformationByHandle(FileDispositionInfo)", path)
        if _before_commit is not None:
            _before_commit()
        kernel32.CloseHandle(handle)
        handle = None
        _finish_transaction(transaction, commit=True)
        committed = True
    finally:
        if handle is not None:
            kernel32.CloseHandle(handle)
        if not committed:
            _finish_transaction(transaction, commit=False)
        kernel32.CloseHandle(transaction)


def _require_nontransacted_writer_blocked(path: Path, payload: bytes) -> None:
    try:
        path.write_bytes(payload)
    except OSError:
        return
    raise RuntimeError("TxF writer did not block a competing non-transacted writer")


def probe_transactional_workspace_commit(directory: Path) -> None:
    """Require usable TxF commit and isolation semantics for workspace mutation on Windows."""
    if os.name != "nt":
        return
    token = f"{os.getpid()}-{id(directory)}"
    first = directory / f".wlmcp-txf-probe-{token}.existing"
    created = directory / f".wlmcp-txf-probe-{token}.created"
    copied = directory / f".wlmcp-txf-probe-{token}.copied"
    moved = directory / f".wlmcp-txf-probe-{token}.moved"
    case_moved = moved.with_name(moved.name.upper())
    created_directory = directory / f".wlmcp-txf-probe-{token}.directory"
    nested_directory = created_directory / "nested"
    try:
        first.write_bytes(b"before")
        identity = windows_file_identity(first)
        committed = transactional_write_bytes(
            first,
            b"after",
            expected_identity=(identity.volume_serial, identity.file_index),
            expected_size=identity.size,
            expected_sha256=hashlib.sha256(b"before").hexdigest(),
            _before_commit=lambda: _require_nontransacted_writer_blocked(first, b"intruder"),
        )
        if (
            first.read_bytes() != b"after"
            or (committed.volume_serial, committed.file_index)
            != (identity.volume_serial, identity.file_index)
        ):
            raise RuntimeError("TxF existing-file commit did not preserve the validated target")
        created_identity = transactional_write_bytes(
            created,
            b"created",
            expected_identity=None,
            expected_size=None,
            expected_sha256=None,
            _before_commit=lambda: _require_nontransacted_writer_blocked(created, b"intruder"),
        )
        if created.read_bytes() != b"created":
            raise RuntimeError("TxF create commit did not become visible")
        live_created = windows_file_identity(created)
        if (live_created.volume_serial, live_created.file_index) != (
            created_identity.volume_serial,
            created_identity.file_index,
        ):
            raise RuntimeError("TxF create commit changed file identity after commit")
        parent_identity = windows_file_identity(directory)
        copied_identity = transactional_copy_file(
            first,
            copied,
            expected_source_identity=(identity.volume_serial, identity.file_index),
            expected_source_size=len(b"after"),
            expected_source_sha256=hashlib.sha256(b"after").hexdigest(),
            expected_source_parent_identity=(
                parent_identity.volume_serial,
                parent_identity.file_index,
            ),
            expected_destination_parent_identity=(
                parent_identity.volume_serial,
                parent_identity.file_index,
            ),
            max_bytes=len(b"after"),
        )
        moved_identity = transactional_move_file(
            copied,
            moved,
            expected_source_identity=(
                copied_identity.volume_serial,
                copied_identity.file_index,
            ),
            expected_source_size=copied_identity.size,
            expected_source_sha256=hashlib.sha256(b"after").hexdigest(),
            expected_source_parent_identity=(
                parent_identity.volume_serial,
                parent_identity.file_index,
            ),
            expected_destination_parent_identity=(
                parent_identity.volume_serial,
                parent_identity.file_index,
            ),
        )
        transactional_move_file(
            moved,
            case_moved,
            expected_source_identity=(
                moved_identity.volume_serial,
                moved_identity.file_index,
            ),
            expected_source_size=moved_identity.size,
            expected_source_sha256=hashlib.sha256(b"after").hexdigest(),
            expected_source_parent_identity=(
                parent_identity.volume_serial,
                parent_identity.file_index,
            ),
            expected_destination_parent_identity=(
                parent_identity.volume_serial,
                parent_identity.file_index,
            ),
        )
        created_directories = transactional_create_directories(
            nested_directory,
            parents=True,
            expected_parent_identity=(
                parent_identity.volume_serial,
                parent_identity.file_index,
            ),
        )
        if created_directories != (created_directory, nested_directory):
            raise RuntimeError("TxF directory chain creation returned an unexpected scope")
        nested_identity = windows_file_identity(nested_directory)
        created_directory_identity = windows_file_identity(created_directory)
        transactional_remove_directory(
            nested_directory,
            expected_identity=(nested_identity.volume_serial, nested_identity.file_index),
            expected_parent_identity=(
                created_directory_identity.volume_serial,
                created_directory_identity.file_index,
            ),
        )
        transactional_remove_directory(
            created_directory,
            expected_identity=(
                created_directory_identity.volume_serial,
                created_directory_identity.file_index,
            ),
            expected_parent_identity=(
                parent_identity.volume_serial,
                parent_identity.file_index,
            ),
        )
        transactional_delete(
            created,
            expected_identity=(created_identity.volume_serial, created_identity.file_index),
            expected_size=created_identity.size,
            expected_sha256=hashlib.sha256(b"created").hexdigest(),
            _before_commit=lambda: _require_nontransacted_writer_blocked(created, b"intruder"),
        )
        if created.exists():
            raise RuntimeError("TxF delete commit did not become visible")
    except (OSError, AttributeError) as error:
        raise RuntimeError(
            "workspace filesystem does not provide required Transactional NTFS commit semantics"
        ) from error
    finally:
        first.unlink(missing_ok=True)
        created.unlink(missing_ok=True)
        copied.unlink(missing_ok=True)
        moved.unlink(missing_ok=True)
        case_moved.unlink(missing_ok=True)
        if nested_directory.exists():
            nested_directory.rmdir()
        if created_directory.exists():
            created_directory.rmdir()
