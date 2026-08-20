from __future__ import annotations

import ctypes
import hashlib
import os
from collections.abc import Callable
from ctypes import get_last_error, wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE = 0x00010000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_BEGIN = 0
_FILE_DISPOSITION_INFO_CLASS = 4
_TRANSACTION_DO_NOT_PROMOTE = 0x00000001
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
    handle = kernel32.CreateFileW(
        str(path),
        0x00000080,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT,
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
        raise RuntimeError("write target changed before transactional commit")
    if expected_size is not None and identity.size != expected_size:
        raise RuntimeError("write target size changed before transactional commit")
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
) -> Any:
    kernel32 = _kernel32()
    desired_access = _GENERIC_READ | _GENERIC_WRITE | (_DELETE if delete else 0)
    handle = kernel32.CreateFileTransactedW(
        str(path),
        desired_access,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING if exists else _CREATE_NEW,
        _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
        transaction,
        None,
        None,
    )
    if handle in (None, _invalid_handle()):
        _raise_last_error("CreateFileTransactedW", path)
    return handle


def _finish_transaction(transaction: Any, *, commit: bool) -> None:
    ktm = _ktm()
    if commit:
        if not ktm.CommitTransaction(transaction):
            _raise_last_error("CommitTransaction")
    else:
        ktm.RollbackTransaction(transaction)


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
                raise RuntimeError("write target content changed before transactional commit")
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
