from __future__ import annotations

import ctypes
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .runtime_trust import (
    RuntimeTree,
    RuntimeTrustInventory,
    _namespace_entry_kind,
    build_runtime_trust_inventory,
)
from .util import canonical_json, sha256_bytes, sha256_text

RUNTIME_IMMUTABILITY_VERSION = 1

# FILE_WRITE_DATA / FILE_ADD_FILE, FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY,
# FILE_WRITE_EA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC,
# and WRITE_OWNER. If the current non-admin WLMCP token has any of these rights
# anywhere in the trusted runtime closure, Approved Host could make a persistent
# change that executes before the next control-plane health check.
_DELETE_ACCESS = 0x00010000
_MUTATING_ACCESS_MASK = (
    0x00000002
    | 0x00000004
    | 0x00000010
    | 0x00000040
    | 0x00000100
    | _DELETE_ACCESS
    | 0x00040000
    | 0x00080000
)
_REPLACEMENT_ACCESS_MASK = 0x00000040 | _DELETE_ACCESS | 0x00040000 | 0x00080000
_VOLUME_ROOT_REPLACEMENT_ACCESS_MASK = _REPLACEMENT_ACCESS_MASK & ~_DELETE_ACCESS
_MAXIMUM_ALLOWED = 0x02000000
_TOKEN_QUERY = 0x0008
_TOKEN_DUPLICATE = 0x0002
_SECURITY_IMPERSONATION = 2

_FILE_GENERIC_READ = 0x00120089
_FILE_GENERIC_WRITE = 0x00120116
_FILE_GENERIC_EXECUTE = 0x001200A0
_FILE_ALL_ACCESS = 0x001F01FF


def _is_reparse(path: Path) -> bool:
    details = path.lstat()
    attributes = int(getattr(details, "st_file_attributes", 0))
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _resolved_existing(path: Path) -> Path:
    if _is_reparse(path):
        raise RuntimeError(f"Approved Host runtime path is a reparse point: {path}")
    return path.resolve(strict=True)


def _ancestor_directories(path: Path) -> set[Path]:
    current = path.resolve(strict=True)
    if current.is_file():
        current = current.parent
    result: set[Path] = set()
    while True:
        result.add(current)
        if current == Path(current.anchor):
            return result
        current = current.parent


def _ancestor_replacement_access_mask(path: Path) -> int:
    """Return rights that can replace a protected descendant through this ancestor."""
    if path == Path(path.anchor):
        # DELETE is object-scoped. On a volume root it describes deletion of the root object
        # itself, not authority to delete a deeper runtime descendant. FILE_DELETE_CHILD and
        # ACL-ownership mutation remain security-relevant even at the volume root.
        return _VOLUME_ROOT_REPLACEMENT_ACCESS_MASK
    return _REPLACEMENT_ACCESS_MASK


def _tree_paths(tree: RuntimeTree) -> tuple[set[Path], set[Path]]:
    root = _resolved_existing(tree.root)
    excluded = tuple(path.resolve(strict=True) for path in tree.excluded_roots)
    directories: set[Path] = {root}
    files: set[Path] = set()
    if root.is_file():
        return set(), {root}
    for current, child_directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        retained: list[str] = []
        for name in child_directories:
            candidate = current_path / name
            resolved = candidate.resolve(strict=True)
            if any(
                resolved == excluded_root
                or resolved.is_relative_to(excluded_root)
                for excluded_root in excluded
            ):
                continue
            if _is_reparse(candidate):
                raise RuntimeError(
                    f"Approved Host runtime tree contains a reparse directory: {candidate}"
                )
            directories.add(resolved)
            retained.append(name)
        child_directories[:] = retained
        for name in names:
            candidate = current_path / name
            if _is_reparse(candidate) or not candidate.is_file():
                raise RuntimeError(
                    f"Approved Host runtime tree contains an unsafe file: {candidate}"
                )
            resolved = candidate.resolve(strict=True)
            if any(
                resolved == excluded_root
                or resolved.is_relative_to(excluded_root)
                for excluded_root in excluded
            ):
                continue
            files.add(resolved)
    return directories, files


def _namespace_paths(root: Path) -> tuple[set[Path], set[Path]]:
    """Expand only entries that can participate in trusted Python import/startup.

    The namespace directory itself remains immutable so an Approved Host child cannot add
    a new importable sibling. Once a child directory is importable as either a regular or
    namespace package, its existing tree is recursively immutable. Non-importable siblings
    remain outside the trusted runtime closure.
    """

    resolved = _resolved_existing(root)
    if not resolved.is_dir():
        return set(), {resolved}
    directories: set[Path] = {resolved}
    files: set[Path] = set()
    for child in sorted(resolved.iterdir(), key=lambda item: item.name.casefold()):
        kind = _namespace_entry_kind(child)
        if kind is None:
            continue
        if _is_reparse(child):
            raise RuntimeError(
                f"Approved Host import namespace contains a reparse point: {child}"
            )
        if child.is_dir():
            child_directories, child_files = _tree_paths(RuntimeTree(child))
            directories.update(child_directories)
            files.update(child_files)
        elif child.is_file():
            files.add(child.resolve(strict=True))
        else:
            raise RuntimeError(
                f"Approved Host import namespace contains an unsafe entry: {child}"
            )
    return directories, files


def _validate_lexical_runtime_ancestors() -> None:
    """Reject lexical reparse ancestry without over-scoping unrelated parent creation rights."""
    values = [
        Path(__file__).absolute(),
        Path(sys.executable).absolute(),
        Path(sys.prefix).absolute(),
        Path(sys.base_prefix).absolute(),
    ]
    base_executable = getattr(sys, "_base_executable", None)
    if base_executable:
        values.append(Path(str(base_executable)).absolute())

    for value in values:
        current = value
        while True:
            if current.exists() and _is_reparse(current):
                raise RuntimeError(
                    f"Approved Host runtime lexical path contains a reparse point: {current}"
                )
            if current == Path(current.anchor):
                break
            current = current.parent


def _runtime_paths(
    package_root: Path | None = None,
    *,
    inventory: RuntimeTrustInventory | None = None,
) -> tuple[
    tuple[Path, ...],
    tuple[Path, ...],
    tuple[Path, ...],
    tuple[tuple[str, str], ...],
]:
    package = (package_root or Path(__file__).resolve(strict=True).parent).resolve(strict=True)
    supplied_inventory = inventory is not None
    inventory = inventory or build_runtime_trust_inventory(package)

    directories: set[Path] = set()
    files: set[Path] = set(inventory.files)
    if not supplied_inventory:
        _validate_lexical_runtime_ancestors()

    # Security paths describe an ACL/identity boundary, not a recursive import tree. Their
    # own mutating access is security-relevant because creation/replacement in the directory
    # can redirect a trusted runtime path; unrelated children are not automatically TCB.
    for security_path in inventory.security_paths:
        resolved = _resolved_existing(security_path)
        if resolved.is_dir():
            directories.add(resolved)
        elif resolved.is_file():
            files.add(resolved)
        else:
            raise RuntimeError(
                f"Approved Host runtime security path is not a regular path: {resolved}"
            )

    # Namespace roots are search locations. Keep the root immutable so new modules cannot be
    # injected, and expand only existing import/startup-capable entries.
    for root in inventory.namespace_roots:
        namespace_directories, namespace_files = _namespace_paths(root)
        directories.update(namespace_directories)
        files.update(namespace_files)

    # Declared runtime/dependency trees are complete TCB roots and remain recursively strict.
    for tree in inventory.trees:
        tree_directories, tree_files = _tree_paths(tree)
        directories.update(tree_directories)
        files.update(tree_files)

    # An editable checkout has launchers one directory above src. They run before
    # Python can inspect the tamper marker, so they are part of the Approved Host TCB.
    source_root = package.parent.resolve(strict=True)
    repository_root = source_root.parent
    if (repository_root / "pyproject.toml").is_file():
        directories.add(repository_root.resolve(strict=True))
        for name in ("run-server.ps1", "run-approvals.ps1", "pyproject.toml"):
            candidate = repository_root / name
            if candidate.is_file():
                files.add(candidate.resolve(strict=True))

    # A runtime directory itself must deny creation as well as replacement. More distant
    # ancestors only need to deny deleting/replacing the protected child or changing ACL
    # authority; harmless creation of an unrelated sibling at a volume root is not enough
    # to compromise the runtime.
    ancestor_directories: set[Path] = set()
    for path in tuple(directories) + tuple(files):
        ancestor_directories.update(_ancestor_directories(path))
    ancestor_directories.difference_update(directories)

    return (
        tuple(sorted(directories, key=lambda item: os.path.normcase(str(item)))),
        tuple(sorted(ancestor_directories, key=lambda item: os.path.normcase(str(item)))),
        tuple(sorted(files, key=lambda item: os.path.normcase(str(item)))),
        inventory.distributions,
    )


def _windows_security_descriptor(path: Path) -> tuple[bytes, int]:
    if os.name != "nt":
        raise RuntimeError("Windows security descriptors are unavailable on this platform")
    from ctypes import wintypes

    class GENERIC_MAPPING(ctypes.Structure):
        _fields_ = [
            ("GenericRead", wintypes.DWORD),
            ("GenericWrite", wintypes.DWORD),
            ("GenericExecute", wintypes.DWORD),
            ("GenericAll", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    get_named = advapi32.GetNamedSecurityInfoW
    get_named.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_named.restype = wintypes.DWORD

    get_length = advapi32.GetSecurityDescriptorLength
    get_length.argtypes = [ctypes.c_void_p]
    get_length.restype = wintypes.DWORD

    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    open_process_token.restype = wintypes.BOOL

    duplicate_token = advapi32.DuplicateToken
    duplicate_token.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    duplicate_token.restype = wintypes.BOOL

    access_check = advapi32.AccessCheck
    access_check.argtypes = [
        ctypes.c_void_p,
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(GENERIC_MAPPING),
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.BOOL),
    ]
    access_check.restype = wintypes.BOOL

    get_current_process = kernel32.GetCurrentProcess
    get_current_process.argtypes = []
    get_current_process.restype = wintypes.HANDLE

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p

    descriptor = ctypes.c_void_p()
    error = get_named(
        str(path),
        1,  # SE_FILE_OBJECT
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        None,
        None,
        None,
        ctypes.byref(descriptor),
    )
    if error != 0 or not descriptor.value:
        raise RuntimeError(
            f"could not inspect Approved Host runtime security descriptor: {path}: {error}"
        )

    token = wintypes.HANDLE()
    impersonation = wintypes.HANDLE()
    try:
        length = int(get_length(descriptor))
        if length <= 0:
            raise RuntimeError(
                f"Approved Host runtime security descriptor has invalid length: {path}"
            )
        descriptor_bytes = ctypes.string_at(descriptor, length)

        if not open_process_token(
            get_current_process(), _TOKEN_QUERY | _TOKEN_DUPLICATE, ctypes.byref(token)
        ):
            raise RuntimeError(
                "could not open the current process token for Approved Host runtime verification"
            )
        if not duplicate_token(token, _SECURITY_IMPERSONATION, ctypes.byref(impersonation)):
            raise RuntimeError(
                "could not create an impersonation token for Approved Host runtime verification"
            )

        mapping = GENERIC_MAPPING(
            _FILE_GENERIC_READ,
            _FILE_GENERIC_WRITE,
            _FILE_GENERIC_EXECUTE,
            _FILE_ALL_ACCESS,
        )
        privilege_length = wintypes.DWORD(1024)
        while True:
            privilege_set = ctypes.create_string_buffer(privilege_length.value)
            granted_access = wintypes.DWORD()
            access_status = wintypes.BOOL()
            ctypes.set_last_error(0)
            ok = access_check(
                descriptor,
                impersonation,
                _MAXIMUM_ALLOWED,
                ctypes.byref(mapping),
                ctypes.cast(privilege_set, ctypes.c_void_p),
                ctypes.byref(privilege_length),
                ctypes.byref(granted_access),
                ctypes.byref(access_status),
            )
            if ok:
                return descriptor_bytes, int(granted_access.value) if access_status.value else 0
            access_error = ctypes.get_last_error()
            if access_error == 122 and privilege_length.value > len(privilege_set):
                continue
            raise RuntimeError(
                f"could not evaluate Approved Host runtime access: {path}: {access_error}"
            )
    finally:
        if impersonation:
            close_handle(impersonation)
        if token:
            close_handle(token)
        local_free(descriptor)


def windows_effective_runtime_access(path: Path) -> int:
    """Return effective FILE_* access for the current Windows process token."""
    resolved = _resolved_existing(path)
    _descriptor, access = _windows_security_descriptor(resolved)
    return access


def _identity_record(
    path: Path,
    *,
    kind: str,
    access: int,
    descriptor: bytes | None,
) -> dict[str, Any]:
    details = path.stat()
    return {
        "path": str(path),
        "kind": kind,
        "device": int(details.st_dev),
        "inode": int(details.st_ino),
        "security_sha256": sha256_bytes(descriptor) if descriptor is not None else None,
        "effective_access": access,
    }


def _verify_paths_immutable(
    directories: tuple[Path, ...],
    ancestor_directories: tuple[Path, ...],
    files: tuple[Path, ...],
    *,
    access_resolver: Callable[[Path], int] | None = None,
    max_paths: int = 100_000,
) -> list[dict[str, Any]]:
    if len(directories) + len(ancestor_directories) + len(files) > max_paths:
        raise RuntimeError("Approved Host runtime closure exceeds the immutability path limit")
    records: list[dict[str, Any]] = []
    groups = (
        ("directory", directories, _MUTATING_ACCESS_MASK),
        ("ancestor", ancestor_directories, _REPLACEMENT_ACCESS_MASK),
        ("file", files, _MUTATING_ACCESS_MASK),
    )
    for kind, paths, denied_mask in groups:
        for path in paths:
            resolved = _resolved_existing(path)
            descriptor: bytes | None = None
            if access_resolver is None:
                descriptor, access = _windows_security_descriptor(resolved)
            else:
                access = int(access_resolver(resolved))
            effective_denied_mask = (
                _ancestor_replacement_access_mask(resolved)
                if kind == "ancestor"
                else denied_mask
            )
            mutating = access & effective_denied_mask
            if mutating:
                raise PermissionError(
                    "Approved Host requires an immutable Python/WLMCP runtime; "
                    f"the current principal has mutating access 0x{mutating:08x} to {resolved}"
                )
            records.append(
                _identity_record(
                    resolved,
                    kind=kind,
                    access=access,
                    descriptor=descriptor,
                )
            )
    return records


def _runtime_is_isolated() -> bool:
    return bool(sys.flags.isolated)


def assert_approved_host_runtime_immutable(
    package_root: Path | None = None,
    *,
    inventory: RuntimeTrustInventory | None = None,
    access_resolver: Callable[[Path], int] | None = None,
) -> dict[str, Any]:
    """Fail closed unless every startup-active runtime file and namespace is user-immutable."""
    if access_resolver is None:
        if os.name != "nt":
            raise RuntimeError("Approved Host runtime immutability is supported only on Windows")
        if not _runtime_is_isolated():
            raise RuntimeError("Approved Host requires Python isolated mode (-I)")
    directories, ancestor_directories, files, distributions = _runtime_paths(
        package_root, inventory=inventory
    )
    records = _verify_paths_immutable(
        directories,
        ancestor_directories,
        files,
        access_resolver=access_resolver,
    )
    payload = {
        "version": RUNTIME_IMMUTABILITY_VERSION,
        "scope": "complete-runtime",
        "paths": records,
        "distributions": [
            {"name": name, "version": version} for name, version in distributions
        ],
    }
    return {
        "version": RUNTIME_IMMUTABILITY_VERSION,
        "scope": "complete-runtime",
        "path_count": len(records),
        "file_count": len(files),
        "directory_count": len(directories),
        "ancestor_directory_count": len(ancestor_directories),
        "digest": sha256_text(canonical_json(payload)),
        "distributions": payload["distributions"],
    }
