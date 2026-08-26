from __future__ import annotations

import ctypes
import os
import re
import site
import stat
import sys
import sysconfig
from dataclasses import dataclass
from importlib import machinery, metadata
from pathlib import Path
from typing import Any

from .util import canonical_json, sha256_bytes, sha256_text

RUNTIME_TRUST_VERSION = 1
_ROOT_DISTRIBUTIONS = (
    "mcp",
    "pydantic",
    "psutil",
    "python-docx",
    "openpyxl",
    "Pillow",
)
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_IMPORTABLE_FILE_SUFFIXES = tuple(
    sorted(
        {
            *(suffix.casefold() for suffix in machinery.SOURCE_SUFFIXES),
            *(suffix.casefold() for suffix in machinery.BYTECODE_SUFFIXES),
            *(suffix.casefold() for suffix in machinery.EXTENSION_SUFFIXES),
        },
        key=len,
        reverse=True,
    )
)
_STARTUP_IMPORT_FILES = {"sitecustomize.py", "usercustomize.py"}


@dataclass(frozen=True)
class RuntimeTree:
    root: Path
    excluded_roots: tuple[Path, ...] = ()


@dataclass(frozen=True)
class RuntimeTrustInventory:
    trees: tuple[RuntimeTree, ...]
    namespace_roots: tuple[Path, ...]
    security_paths: tuple[Path, ...]
    files: tuple[Path, ...]
    distributions: tuple[tuple[str, str], ...]


def _canonical_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _is_inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_reparse(path: Path) -> bool:
    details = path.lstat()
    attributes = int(getattr(details, "st_file_attributes", 0))
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _directory_has_package_init(path: Path) -> bool:
    return any((path / f"__init__{suffix}").is_file() for suffix in _IMPORTABLE_FILE_SUFFIXES)


def _namespace_entry_kind(path: Path) -> str | None:
    """Classify entries that can affect trusted Python import/startup resolution.

    Namespace roots are search locations, not recursive trust roots. A non-importable sibling
    such as the Windows hosted-toolcache ``python3.exe`` alias must not make the whole runtime
    unavailable merely because it is a reparse point. Python/native modules, startup ``.pth``
    hooks, regular packages and namespace-package directories remain security relevant.
    """

    name = path.name
    folded = name.casefold()
    if folded.endswith(".pth"):
        return "startup-hook"
    if folded in _STARTUP_IMPORT_FILES:
        return "startup-module"
    for suffix in _IMPORTABLE_FILE_SUFFIXES:
        if folded.endswith(suffix):
            module_name = name[: -len(suffix)] if suffix else name
            if module_name.isidentifier():
                return "module-file"
            return None

    if _is_reparse(path):
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            if name.isidentifier():
                raise RuntimeError(
                    f"trusted import namespace contains an unresolved package entry: {path}"
                ) from error
            return None
        if resolved.is_dir() and name.isidentifier():
            return "namespace-directory"
        return None

    if path.is_dir() and name.isidentifier():
        return "package-directory" if _directory_has_package_init(path) else "namespace-directory"
    return None


def _resolved_existing(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if _is_reparse(path):
        raise RuntimeError(f"trusted runtime path contains a reparse point: {path}")
    return resolved


def _security_descriptor_sha256(path: Path) -> str | None:
    if os.name != "nt":
        return None
    from ctypes import wintypes

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
            f"could not inspect trusted runtime security descriptor: {path}: {error}"
        )
    try:
        length = int(get_length(descriptor))
        if length <= 0:
            raise RuntimeError(
                f"trusted runtime security descriptor has invalid length: {path}"
            )
        return sha256_bytes(ctypes.string_at(descriptor, length))
    finally:
        local_free(descriptor)


def _site_package_roots() -> tuple[Path, ...]:
    candidates: set[Path] = set()
    for value in (sysconfig.get_path("purelib"), sysconfig.get_path("platlib")):
        if value:
            path = Path(value)
            if path.is_dir():
                candidates.add(path.resolve(strict=True))
    try:
        for value in site.getsitepackages():
            path = Path(value)
            if path.is_dir():
                candidates.add(path.resolve(strict=True))
    except AttributeError:
        pass
    return tuple(sorted(candidates, key=lambda item: os.path.normcase(str(item))))


def _distribution_closure() -> tuple[metadata.Distribution, ...]:
    pending = list(_ROOT_DISTRIBUTIONS)
    seen: set[str] = set()
    result: list[metadata.Distribution] = []
    while pending:
        requested = pending.pop()
        canonical = _canonical_distribution_name(requested)
        if canonical in seen:
            continue
        seen.add(canonical)
        try:
            distribution = metadata.distribution(requested)
        except metadata.PackageNotFoundError as error:
            if canonical in {
                _canonical_distribution_name(name) for name in _ROOT_DISTRIBUTIONS
            }:
                raise RuntimeError(
                    f"trusted runtime dependency is not installed: {requested}"
                ) from error
            continue
        result.append(distribution)
        for requirement in distribution.requires or ():
            match = _REQUIREMENT_NAME.match(requirement)
            if match is not None:
                pending.append(match.group(1))
    return tuple(
        sorted(
            result,
            key=lambda item: _canonical_distribution_name(
                str(item.metadata.get("Name") or "")
            ),
        )
    )


def _distribution_inventory(
    distributions: tuple[metadata.Distribution, ...],
) -> tuple[set[RuntimeTree], set[Path], tuple[tuple[str, str], ...]]:
    trees: set[RuntimeTree] = set()
    files: set[Path] = set()
    versions: list[tuple[str, str]] = []
    for distribution in distributions:
        name = str(distribution.metadata.get("Name") or "")
        versions.append((name, str(distribution.version)))
        listed = distribution.files
        if listed is None:
            raise RuntimeError(f"trusted dependency has no installed file manifest: {name}")
        base = Path(distribution.locate_file("")).resolve(strict=True)
        for relative in listed:
            located = Path(distribution.locate_file(relative))
            if not located.exists():
                raise RuntimeError(
                    f"trusted dependency file disappeared: {name}: {relative}"
                )
            resolved = located.resolve(strict=True)
            try:
                within = resolved.relative_to(base)
            except ValueError:
                files.add(resolved)
                continue
            if not within.parts:
                continue
            top = base / within.parts[0]
            if top.is_dir():
                trees.add(RuntimeTree(top.resolve(strict=True)))
            else:
                files.add(top.resolve(strict=True))
    return trees, files, tuple(versions)


def build_runtime_trust_inventory(package_root: Path | None = None) -> RuntimeTrustInventory:
    package = (package_root or Path(__file__).resolve(strict=True).parent).resolve(strict=True)
    source_root = package.parent.resolve(strict=True)
    site_roots = _site_package_roots()
    trees: set[RuntimeTree] = {RuntimeTree(package)}
    namespace_roots: set[Path] = {source_root}
    files: set[Path] = set()
    security_paths: set[Path] = {source_root}

    if not any(_is_inside(source_root, site_root) for site_root in site_roots):
        trees.add(RuntimeTree(source_root))

    for value in (sys.executable, getattr(sys, "_base_executable", None)):
        if value:
            path = Path(value)
            if path.is_file():
                resolved = path.resolve(strict=True)
                files.add(resolved)
                security_paths.add(resolved.parent)

    for prefix in {Path(sys.prefix), Path(sys.base_prefix)}:
        if prefix.is_dir():
            security_paths.add(prefix.resolve(strict=True))
        pyvenv = prefix / "pyvenv.cfg"
        if pyvenv.is_file():
            files.add(pyvenv.resolve(strict=True))
        dlls = prefix / "DLLs"
        if dlls.is_dir():
            trees.add(RuntimeTree(dlls.resolve(strict=True)))
        if os.name == "nt":
            for candidate in prefix.glob("python*.dll"):
                if candidate.is_file():
                    files.add(candidate.resolve(strict=True))
            for candidate in prefix.glob("vcruntime*.dll"):
                if candidate.is_file():
                    files.add(candidate.resolve(strict=True))

    # Production launchers execute before Python can inspect the control-plane marker. If
    # present adjacent to the active venv, they are part of the persistent Approved Host TCB.
    runtime_parent = Path(sys.prefix).resolve(strict=True).parent
    launcher_files = [
        runtime_parent / "run-server.ps1",
        runtime_parent / "run-approvals.ps1",
    ]
    existing_launchers = [path for path in launcher_files if path.is_file()]
    if existing_launchers:
        security_paths.add(runtime_parent)
        files.update(path.resolve(strict=True) for path in existing_launchers)

    for key in ("stdlib", "platstdlib"):
        value = sysconfig.get_path(key)
        if not value:
            continue
        root = Path(value)
        if root.is_dir():
            resolved = root.resolve(strict=True)
            excluded_roots = {
                site_root for site_root in site_roots if _is_inside(site_root, resolved)
            }
            for name in ("site-packages", "dist-packages"):
                nested = resolved / name
                if nested.is_dir():
                    excluded_roots.add(nested.resolve(strict=True))
            trees.add(
                RuntimeTree(
                    resolved,
                    tuple(
                        sorted(
                            excluded_roots,
                            key=lambda item: os.path.normcase(str(item)),
                        )
                    ),
                )
            )

    for site_root in site_roots:
        namespace_roots.add(site_root)
        security_paths.add(site_root)
        for candidate in site_root.glob("*.pth"):
            if candidate.is_file():
                files.add(candidate.resolve(strict=True))
        for name in ("sitecustomize.py", "usercustomize.py"):
            candidate = site_root / name
            if candidate.is_file():
                files.add(candidate.resolve(strict=True))

    dependency_trees, dependency_files, versions = _distribution_inventory(
        _distribution_closure()
    )
    trees.update(dependency_trees)
    files.update(dependency_files)

    for value in sys.path:
        if not value:
            continue
        candidate = Path(value)
        if candidate.is_file():
            files.add(candidate.resolve(strict=True))
        elif candidate.is_dir():
            resolved = candidate.resolve(strict=True)
            namespace_roots.add(resolved)
            if (
                resolved != source_root
                and not any(_is_inside(resolved, site_root) for site_root in site_roots)
                and not any(
                    _is_inside(resolved, tree.root) or _is_inside(tree.root, resolved)
                    for tree in trees
                )
            ):
                trees.add(RuntimeTree(resolved))

    return RuntimeTrustInventory(
        trees=tuple(sorted(trees, key=lambda item: os.path.normcase(str(item.root)))),
        namespace_roots=tuple(
            sorted(namespace_roots, key=lambda item: os.path.normcase(str(item)))
        ),
        security_paths=tuple(
            sorted(security_paths, key=lambda item: os.path.normcase(str(item)))
        ),
        files=tuple(sorted(files, key=lambda item: os.path.normcase(str(item)))),
        distributions=versions,
    )


def _tree_entries(tree: RuntimeTree) -> tuple[list[Path], list[Path]]:
    root = _resolved_existing(tree.root)
    excluded = tuple(path.resolve(strict=True) for path in tree.excluded_roots)
    if root.is_file():
        return [root], []
    files: list[Path] = []
    directories_seen: list[Path] = [root]
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        retained: list[str] = []
        for name in directories:
            candidate = current_path / name
            if any(
                candidate == excluded_root or _is_inside(candidate, excluded_root)
                for excluded_root in excluded
            ):
                continue
            if _is_reparse(candidate):
                raise RuntimeError(
                    f"trusted runtime tree contains a reparse directory: {candidate}"
                )
            retained.append(name)
            directories_seen.append(candidate.resolve(strict=True))
        directories[:] = retained
        for name in names:
            candidate = current_path / name
            if any(
                candidate == excluded_root or _is_inside(candidate, excluded_root)
                for excluded_root in excluded
            ):
                continue
            if _is_reparse(candidate) or not candidate.is_file():
                raise RuntimeError(
                    f"trusted runtime tree contains an unsafe file: {candidate}"
                )
            files.append(candidate.resolve(strict=True))
    return files, directories_seen


def _namespace_records(roots: tuple[Path, ...]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for root in roots:
        resolved = _resolved_existing(root)
        if not resolved.is_dir():
            continue
        entries: list[dict[str, Any]] = []
        for child in sorted(resolved.iterdir(), key=lambda item: item.name.casefold()):
            kind = _namespace_entry_kind(child)
            if kind is None:
                continue
            if _is_reparse(child):
                raise RuntimeError(
                    f"trusted import namespace contains a reparse point: {child}"
                )
            details = child.stat()
            entries.append(
                {
                    "name": child.name,
                    "kind": kind,
                    "device": int(details.st_dev),
                    "inode": int(details.st_ino),
                }
            )
        root_details = resolved.stat()
        records.append(
            {
                "root": str(resolved),
                "device": int(root_details.st_dev),
                "inode": int(root_details.st_ino),
                "security_sha256": _security_descriptor_sha256(resolved),
                "entries": entries,
            }
        )
    return records


def capture_runtime_dependency_state(
    *,
    max_files: int,
    max_bytes: int,
    inventory: RuntimeTrustInventory | None = None,
) -> dict[str, Any]:
    inventory = inventory or build_runtime_trust_inventory()
    candidates: set[Path] = set(inventory.files)
    directories: set[Path] = set()
    for tree in inventory.trees:
        tree_files, tree_directories = _tree_entries(tree)
        candidates.update(tree_files)
        directories.update(tree_directories)
    records: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(candidates, key=lambda item: os.path.normcase(str(item))):
        resolved = _resolved_existing(path)
        if not resolved.is_file():
            raise RuntimeError(f"trusted runtime dependency is not a regular file: {resolved}")
        data = resolved.read_bytes()
        total_bytes += len(data)
        if len(records) + 1 > max_files:
            raise RuntimeError(
                "trusted runtime dependency closure exceeds the file admission limit"
            )
        if total_bytes > max_bytes:
            raise RuntimeError(
                "trusted runtime dependency closure exceeds the byte admission limit"
            )
        details = resolved.stat()
        records.append(
            {
                "path": str(resolved),
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "device": int(details.st_dev),
                "inode": int(details.st_ino),
                "security_sha256": _security_descriptor_sha256(resolved),
            }
        )
    directory_records: list[dict[str, Any]] = []
    for directory in sorted(
        directories, key=lambda item: os.path.normcase(str(item))
    ):
        details = directory.stat()
        directory_records.append(
            {
                "path": str(directory),
                "device": int(details.st_dev),
                "inode": int(details.st_ino),
                "security_sha256": _security_descriptor_sha256(directory),
            }
        )
    security_records: list[dict[str, Any]] = []
    for path in inventory.security_paths:
        resolved = _resolved_existing(path)
        details = resolved.stat()
        security_records.append(
            {
                "path": str(resolved),
                "device": int(details.st_dev),
                "inode": int(details.st_ino),
                "security_sha256": _security_descriptor_sha256(resolved),
            }
        )
    namespace = _namespace_records(inventory.namespace_roots)
    payload = {
        "version": RUNTIME_TRUST_VERSION,
        "distributions": [
            {"name": name, "version": version}
            for name, version in inventory.distributions
        ],
        "namespace": namespace,
        "security_paths": security_records,
        "directories": directory_records,
        "files": records,
    }
    return {
        "version": RUNTIME_TRUST_VERSION,
        "file_count": len(records),
        "bytes": total_bytes,
        "digest": sha256_text(canonical_json(payload)),
        "distributions": payload["distributions"],
    }


def runtime_generation_identity(package_root: Path | None = None) -> dict[str, Any]:
    package = (package_root or Path(__file__).resolve(strict=True).parent).resolve(strict=True)
    source_root = package.parent.resolve(strict=True)
    artifacts: list[dict[str, Any]] = []
    candidates: set[Path] = set()
    for value in (sys.executable, getattr(sys, "_base_executable", None)):
        if value:
            candidate = Path(value)
            if candidate.is_file():
                candidates.add(candidate.resolve(strict=True))
    for prefix in {Path(sys.prefix), Path(sys.base_prefix)}:
        pyvenv = prefix / "pyvenv.cfg"
        if pyvenv.is_file():
            candidates.add(pyvenv.resolve(strict=True))
    for path in sorted(candidates, key=lambda item: os.path.normcase(str(item))):
        data = path.read_bytes()
        details = path.stat()
        artifacts.append(
            {
                "path": str(path),
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "device": int(details.st_dev),
                "inode": int(details.st_ino),
                "security_sha256": _security_descriptor_sha256(path),
            }
        )
    return {
        "version": RUNTIME_TRUST_VERSION,
        "prefix": str(Path(sys.prefix).resolve()),
        "base_prefix": str(Path(sys.base_prefix).resolve()),
        "source_root": str(source_root),
        "source_namespace": _namespace_records((source_root,))[0],
        "artifacts": artifacts,
    }
