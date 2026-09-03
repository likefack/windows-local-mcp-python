from __future__ import annotations

import ctypes
import json
import os
import platform
import re
import shutil
import subprocess
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from ctypes import create_unicode_buffer, get_last_error, wintypes
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .child_env import build_command_environment, sanitize_executable_search_path
from .config import Settings
from .sandbox_brokered_process import (
    brokered_process_probe_command,
    classify_brokered_process_probe,
)
from .tool_safety import capture_executable_identity, ensure_external_tool_executable
from .util import canonical_json, sha256_text
from .wfp_guard import (
    GUARD_POLICY_GENERATION,
    GUARD_VERSION,
    WfpGuardError,
    WfpGuardStateMismatchError,
    guard_verification_binding,
    guard_verification_binding_digest,
    resolve_sandbox_account_identity,
)
from .wfp_guard_identity import capture_wfp_guard_implementation_identity
from .windows_job import WindowsJobLimits, WindowsSandboxJob
from .windows_system import physical_filesystem_path

_CODEX_VERSION = re.compile(r"^codex-cli\s+([^\s]+)")
_OPENAI_AUTHENTICODE_NAMES = ('O="OpenAI OpCo, LLC"', 'CN="OpenAI OpCo, LLC"')
_SANDBOX_HELPERS = (
    "codex-command-runner.exe",
    "codex-windows-sandbox-setup.exe",
)
_NPM_SANDBOX_HELPERS = ("codex-code-mode-host.exe",)
_NPM_CODEX_PACKAGE_NAME = "@openai/codex"
_NPM_CODEX_WRAPPER_NAMES = ("codex.cmd", "codex.ps1", "codex")
_NPM_WINDOWS_TARGETS = {
    "x64": (
        "@openai/codex-win32-x64",
        "x86_64-pc-windows-msvc",
        "x64",
    ),
    "arm64": (
        "@openai/codex-win32-arm64",
        "aarch64-pc-windows-msvc",
        "arm64",
    ),
}
_NPM_PACKAGE_MANIFEST_MAX_BYTES = 1024 * 1024
_WLMCP_ISOLATION_POLICY_VERSION = 3
_SANDBOX_STATE_POLICY_VERSION = 2
_SANDBOX_STATE_GLOB_SCAN_MAX_DEPTH = 64
SANDBOX_LIVE_MARKER_VERSION = 5
SANDBOX_SECURITY_PROPERTIES = (
    "filesystem_read",
    "filesystem_write",
    "protected_information_read",
    "internet",
    "lan",
    "loopback",
    "descendant_containment",
    "termination",
    "resource_bound",
)
_ACCEPTED_RESIDUAL_RISK_PROPERTIES = frozenset({"protected_information_read", "lan"})
_MANDATORY_ROUTE_PROPERTIES = (
    "filesystem_read",
    "filesystem_write",
    "internet",
    "loopback",
    "termination",
    "resource_bound",
)
_MANDATORY_DESCENDANT_CHECKS = (
    "child_source_workspace_read_denied",
    "child_source_workspace_write_denied",
    "child_outside_user_read_denied",
    "child_control_plane_read_denied",
    "child_control_plane_write_denied",
    "child_internet_denied",
    "child_loopback_denied",
    "grandchild_source_workspace_read_denied",
    "grandchild_source_workspace_write_denied",
    "grandchild_outside_user_read_denied",
    "grandchild_control_plane_read_denied",
    "grandchild_control_plane_write_denied",
    "grandchild_internet_denied",
    "grandchild_loopback_denied",
)
_ALLOWED_PROPERTY_STATUSES = frozenset({"verified", "failed", "unverified"})
_BROKERED_PROCESS_CHECK = "brokered_process_creation_denied"


class ApprovedSandboxUnavailable(RuntimeError):
    """The approved sandbox cannot safely launch; callers must not fall back to host."""


@dataclass(frozen=True)
class CodexSandboxHelper:
    name: str
    executable: str
    executable_sha256: str
    executable_size: int
    executable_mtime_ns: int
    signature_status: str
    signer_subject: str
    signer_thumbprint: str
    stable_file_identity: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "executable": self.executable,
            "executable_sha256": self.executable_sha256,
            "executable_size": self.executable_size,
            "executable_mtime_ns": self.executable_mtime_ns,
            "signature_status": self.signature_status,
            "signer_subject": self.signer_subject,
            "signer_thumbprint": self.signer_thumbprint,
            "stable_file_identity": self.stable_file_identity,
        }


@dataclass(frozen=True)
class CodexSandboxBackend:
    executable: str
    executable_sha256: str
    executable_size: int
    executable_mtime_ns: int
    windows_mode: str
    permission_profile: str
    provenance: str
    signature_status: str
    signer_subject: str
    signer_thumbprint: str
    helpers: tuple[CodexSandboxHelper, ...]
    version: str = "unresolved"
    stable_file_identity: dict[str, Any] = field(default_factory=dict)
    isolation_policy_version: int = _WLMCP_ISOLATION_POLICY_VERSION
    max_processes: int = 64
    max_memory_bytes: int = 4 * 1024 * 1024 * 1024

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": "openai-codex-windows-sandbox",
            "adapter": "installed-codex-cli-sandbox-entrypoint",
            "executable": self.executable,
            "executable_sha256": self.executable_sha256,
            "executable_size": self.executable_size,
            "executable_mtime_ns": self.executable_mtime_ns,
            "version": self.version,
            "windows_mode": self.windows_mode,
            "permission_profile": self.permission_profile,
            "provenance": self.provenance,
            "signature_status": self.signature_status,
            "signer_subject": self.signer_subject,
            "signer_thumbprint": self.signer_thumbprint,
            "stable_file_identity": self.stable_file_identity,
            "helper_dependencies": [helper.as_dict() for helper in self.helpers],
            "wlmcp_isolation_policy_version": self.isolation_policy_version,
            "max_processes": self.max_processes,
            "max_memory_bytes": self.max_memory_bytes,
            "model_api_usage": "none; codex sandbox does not start an agent",
            "authentication_required": False,
            "distribution_mode": "installed_codex_dependency",
        }


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _discovery_path_is_allowed(path: Path, settings: Settings) -> bool:
    """Reject discovery locators and package roots controlled by MCP input roots."""
    if not path.is_absolute():
        return False
    try:
        lexical = Path(os.path.abspath(str(path)))
        resolved = lexical.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return False

    roots = [settings.workspace_root, settings.data_dir]
    if settings.sandbox_scratch_dir is not None:
        roots.append(settings.sandbox_scratch_dir)
    try:
        protected_roots = [Path(root).resolve(strict=False) for root in roots]
    except (OSError, RuntimeError, ValueError):
        return False
    return not any(
        _path_is_within(candidate, root)
        for root in protected_roots
        for candidate in (lexical, resolved)
    )


def _is_regular_non_reparse_file(path: Path) -> bool:
    try:
        if not path.is_file() or path.is_symlink():
            return False
        attributes = int(getattr(path.stat(), "st_file_attributes", 0))
    except OSError:
        return False
    # FILE_ATTRIBUTE_REPARSE_POINT. The final executable is checked again by
    # ensure_external_tool_executable and the identity capture functions.
    return not attributes & 0x400


def _read_npm_package_manifest(path: Path) -> dict[str, Any] | None:
    try:
        if not _is_regular_non_reparse_file(path):
            return None
        if path.stat().st_size > _NPM_PACKAGE_MANIFEST_MAX_BYTES:
            return None
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _npm_windows_target() -> tuple[str, str, str]:
    values = (
        os.environ.get("PROCESSOR_ARCHITEW6432"),
        os.environ.get("PROCESSOR_ARCHITECTURE"),
        platform.machine(),
    )
    for value in values:
        if not value:
            continue
        normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
        if normalized in {"amd64", "x64", "x8664"}:
            return _NPM_WINDOWS_TARGETS["x64"]
        if normalized in {"arm64", "aarch64"}:
            return _NPM_WINDOWS_TARGETS["arm64"]
    raise ApprovedSandboxUnavailable("Windows native architecture is not supported by Codex npm")


def _manifest_has_value(manifest: dict[str, Any], key: str, expected: str) -> bool:
    values = manifest.get(key)
    return isinstance(values, list) and expected in {str(value) for value in values}


def _manifest_declares_codex_wrapper(manifest: dict[str, Any]) -> bool:
    entry = manifest.get("bin")
    if isinstance(entry, str):
        return entry.replace("\\", "/") == "bin/codex.js"
    return (
        isinstance(entry, dict)
        and str(entry.get("codex") or "").replace("\\", "/") == "bin/codex.js"
    )


def _validate_npm_codex_package_root(
    package_root: Path, settings: Settings
) -> Path | None:
    """Resolve only the exact native path described by the official npm layout."""
    if package_root.name.casefold() != "codex":
        return None
    if not _discovery_path_is_allowed(package_root, settings):
        return None
    manifest = _read_npm_package_manifest(package_root / "package.json")
    if manifest is None or manifest.get("name") != _NPM_CODEX_PACKAGE_NAME:
        return None
    if not _manifest_declares_codex_wrapper(manifest):
        return None
    if not _is_regular_non_reparse_file(package_root / "bin" / "codex.js"):
        return None

    optional_dependencies = manifest.get("optionalDependencies")
    if not isinstance(optional_dependencies, dict):
        return None
    try:
        target_package, target_triple, target_cpu = _npm_windows_target()
    except ApprovedSandboxUnavailable:
        return None
    if target_package not in optional_dependencies:
        return None
    target_package_directory = target_package.rsplit("/", 1)[-1]

    target_roots = (
        package_root / "node_modules" / "@openai" / target_package_directory,
        package_root.parent / target_package_directory,
    )
    for target_root in target_roots:
        if not _discovery_path_is_allowed(target_root, settings):
            continue
        target_manifest = _read_npm_package_manifest(target_root / "package.json")
        if target_manifest is None:
            continue
        if target_manifest.get("name") not in {
            _NPM_CODEX_PACKAGE_NAME,
            target_package,
        }:
            continue
        if not _manifest_has_value(target_manifest, "os", "win32"):
            continue
        if not _manifest_has_value(target_manifest, "cpu", target_cpu):
            continue
        native = target_root / "vendor" / target_triple / "bin" / "codex.exe"
        helper = target_root / "vendor" / target_triple / "bin" / _NPM_SANDBOX_HELPERS[0]
        if not _is_regular_non_reparse_file(native):
            continue
        if not _is_regular_non_reparse_file(helper):
            continue
        try:
            return native.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
    return None


def _npm_wrapper_locator_paths(settings: Settings) -> Iterator[Path]:
    """Find npm shims as locators only; no shim is ever executed or trusted."""
    roots: list[Path] = []
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        value = raw.strip().strip('"')
        if value:
            roots.append(Path(value))
    for name in ("APPDATA", "LOCALAPPDATA"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value) / "npm")
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        roots.append(Path(user_profile) / "AppData" / "Roaming" / "npm")
    for name in ("PROGRAMW6432", "PROGRAMFILES", "PROGRAMFILES(X86)"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value) / "nodejs")
    try:
        roots.append(Path.home() / "AppData" / "Roaming" / "npm")
    except (OSError, RuntimeError):
        pass

    seen: set[str] = set()
    for root in roots:
        if not root.is_absolute():
            continue
        for name in _NPM_CODEX_WRAPPER_NAMES:
            wrapper = root / name
            if not _is_regular_non_reparse_file(wrapper):
                continue
            if not _discovery_path_is_allowed(wrapper, settings):
                continue
            try:
                key = os.path.normcase(str(wrapper.resolve(strict=True)))
            except (OSError, RuntimeError):
                continue
            if key in seen:
                continue
            seen.add(key)
            yield wrapper


def _npm_package_root_for_wrapper(wrapper: Path, settings: Settings) -> Path | None:
    if wrapper.name.casefold() not in {name.casefold() for name in _NPM_CODEX_WRAPPER_NAMES}:
        return None
    if not _discovery_path_is_allowed(wrapper, settings):
        return None
    prefix = wrapper.parent
    if prefix.name.casefold() == "bin":
        prefix = prefix.parent
    package_root = prefix / "node_modules" / "@openai" / "codex"
    return package_root if _discovery_path_is_allowed(package_root, settings) else None


def _iter_npm_codex_candidates(
    settings: Settings,
) -> Iterator[tuple[Path, str, tuple[str, ...], bool]]:
    for wrapper in _npm_wrapper_locator_paths(settings):
        package_root = _npm_package_root_for_wrapper(wrapper, settings)
        if package_root is None:
            continue
        native = _validate_npm_codex_package_root(package_root, settings)
        if native is None:
            continue
        yield native, "npm-global-codex-package", _NPM_SANDBOX_HELPERS, True


def _looks_like_npm_codex_native_path(path: Path) -> bool:
    try:
        target_root = path.parent.parent.parent.parent
    except (AttributeError, IndexError):
        return False
    return (
        path.name.casefold() == "codex.exe"
        and path.parent.name.casefold() == "bin"
        and target_root.name.casefold().startswith("codex-win32-")
    )


def _validated_npm_native_path(path: Path, settings: Settings) -> Path | None:
    if not _looks_like_npm_codex_native_path(path):
        return None
    target_root = path.parent.parent.parent.parent
    possible_roots = (
        target_root.parent / "codex",
        target_root.parent.parent.parent,
    )
    seen: set[str] = set()
    for package_root in possible_roots:
        try:
            key = os.path.normcase(str(package_root.resolve(strict=False)))
        except (OSError, RuntimeError):
            continue
        if key in seen:
            continue
        seen.add(key)
        native = _validate_npm_codex_package_root(package_root, settings)
        if native is not None and os.path.normcase(str(native)) == os.path.normcase(str(path)):
            return native
    return None


def resolve_codex_sandbox_backend(settings: Settings) -> CodexSandboxBackend:
    if not settings.approved_sandbox_enabled:
        raise ApprovedSandboxUnavailable("Approved Sandbox is disabled by local policy")
    if os.name != "nt":
        raise ApprovedSandboxUnavailable("Approved Sandbox requires native Windows")

    candidates: list[tuple[Path, str, tuple[str, ...], bool]] = []
    if settings.approved_sandbox_codex_path is not None:
        explicit_path = settings.approved_sandbox_codex_path
        explicit_is_npm = _looks_like_npm_codex_native_path(explicit_path)
        candidates.append(
            (
                explicit_path,
                "explicit-trusted-local-config",
                _NPM_SANDBOX_HELPERS if explicit_is_npm else _SANDBOX_HELPERS,
                explicit_is_npm,
            )
        )
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        cache_root = Path(local_app_data) / "OpenAI" / "Codex" / "bin"
        if cache_root.is_dir():
            candidates.extend(
                (
                    item,
                    "openai-codex-desktop-install-root",
                    _SANDBOX_HELPERS,
                    False,
                )
                for item in sorted(
                    cache_root.glob("*/codex.exe"),
                    key=lambda item: item.stat().st_mtime_ns,
                    reverse=True,
                )
            )
        candidates.append(
            (
                Path(local_app_data)
                / "Programs"
                / "OpenAI"
                / "Codex"
                / "bin"
                / "codex.exe",
                "openai-codex-program-install-root",
                _SANDBOX_HELPERS,
                False,
            )
        )
    candidates.extend(
        [
            (
                Path.home()
                / ".codex"
                / "packages"
                / "standalone"
                / "current"
                / "bin"
                / "codex.exe",
                "codex-managed-standalone-root",
                _SANDBOX_HELPERS,
                False,
            ),
            (
                Path.home()
                / ".codex"
                / "packages"
                / "standalone"
                / "current"
                / "codex.exe",
                "codex-managed-standalone-root",
                _SANDBOX_HELPERS,
                False,
            ),
        ]
    )
    candidates.extend(_iter_npm_codex_candidates(settings))

    errors: list[str] = []
    seen: set[str] = set()
    for candidate, provenance, helper_names, requires_npm_package in candidates:
        folded = os.path.normcase(str(candidate))
        if folded in seen:
            continue
        seen.add(folded)
        try:
            if requires_npm_package:
                npm_native = _validated_npm_native_path(candidate, settings)
                if npm_native is None or os.path.normcase(str(npm_native)) != os.path.normcase(
                    str(candidate)
                ):
                    raise ApprovedSandboxUnavailable(
                        "Codex npm package metadata or native target is invalid"
                    )
            executable = Path(
                ensure_external_tool_executable(
                    str(candidate),
                    workspace_root=settings.workspace_root,
                    data_dir=settings.data_dir,
                    sandbox_scratch_dir=settings.sandbox_scratch_dir,
                )
            ).resolve(strict=True)
            authenticode = _openai_authenticode_identity(executable)
            executable_identity = capture_executable_identity(
                executable,
                provenance=provenance,
            )
            helpers = tuple(
                _resolve_codex_helper(settings, executable, name) for name in helper_names
            )
            backend = CodexSandboxBackend(
                executable=str(executable),
                executable_sha256=str(executable_identity["sha256"]),
                executable_size=int(executable_identity["size"]),
                executable_mtime_ns=int(executable_identity["mtime_ns"]),
                windows_mode=settings.approved_sandbox_windows_mode,
                permission_profile=settings.approved_sandbox_permission_profile,
                provenance=provenance,
                signature_status=str(authenticode["status"]),
                signer_subject=str(authenticode["subject"]),
                signer_thumbprint=str(authenticode["thumbprint"]),
                helpers=helpers,
                stable_file_identity=dict(executable_identity["stable_file_identity"]),
                max_processes=settings.max_sandbox_processes,
                max_memory_bytes=settings.max_sandbox_memory_bytes,
            )
            # Version output is part of the backend identity, and the complete executable
            # closure remains held while the version command runs.
            with hold_codex_sandbox_backend(backend):
                version = probe_codex_version(backend, settings)
            return replace(backend, version=version)
        except (
            ApprovedSandboxUnavailable,
            FileNotFoundError,
            OSError,
            PermissionError,
            ValueError,
        ) as error:
            errors.append(f"{candidate}: {type(error).__name__}")
    detail = "; ".join(errors[:4])
    raise ApprovedSandboxUnavailable(
        "installed Codex sandbox launcher was not found or was not accessible"
        + (f" ({detail})" if detail else "")
    )


def verify_codex_sandbox_backend(
    settings: Settings, expected: dict[str, Any]
) -> CodexSandboxBackend:
    backend = resolve_codex_sandbox_backend(settings)
    actual = backend.as_dict()
    for key in (
        "executable",
        "executable_sha256",
        "executable_size",
        "executable_mtime_ns",
        "windows_mode",
        "permission_profile",
        "provenance",
        "signature_status",
        "signer_subject",
        "signer_thumbprint",
        "stable_file_identity",
        "helper_dependencies",
        "version",
        "wlmcp_isolation_policy_version",
        "max_processes",
        "max_memory_bytes",
    ):
        if actual.get(key) != expected.get(key):
            raise ApprovedSandboxUnavailable(
                f"Approved Sandbox backend changed after approval request: {key}"
            )
    return backend


def sandbox_isolation_context(
    settings: Settings, backend: CodexSandboxBackend
) -> dict[str, Any]:
    """Return the stable security inputs that determine the effective Sandbox route."""

    assert settings.sandbox_scratch_dir is not None

    def root_identity(path: Path) -> dict[str, Any]:
        resolved = path.resolve(strict=True)
        details = resolved.stat()
        return {
            "device": int(details.st_dev),
            "inode": int(details.st_ino),
            "physical_path": physical_filesystem_path(resolved),
        }

    def stable_paths(paths: Sequence[Path]) -> list[str]:
        return sorted(
            {str(path.resolve()) for path in paths},
            key=lambda value: (os.path.normcase(value), value),
        )

    def stable_names(values: Sequence[str]) -> list[str]:
        return sorted(
            {str(value) for value in values},
            key=lambda value: (os.path.normcase(value), value),
        )

    return {
        "version": 3,
        "backend": backend.as_dict(),
        "wfp_guard_implementation": capture_wfp_guard_implementation_identity(),
        "windows_os_identity": windows_os_identity(),
        "roots": {
            "workspace_root": root_identity(settings.workspace_root),
            "data_dir": root_identity(settings.data_dir),
            "sandbox_scratch_dir": root_identity(settings.sandbox_scratch_dir),
        },
        "blocked_file_names": stable_names(settings.blocked_file_names),
        "read_denied_directories": stable_names(settings.read_denied_directories),
        "write_denied_directories": stable_names(settings.write_denied_directories),
        "hidden_directories": stable_names(settings.hidden_directories),
        "child_environment_allowlist": stable_names(settings.child_environment_allowlist),
        "sandbox_dependency_readable_paths": stable_paths(
            settings.sandbox_dependency_readable_paths
        ),
        "live_verification_ttl_seconds": settings.sandbox_live_verification_ttl_seconds,
        "max_sandbox_scratch_bytes": settings.max_sandbox_scratch_bytes,
        "wlmcp_isolation_policy_version": backend.isolation_policy_version,
        "process_count_limit": backend.max_processes,
        "process_tree_memory_limit_bytes": backend.max_memory_bytes,
        "configured_process_count_limit": settings.max_sandbox_processes,
        "configured_process_tree_memory_limit_bytes": settings.max_sandbox_memory_bytes,
        "sandbox_state_policy": {
            "version": _SANDBOX_STATE_POLICY_VERSION,
            "filesystem_policy_generation": 2,
            "network_policy_generation": 1,
            "filesystem": "restricted",
            "network": "restricted",
            "direct_network_disabled": True,
            "glob_scan_max_depth": _SANDBOX_STATE_GLOB_SCAN_MAX_DEPTH,
            "use_legacy_landlock": False,
        },
    }


def isolation_context_digest(settings: Settings, backend: CodexSandboxBackend) -> str:
    """Hash the complete security-relevant configuration used by live verification."""

    return sha256_text(canonical_json(sandbox_isolation_context(settings, backend)))


def windows_os_identity() -> dict[str, Any]:
    """Return the Windows product/build/UBR/architecture identity bound to live evidence."""

    if os.name != "nt":
        return {"platform": os.name, "supported_security_boundary": False}

    import winreg

    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            values = {
                name: winreg.QueryValueEx(key, name)[0]
                for name in (
                    "ProductName",
                    "EditionID",
                    "DisplayVersion",
                    "CurrentMajorVersionNumber",
                    "CurrentMinorVersionNumber",
                    "CurrentBuildNumber",
                    "UBR",
                )
            }
    except OSError as error:
        raise ApprovedSandboxUnavailable(
            "Windows product/build identity could not be read"
        ) from error

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetNativeSystemInfo.argtypes = [wintypes.LPVOID]
    kernel32.GetNativeSystemInfo.restype = None
    system_info = (ctypes.c_byte * 64)()
    kernel32.GetNativeSystemInfo(ctypes.byref(system_info))
    architecture_code = ctypes.cast(
        ctypes.byref(system_info), ctypes.POINTER(ctypes.c_ushort)
    ).contents.value
    architecture = {
        0: "x86",
        5: "arm",
        6: "ia64",
        9: "amd64",
        12: "arm64",
    }.get(int(architecture_code), f"unknown-{architecture_code}")
    if architecture.startswith("unknown-"):
        raise ApprovedSandboxUnavailable("Windows native architecture is unrecognized")
    return {
        "platform": "windows",
        "product_name": str(values["ProductName"]),
        "edition_id": str(values["EditionID"]),
        "display_version": str(values["DisplayVersion"]),
        "major_version": int(values["CurrentMajorVersionNumber"]),
        "minor_version": int(values["CurrentMinorVersionNumber"]),
        "build": int(values["CurrentBuildNumber"]),
        "ubr": int(values["UBR"]),
        "native_architecture": architecture,
    }


def sandbox_live_verification_route_eligible(evidence: dict[str, Any]) -> bool:
    """Apply the Security Contract route gate while preserving accepted residual risks."""

    properties = evidence.get("properties")
    if not isinstance(properties, dict):
        return False
    for name in SANDBOX_SECURITY_PROPERTIES:
        item = properties.get(name)
        if (
            not isinstance(item, dict)
            or item.get("status") not in _ALLOWED_PROPERTY_STATUSES
        ):
            return False
    if any(
        properties[name].get("status") != "verified"
        for name in _MANDATORY_ROUTE_PROPERTIES
    ):
        return False

    checks = evidence.get("checks")
    if not isinstance(checks, dict) or checks.get(_BROKERED_PROCESS_CHECK) is not True:
        return False

    descendant = properties.get("descendant_containment")
    if not isinstance(descendant, dict):
        return False
    if descendant.get("status") == "verified":
        return True

    return all(checks.get(name) is True for name in _MANDATORY_DESCENDANT_CHECKS)


def _parse_live_verification_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _live_verification_failure_reason(evidence: dict[str, Any]) -> str | None:
    properties = evidence.get("properties")
    if isinstance(properties, dict):
        failed = sorted(
            name
            for name, item in properties.items()
            if isinstance(item, dict) and item.get("status") == "failed"
        )
        if failed:
            return "security boundary failed: " + ", ".join(failed)
    persisted_reason = evidence.get("verification_failure_reason")
    if isinstance(persisted_reason, str) and persisted_reason:
        return persisted_reason[:2000]
    diagnostics = evidence.get("diagnostics")
    if isinstance(diagnostics, dict):
        reason = diagnostics.get("verification_error")
        if isinstance(reason, str) and reason:
            return reason[:2000]
    return None


def _has_failed_live_property(evidence: dict[str, Any]) -> bool:
    properties = evidence.get("properties")
    return isinstance(properties, dict) and any(
        isinstance(item, dict) and item.get("status") == "failed"
        for item in properties.values()
    )


def codex_sandbox_live_verification_status(
    settings: Settings,
    backend: CodexSandboxBackend,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Durable marker を実行可否とは独立した lifecycle 状態へ分類する。"""

    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    base: dict[str, Any] = {
        "status": "missing",
        "evidence": None,
        "last_verified_at": None,
        "last_verification_attempt_at": None,
        "stale_reason": None,
        "failure_reason": None,
    }
    try:
        evidence = json.loads(marker.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return base
    except (OSError, ValueError) as error:
        return {
            **base,
            "status": "stale",
            "stale_reason": f"marker_unreadable_or_invalid: {type(error).__name__}",
        }
    if not isinstance(evidence, dict):
        return {**base, "status": "stale", "stale_reason": "marker_payload_not_object"}
    result = {
        **base,
        "evidence": evidence,
        "last_verified_at": (
            evidence.get("verified_at")
            if evidence.get("verification_status") == "verified"
            else None
        ),
        "last_verification_attempt_at": evidence.get("attempted_at")
        or evidence.get("verified_at"),
    }
    if evidence.get("version") != SANDBOX_LIVE_MARKER_VERSION:
        return {**result, "status": "stale", "stale_reason": "marker_schema_incompatible"}
    persisted_status = evidence.get("verification_status")
    if persisted_status == "verifying":
        return {**result, "status": "verifying"}
    if persisted_status in {"failed", "unverified"}:
        return {
            **result,
            "status": persisted_status,
            "failure_reason": _live_verification_failure_reason(evidence)
            or "required live properties remain unverified",
        }
    try:
        context = sandbox_isolation_context(settings, backend)
        guard_implementation = context.get("wfp_guard_implementation")
        os_identity = context.get("windows_os_identity")
        account_identity = resolve_sandbox_account_identity().as_dict()
    except (OSError, PermissionError, RuntimeError, ValueError, WfpGuardError) as error:
        return {
            **result,
            "status": "stale",
            "stale_reason": f"current_isolation_identity_unavailable: {type(error).__name__}",
        }
    if not isinstance(guard_implementation, dict) or not isinstance(os_identity, dict):
        return {**result, "status": "stale", "stale_reason": "current_identity_incomplete"}
    expected_isolation_digest = sha256_text(canonical_json(context))
    wfp_binding = evidence.get("wfp_guard_binding")
    identity_checks = (
        (
            "backend_identity_mismatch",
            evidence.get("backend_digest")
            == sha256_text(canonical_json(backend.as_dict())),
        ),
        ("backend_version_mismatch", evidence.get("backend_version") == backend.version),
        (
            "isolation_context_mismatch",
            evidence.get("isolation_context_digest") == expected_isolation_digest,
        ),
        (
            "guard_implementation_mismatch",
            evidence.get("guard_implementation_digest")
            == guard_implementation.get("digest")
            and evidence.get("guard_implementation") == guard_implementation,
        ),
        (
            "windows_os_identity_mismatch",
            evidence.get("windows_os_identity_digest")
            == sha256_text(canonical_json(os_identity))
            and evidence.get("windows_os_identity") == os_identity,
        ),
        (
            "sandbox_account_identity_mismatch",
            evidence.get("sandbox_account_identity") == account_identity,
        ),
        (
            "wfp_guard_binding_mismatch",
            isinstance(wfp_binding, dict)
            and wfp_binding.get("guard_version") == GUARD_VERSION
            and wfp_binding.get("policy_generation") == GUARD_POLICY_GENERATION
            and wfp_binding.get("sandbox_account_identity") == account_identity
            and evidence.get("wfp_guard_binding_digest")
            == sha256_text(canonical_json(wfp_binding)),
        ),
    )
    for reason, matches in identity_checks:
        if not matches:
            return {**result, "status": "stale", "stale_reason": reason}

    verified_at = _parse_live_verification_time(evidence.get("verified_at"))
    if verified_at is None:
        return {**result, "status": "stale", "stale_reason": "verified_at_invalid"}
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    current = current.astimezone(UTC)
    if verified_at > current + timedelta(minutes=5):
        return {**result, "status": "stale", "stale_reason": "verified_at_in_future"}
    if current - verified_at > timedelta(
        seconds=settings.sandbox_live_verification_ttl_seconds
    ):
        return {**result, "status": "stale", "stale_reason": "verification_ttl_expired"}

    if sandbox_live_verification_route_eligible(evidence):
        return {
            **result,
            "status": "verified",
            "last_verified_at": evidence.get("verified_at"),
        }
    failure_reason = _live_verification_failure_reason(evidence)
    inferred_status = "failed" if _has_failed_live_property(evidence) else "unverified"
    return {
        **result,
        "status": inferred_status,
        "failure_reason": failure_reason or "required live properties remain unverified",
    }


def require_codex_sandbox_live_verification(
    settings: Settings, backend: CodexSandboxBackend
) -> dict[str, Any]:
    """Bind execution to successful live checks of this exact installed backend."""
    if not settings.approved_sandbox_require_live_verification:
        raise ApprovedSandboxUnavailable(
            "Codex Sandbox live verification cannot be disabled by local configuration"
        )
    inspection = codex_sandbox_live_verification_status(settings, backend)
    evidence = inspection.get("evidence")
    if inspection.get("status") != "verified" or not isinstance(evidence, dict):
        status = inspection.get("status", "unavailable")
        reason = inspection.get("stale_reason") or inspection.get("failure_reason")
        details = f"status={status}"
        if isinstance(reason, str) and reason:
            details += f"; reason={reason}"
        raise ApprovedSandboxUnavailable(
            "Codex Sandbox live verification is missing, failed, or stale for this backend "
            f"({details})"
        )
    return evidence


@contextmanager
def hold_codex_sandbox_backend(
    backend: CodexSandboxBackend,
) -> Iterator[CodexSandboxBackend]:
    """Deny replacement/writes while the verified launcher is probed and executed."""
    if os.name != "nt":
        raise ApprovedSandboxUnavailable("Approved Sandbox requires native Windows")
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
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    invalid_handle = wintypes.HANDLE(-1).value
    handles: list[wintypes.HANDLE] = []
    try:
        identities: list[tuple[Path, Any]] = [
            (Path(backend.executable), backend),
            *((Path(helper.executable), helper) for helper in backend.helpers),
        ]
        for path, _expected in identities:
            handle = kernel32.CreateFileW(
                str(path),
                0x80000000,  # GENERIC_READ
                0x00000001,  # FILE_SHARE_READ only; deny replacement and writes
                None,
                3,  # OPEN_EXISTING
                0x00000080,  # FILE_ATTRIBUTE_NORMAL
                None,
            )
            if handle in (None, invalid_handle):
                raise ApprovedSandboxUnavailable(
                    f"could not lock Codex sandbox dependency {path.name}: "
                    f"WinError {get_last_error()}"
                )
            handles.append(handle)
        for path, expected in identities:
            actual = _binary_identity(path)
            for key, value in actual.items():
                if value != getattr(expected, key):
                    raise ApprovedSandboxUnavailable(
                        f"Codex sandbox dependency changed before execution: "
                        f"{path.name}:{key}"
                    )
        yield backend
    finally:
        for handle in reversed(handles):
            kernel32.CloseHandle(handle)


def probe_codex_version(backend: CodexSandboxBackend, settings: Settings) -> str:
    environment = build_command_environment(
        os.environ,
        extra_names=settings.child_environment_allowlist,
        nonce=uuid.uuid4().hex,
    )
    assert settings.sandbox_scratch_dir is not None
    sanitize_executable_search_path(
        environment,
        forbidden_roots=(
            settings.workspace_root,
            settings.data_dir,
            settings.sandbox_scratch_dir,
        ),
        prepend=(Path(backend.executable).parent,),
    )
    try:
        result = subprocess.run(
            [backend.executable, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
            shell=False,
            cwd=Path(backend.executable).parent,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ApprovedSandboxUnavailable(
            f"Codex sandbox launcher version probe failed: {error}"
        ) from error
    match = _CODEX_VERSION.match(result.stdout.strip())
    if result.returncode != 0 or match is None:
        raise ApprovedSandboxUnavailable(
            "Codex sandbox launcher did not return a recognized version"
        )
    return match.group(1)


def build_codex_sandbox_argv(
    backend: CodexSandboxBackend,
    *,
    settings: Settings,
    command: list[str],
    cwd: str,
    writable_roots: Sequence[Path] = (),
) -> list[str]:
    if not command:
        raise ValueError("Approved Sandbox command cannot be empty")
    sandbox_state = codex_sandbox_state(
        settings,
        command=command,
        cwd=Path(cwd),
        writable_roots=writable_roots,
    )
    return [
        backend.executable,
        "sandbox",
        "-c",
        f'windows.sandbox="{backend.windows_mode}"',
        "--sandbox-state-json",
        canonical_json(sandbox_state),
        "--sandbox-state-disable-network",
        "--",
        *command,
    ]


def codex_sandbox_state(
    settings: Settings,
    *,
    command: Sequence[str],
    cwd: Path,
    writable_roots: Sequence[Path] = (),
) -> dict[str, Any]:
    """Build the exact filesystem/network capability passed to the Codex backend."""
    if not command:
        raise ValueError("Approved Sandbox command cannot be empty")
    cwd = cwd.resolve(strict=True)
    workspace = settings.workspace_root.resolve(strict=True)
    data_dir = settings.data_dir.resolve(strict=True)
    assert settings.sandbox_scratch_dir is not None
    scratch = settings.sandbox_scratch_dir.resolve(strict=True)
    protected_roots = (workspace, data_dir, scratch)
    entries: list[dict[str, Any]] = [
        _special_filesystem_entry("minimal", "read"),
        _path_filesystem_entry(workspace, "deny"),
        _path_filesystem_entry(data_dir, "deny"),
    ]
    readable_roots = [
        Path(command[0]).resolve(strict=True).parent,
        *(path.resolve(strict=True) for path in settings.sandbox_dependency_readable_paths),
    ]

    def overlaps_protected(path: Path) -> bool:
        for protected in protected_roots:
            try:
                path.relative_to(protected)
                return True
            except ValueError:
                pass
            try:
                protected.relative_to(path)
                return True
            except ValueError:
                pass
        return False

    for path in readable_roots:
        if overlaps_protected(path):
            raise ApprovedSandboxUnavailable(
                f"Sandbox readable dependency overlaps a protected root: {path}"
            )
    seen: set[str] = set()
    for path in [*readable_roots, *(root.resolve(strict=True) for root in writable_roots)]:
        folded = os.path.normcase(str(path))
        if folded in seen:
            continue
        seen.add(folded)
        entries.append(
            _path_filesystem_entry(
                path,
                "write"
                if any(path == root.resolve(strict=True) for root in writable_roots)
                else "read",
            )
        )
    return {
        "permissionProfile": {
            "type": "managed",
            "file_system": {
                "type": "restricted",
                "entries": entries,
                "glob_scan_max_depth": _SANDBOX_STATE_GLOB_SCAN_MAX_DEPTH,
            },
            "network": "restricted",
        },
        "codexLinuxSandboxExe": None,
        "sandboxCwd": cwd.as_uri(),
        "useLegacyLandlock": False,
    }


def launch_codex_sandbox(
    backend: CodexSandboxBackend,
    *,
    settings: Settings,
    command: list[str],
    cwd: Path,
    writable_roots: Sequence[Path],
    environment: dict[str, str],
    stdin: Any,
    stdout: Any,
    stderr: Any,
    limits: WindowsJobLimits | None = None,
) -> tuple[subprocess.Popen[Any], WindowsSandboxJob, list[str]]:
    """Launch suspended, attach the whole route to a bounded Job, then resume."""
    argv = build_codex_sandbox_argv(
        backend,
        settings=settings,
        command=command,
        cwd=str(cwd),
        writable_roots=writable_roots,
    )
    job = WindowsSandboxJob(
        limits
        or WindowsJobLimits(
            max_processes=backend.max_processes,
            max_memory_bytes=backend.max_memory_bytes,
        )
    )
    try:
        process = job.popen(
            argv,
            cwd=Path(backend.executable).parent,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0),
            env=environment,
        )
    except Exception:
        job.close()
        raise
    return process, job, argv


def _require_brokered_process_creation_denied(
    backend: CodexSandboxBackend,
    *,
    settings: Settings,
) -> None:
    """Recheck the WMI Job-escape class immediately before an approved payload launch."""

    assert settings.sandbox_scratch_dir is not None
    root = (
        settings.sandbox_scratch_dir
        / "brokered-process-preflight"
        / uuid.uuid4().hex
    )
    root.mkdir(parents=True, exist_ok=False)
    environment = build_command_environment(
        os.environ,
        extra_names=settings.child_environment_allowlist,
        nonce=uuid.uuid4().hex,
    )
    sanitize_executable_search_path(
        environment,
        forbidden_roots=(
            settings.workspace_root,
            settings.data_dir,
            settings.sandbox_scratch_dir,
        ),
        prepend=(Path(backend.executable).parent,),
    )
    process: subprocess.Popen[Any] | None = None
    job: WindowsSandboxJob | None = None
    try:
        command = brokered_process_probe_command(uuid.uuid4().hex)
        process, job, _argv = launch_codex_sandbox(
            backend,
            settings=settings,
            command=command,
            cwd=root,
            writable_roots=(root,),
            environment=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout, _stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired as error:
            raise ApprovedSandboxUnavailable(
                "Codex Sandbox brokered-process preflight timed out"
            ) from error
        if not job.wait_empty(timeout=10):
            raise ApprovedSandboxUnavailable(
                "Codex Sandbox brokered-process preflight did not drain"
            )
        value, reason = classify_brokered_process_probe(process.returncode, stdout)
        if value is not True:
            raise ApprovedSandboxUnavailable(
                f"Codex Sandbox brokered-process boundary is not verified: {reason}"
            )
    except ApprovedSandboxUnavailable:
        raise
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise ApprovedSandboxUnavailable(
            "Codex Sandbox brokered-process preflight could not be verified"
        ) from error
    finally:
        if job is not None:
            job.terminate()
            job.wait_empty(timeout=10)
            job.close()
        shutil.rmtree(root, ignore_errors=True)


def guard_and_launch_codex_sandbox(
    backend: CodexSandboxBackend,
    *,
    settings: Settings,
    command: list[str],
    cwd: Path,
    writable_roots: Sequence[Path],
    environment: dict[str, str],
    stdin: Any,
    stdout: Any,
    stderr: Any,
    limits: WindowsJobLimits | None = None,
    on_guard_verified: Callable[[dict[str, object]], None] | None = None,
    expected_live_evidence: dict[str, Any] | None = None,
) -> tuple[
    subprocess.Popen[Any], WindowsSandboxJob, list[str], dict[str, object]
]:
    """Verify the fixed WFP Guard immediately before starting the Sandbox route."""

    from .wfp_guard_runtime import ensure_runtime_codex_loopback_guard

    if expected_live_evidence is not None:
        current_evidence = require_codex_sandbox_live_verification(settings, backend)
        if current_evidence != expected_live_evidence:
            raise ApprovedSandboxUnavailable(
                "Codex Sandbox live marker changed before WFP verification; "
                "run verify-codex-sandbox explicitly"
            )
        try:
            account_identity = resolve_sandbox_account_identity().as_dict()
        except WfpGuardError as error:
            raise ApprovedSandboxUnavailable(
                "Codex Sandbox account identity could not be revalidated; "
                "run verify-codex-sandbox explicitly"
            ) from error
        if account_identity != current_evidence.get("sandbox_account_identity"):
            raise ApprovedSandboxUnavailable(
                "Codex Sandbox account identity changed after live verification; "
                "run verify-codex-sandbox explicitly"
            )
    try:
        verification = ensure_runtime_codex_loopback_guard()
    except WfpGuardStateMismatchError as error:
        raise ApprovedSandboxUnavailable(
            "Codex Sandbox WFP state conflicts with the verified marker; "
            "run verify-codex-sandbox explicitly"
        ) from error
    except (OSError, RuntimeError, WfpGuardError) as error:
        raise ApprovedSandboxUnavailable(
            "Codex Sandbox WFP Guard verification failed; automatic elevation was not "
            f"attempted. Run verify-codex-sandbox explicitly: {error}"
        ) from error
    guard_payload = verification.as_dict()
    if expected_live_evidence is not None:
        binding = guard_verification_binding(verification)
        if (
            binding != expected_live_evidence.get("wfp_guard_binding")
            or guard_verification_binding_digest(verification)
            != expected_live_evidence.get("wfp_guard_binding_digest")
        ):
            raise ApprovedSandboxUnavailable(
                "Codex Sandbox WFP read-back differs from the live marker; "
                "run verify-codex-sandbox explicitly"
            )
    if on_guard_verified is not None:
        on_guard_verified(guard_payload)
    if expected_live_evidence is not None:
        _require_brokered_process_creation_denied(backend, settings=settings)
    process, job, argv = launch_codex_sandbox(
        backend,
        settings=settings,
        command=command,
        cwd=cwd,
        writable_roots=writable_roots,
        environment=environment,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        limits=limits,
    )
    return process, job, argv, guard_payload


def _path_filesystem_entry(path: Path, access: str) -> dict[str, Any]:
    return {"path": {"type": "path", "path": str(path)}, "access": access}


def _special_filesystem_entry(value: str, access: str) -> dict[str, Any]:
    return {
        "path": {"type": "special", "value": {"kind": value}},
        "access": access,
    }


def _glob_filesystem_entry(pattern: str, access: str) -> dict[str, Any]:
    return {
        "path": {"type": "glob_pattern", "pattern": pattern},
        "access": access,
    }


def _protected_read_entries(settings: Settings, workspace: Path) -> list[dict[str, Any]]:
    prefix = workspace.as_posix().rstrip("/")
    patterns: set[str] = set()
    for name in settings.blocked_file_names:
        patterns.add(f"{prefix}/{name}")
        patterns.add(f"{prefix}/**/{name}")
    patterns.add(f"{prefix}/.env.*")
    patterns.add(f"{prefix}/**/.env.*")
    for name in settings.read_denied_directories:
        patterns.add(f"{prefix}/{name}")
        patterns.add(f"{prefix}/**/{name}")
        patterns.add(f"{prefix}/**/{name}/**")
    return [_glob_filesystem_entry(pattern, "deny") for pattern in sorted(patterns)]


def codex_sandbox_effective_policy(*, workspace_write: bool) -> dict[str, Any]:
    return {
        "sandbox_backend": "openai-codex-windows-sandbox",
        "filesystem_policy": {
            "source_workspace": "denied; execution uses only the approved snapshot/run projection",
            "execution_copy": "read-write" if workspace_write else "read-write disposable scratch",
            "outside_workspace_read": "requested deny except minimal Windows/toolchain and explicit dependencies",
            "outside_workspace_write": "denied except the per-operation scratch root",
            "protected_paths": "requested Codex elevated deny-read policy; live evidence required",
        },
        "network_policy": {
            "internet": "deny",
            "lan": "deny",
            "loopback": "deny",
            "enforcement": (
                "Codex network restriction plus read-back-verified static non-persistent "
                "direct WFP loopback block"
            ),
            "loopback_guard": GUARD_VERSION,
            "loopback_guard_policy_generation": GUARD_POLICY_GENERATION,
        },
        "descendant_policy": "filesystem/network token plus outer Job Object inherited by descendants",
        "resource_policy": (
            "OS Job Object active-process and process-tree committed-memory limits plus "
            "immediate Win32_Process.Create denial preflight"
        ),
        "actual_execution_boundary": (
            "live-verified Codex boundary plus WLMCP Job Object and brokered-process preflight"
        ),
        "external_state_changes": "device, service, and IPC effects are command-dependent and may not be rollbackable",
        "rollback": "workspace checkpoints only; external effects are not undone",
    }


def _resolve_codex_helper(
    settings: Settings, launcher: Path, name: str
) -> CodexSandboxHelper:
    candidate = Path(
        ensure_external_tool_executable(
            str(launcher.parent / name),
            workspace_root=settings.workspace_root,
            data_dir=settings.data_dir,
            sandbox_scratch_dir=settings.sandbox_scratch_dir,
        )
    ).resolve(strict=True)
    if candidate.parent != launcher.parent:
        raise ApprovedSandboxUnavailable(
            f"Codex sandbox helper escaped the bound install directory: {name}"
        )
    identity = _binary_identity(candidate)
    return CodexSandboxHelper(name=name, **identity)


def _binary_identity(path: Path) -> dict[str, Any]:
    authenticode = _openai_authenticode_identity(path)
    captured = capture_executable_identity(
        path,
        provenance="openai-authenticode-signed-codex-dependency",
    )
    return {
        "executable": str(path),
        "executable_sha256": captured["sha256"],
        "executable_size": captured["size"],
        "executable_mtime_ns": captured["mtime_ns"],
        "signature_status": str(authenticode["status"]),
        "signer_subject": str(authenticode["subject"]),
        "signer_thumbprint": str(authenticode["thumbprint"]),
        "stable_file_identity": captured["stable_file_identity"],
    }


def _openai_authenticode_identity(path: Path) -> dict[str, str]:
    windows_directory = _system_windows_directory()
    powershell = (
        windows_directory
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    if not powershell.is_file():
        raise ApprovedSandboxUnavailable(
            "the trusted Windows Authenticode verifier is unavailable"
        )
    command = (
        "$s=Get-AuthenticodeSignature -LiteralPath $env:WLMCP_AUTH_PATH;"
        "[pscustomobject]@{Status=[string]$s.Status;"
        "Subject=[string]$s.SignerCertificate.Subject;"
        "Thumbprint=[string]$s.SignerCertificate.Thumbprint} | ConvertTo-Json -Compress"
    )
    environment = {
        "SystemRoot": str(windows_directory),
        "WINDIR": str(windows_directory),
        "WLMCP_AUTH_PATH": str(path),
    }
    for name in ("TEMP", "TMP"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    try:
        result = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8-sig",
            errors="replace",
            timeout=15,
            check=False,
            shell=False,
            env=environment,
        )
        payload = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise ApprovedSandboxUnavailable(
            f"Codex launcher Authenticode verification failed: {type(error).__name__}"
        ) from error
    status = str(payload.get("Status") or "")
    subject = str(payload.get("Subject") or "")
    thumbprint = str(payload.get("Thumbprint") or "").upper()
    if (
        result.returncode != 0
        or status != "Valid"
        or not any(name in subject for name in _OPENAI_AUTHENTICODE_NAMES)
        or not re.fullmatch(r"[0-9A-F]{40,64}", thumbprint)
    ):
        raise ApprovedSandboxUnavailable(
            "Codex launcher is not validly Authenticode-signed by OpenAI OpCo, LLC"
        )
    return {"status": status, "subject": subject, "thumbprint": thumbprint}


def _system_windows_directory() -> Path:
    if os.name != "nt":
        raise ApprovedSandboxUnavailable("Windows system directory is unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel32.GetWindowsDirectoryW.restype = wintypes.UINT
    buffer = create_unicode_buffer(32768)
    length = kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise ApprovedSandboxUnavailable(
            f"could not resolve the Windows directory: WinError {get_last_error()}"
        )
    return Path(buffer.value).resolve(strict=True)
