from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from ctypes import create_unicode_buffer, get_last_error, wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .child_env import build_command_environment, sanitize_executable_search_path
from .config import Settings
from .tool_safety import ensure_external_tool_executable
from .util import canonical_json, sha256_text
from .wfp_guard import GUARD_POLICY_GENERATION, GUARD_VERSION
from .windows_job import WindowsJobLimits, WindowsSandboxJob
from .windows_system import physical_filesystem_path

_CODEX_VERSION = re.compile(r"^codex-cli\s+([^\s]+)")
_OPENAI_AUTHENTICODE_NAMES = ('O="OpenAI OpCo, LLC"', 'CN="OpenAI OpCo, LLC"')
_SANDBOX_HELPERS = (
    "codex-command-runner.exe",
    "codex-windows-sandbox-setup.exe",
)
_WLMCP_ISOLATION_POLICY_VERSION = 1
_SANDBOX_STATE_POLICY_VERSION = 1
_SANDBOX_STATE_GLOB_SCAN_MAX_DEPTH = 64
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
_ACCEPTED_RESIDUAL_RISK_PROPERTIES = frozenset(
    {"protected_information_read", "lan"}
)
_MANDATORY_ROUTE_PROPERTIES = (
    "filesystem_read",
    "filesystem_write",
    "internet",
    "loopback",
    "termination",
    "resource_bound",
)
_MANDATORY_DESCENDANT_CHECKS = (
    "child_source_workspace_write_denied",
    "child_outside_user_read_denied",
    "child_control_plane_read_denied",
    "child_control_plane_write_denied",
    "child_internet_denied",
    "child_loopback_denied",
    "grandchild_source_workspace_write_denied",
    "grandchild_outside_user_read_denied",
    "grandchild_control_plane_read_denied",
    "grandchild_control_plane_write_denied",
    "grandchild_internet_denied",
    "grandchild_loopback_denied",
)
_ALLOWED_PROPERTY_STATUSES = frozenset({"verified", "failed", "unverified"})


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
            "version": "resolved_after_approval",
            "windows_mode": self.windows_mode,
            "permission_profile": self.permission_profile,
            "provenance": self.provenance,
            "signature_status": self.signature_status,
            "signer_subject": self.signer_subject,
            "signer_thumbprint": self.signer_thumbprint,
            "helper_dependencies": [helper.as_dict() for helper in self.helpers],
            "wlmcp_isolation_policy_version": self.isolation_policy_version,
            "max_processes": self.max_processes,
            "max_memory_bytes": self.max_memory_bytes,
            "model_api_usage": "none; codex sandbox does not start an agent",
            "authentication_required": False,
            "distribution_mode": "installed_codex_dependency",
        }


def resolve_codex_sandbox_backend(settings: Settings) -> CodexSandboxBackend:
    if not settings.approved_sandbox_enabled:
        raise ApprovedSandboxUnavailable("Approved Sandbox is disabled by local policy")
    if os.name != "nt":
        raise ApprovedSandboxUnavailable("Approved Sandbox requires native Windows")

    candidates: list[tuple[Path, str]] = []
    if settings.approved_sandbox_codex_path is not None:
        candidates.append(
            (settings.approved_sandbox_codex_path, "explicit-trusted-local-config")
        )
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        cache_root = Path(local_app_data) / "OpenAI" / "Codex" / "bin"
        if cache_root.is_dir():
            candidates.extend(
                (item, "openai-codex-desktop-install-root")
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
            ),
            (
                Path.home()
                / ".codex"
                / "packages"
                / "standalone"
                / "current"
                / "codex.exe",
                "codex-managed-standalone-root",
            ),
        ]
    )

    errors: list[str] = []
    seen: set[str] = set()
    for candidate, provenance in candidates:
        folded = os.path.normcase(str(candidate))
        if folded in seen:
            continue
        seen.add(folded)
        try:
            executable = Path(
                ensure_external_tool_executable(
                    str(candidate),
                    workspace_root=settings.workspace_root,
                    data_dir=settings.data_dir,
                    sandbox_scratch_dir=settings.sandbox_scratch_dir,
                )
            ).resolve(strict=True)
            stat = executable.stat()
            authenticode = _openai_authenticode_identity(executable)
            helpers = tuple(
                _resolve_codex_helper(settings, executable, name)
                for name in _SANDBOX_HELPERS
            )
            return CodexSandboxBackend(
                executable=str(executable),
                executable_sha256=_sha256_file(executable),
                executable_size=stat.st_size,
                executable_mtime_ns=stat.st_mtime_ns,
                windows_mode=settings.approved_sandbox_windows_mode,
                permission_profile=settings.approved_sandbox_permission_profile,
                provenance=provenance,
                signature_status=str(authenticode["status"]),
                signer_subject=str(authenticode["subject"]),
                signer_thumbprint=str(authenticode["thumbprint"]),
                helpers=helpers,
                max_processes=settings.max_sandbox_processes,
                max_memory_bytes=settings.max_sandbox_memory_bytes,
            )
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
        "helper_dependencies",
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
        "version": 1,
        "backend": backend.as_dict(),
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
        "max_sandbox_scratch_bytes": settings.max_sandbox_scratch_bytes,
        "wlmcp_isolation_policy_version": backend.isolation_policy_version,
        "process_count_limit": backend.max_processes,
        "process_tree_memory_limit_bytes": backend.max_memory_bytes,
        "configured_process_count_limit": settings.max_sandbox_processes,
        "configured_process_tree_memory_limit_bytes": settings.max_sandbox_memory_bytes,
        "sandbox_state_policy": {
            "version": _SANDBOX_STATE_POLICY_VERSION,
            "filesystem_policy_generation": 1,
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

    descendant = properties.get("descendant_containment")
    if not isinstance(descendant, dict):
        return False
    if descendant.get("status") == "verified":
        return True

    checks = evidence.get("checks")
    if not isinstance(checks, dict):
        return False
    return all(checks.get(name) is True for name in _MANDATORY_DESCENDANT_CHECKS)


def require_codex_sandbox_live_verification(
    settings: Settings, backend: CodexSandboxBackend
) -> dict[str, Any]:
    """Bind execution to successful live checks of this exact installed backend."""
    if not settings.approved_sandbox_require_live_verification:
        raise ApprovedSandboxUnavailable(
            "Codex Sandbox live verification cannot be disabled by local configuration"
        )
    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    try:
        evidence = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ApprovedSandboxUnavailable(
            "Codex Sandbox has not completed Windows live verification for this profile"
        ) from error
    try:
        expected_isolation_digest = isolation_context_digest(settings, backend)
    except (OSError, PermissionError, RuntimeError, ValueError) as error:
        raise ApprovedSandboxUnavailable(
            "Codex Sandbox isolation context could not be resolved"
        ) from error
    if (
        evidence.get("version") != 3
        or evidence.get("backend_digest")
        != sha256_text(canonical_json(backend.as_dict()))
        or evidence.get("isolation_context_digest") != expected_isolation_digest
        or not sandbox_live_verification_route_eligible(evidence)
    ):
        raise ApprovedSandboxUnavailable(
            "Codex Sandbox live verification is missing, failed, or stale for this backend"
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
    entries: list[dict[str, Any]] = [
        _special_filesystem_entry("minimal", "read"),
        _path_filesystem_entry(workspace, "read"),
    ]
    readable_roots = [
        Path(command[0]).resolve(strict=True).parent,
        *(path.resolve(strict=True) for path in settings.sandbox_dependency_readable_paths),
    ]
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
    entries.extend(_protected_read_entries(settings, workspace))
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
) -> tuple[
    subprocess.Popen[Any], WindowsSandboxJob, list[str], dict[str, object]
]:
    """Verify the fixed WFP Guard immediately before starting the Sandbox route."""

    from .wfp_guard import WfpGuardError
    from .wfp_guard_runtime import ensure_runtime_codex_loopback_guard

    try:
        verification = ensure_runtime_codex_loopback_guard()
    except (OSError, RuntimeError, WfpGuardError) as error:
        raise ApprovedSandboxUnavailable(
            f"Codex Sandbox WFP Guard verification failed: {error}"
        ) from error
    guard_payload = verification.as_dict()
    if on_guard_verified is not None:
        on_guard_verified(guard_payload)
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
            "source_workspace": "requested read-only with protected-path deny-read rules",
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
        "resource_policy": "OS Job Object active-process and process-tree committed-memory limits",
        "actual_execution_boundary": "live-verified Codex boundary plus WLMCP Job Object",
        "external_state_changes": "device, service, and IPC effects are command-dependent and may not be rollbackable",
        "rollback": "workspace checkpoints only; external effects are not undone",
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    stat = path.stat()
    authenticode = _openai_authenticode_identity(path)
    return {
        "executable": str(path),
        "executable_sha256": _sha256_file(path),
        "executable_size": stat.st_size,
        "executable_mtime_ns": stat.st_mtime_ns,
        "signature_status": str(authenticode["status"]),
        "signer_subject": str(authenticode["subject"]),
        "signer_thumbprint": str(authenticode["thumbprint"]),
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
