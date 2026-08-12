from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import create_unicode_buffer, get_last_error, wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .child_env import build_command_environment, sanitize_executable_search_path
from .config import Settings
from .tool_safety import ensure_external_tool_executable
from .util import canonical_json, sha256_text

_CODEX_VERSION = re.compile(r"^codex-cli\s+([^\s]+)")
_OPENAI_AUTHENTICODE_NAMES = ('O="OpenAI OpCo, LLC"', 'CN="OpenAI OpCo, LLC"')
_SANDBOX_HELPERS = (
    "codex-command-runner.exe",
    "codex-windows-sandbox-setup.exe",
)
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
    ):
        if actual.get(key) != expected.get(key):
            raise ApprovedSandboxUnavailable(
                f"Approved Sandbox backend changed after approval request: {key}"
            )
    return backend


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
    properties = evidence.get("properties")
    if (
        evidence.get("version") != 2
        or evidence.get("passed") is not True
        or evidence.get("backend_digest")
        != sha256_text(canonical_json(backend.as_dict()))
        or not isinstance(properties, dict)
        or any(
            not isinstance(properties.get(name), dict)
            or properties[name].get("status") != "verified"
            for name in SANDBOX_SECURITY_PROPERTIES
        )
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
    command: list[str],
    cwd: str,
) -> list[str]:
    if not command:
        raise ValueError("Approved Sandbox command cannot be empty")
    return [
        backend.executable,
        "sandbox",
        "-c",
        f'windows.sandbox="{backend.windows_mode}"',
        "-P",
        backend.permission_profile,
        "-C",
        cwd,
        "--",
        *command,
    ]


def codex_sandbox_effective_policy(*, workspace_write: bool) -> dict[str, Any]:
    return {
        "sandbox_backend": "openai-codex-windows-sandbox",
        "filesystem_policy": {
            "workspace": "read-write" if workspace_write else "backend profile may still allow write",
            "outside_workspace_read": "broad Windows platform/user-readable scope",
            "outside_workspace_write": "denied by Codex :workspace profile",
            "protected_paths": "MCP validation and checkpoint scope remain narrower than backend read scope",
        },
        "network_policy": {
            "internet": "deny",
            "lan": "deny",
            "loopback": "backend-managed; not represented as a per-port guarantee",
            "enforcement": "Codex elevated sandbox firewall/restricted-token policy",
        },
        "descendant_policy": "children remain under the Codex sandbox command runner/job",
        "actual_execution_boundary": "dedicated lower-privilege Codex sandbox user plus restricted token",
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
