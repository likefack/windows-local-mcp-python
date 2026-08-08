from __future__ import annotations

import ctypes
import hashlib
import json
import os
import subprocess
import tempfile
from ctypes import wintypes
from pathlib import Path
from typing import BinaryIO

from .config import Settings
from .windows_system import windows_system_executable

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_SUSPENDED = 0x00000004
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
ERROR_ALREADY_EXISTS_HRESULT = -2147024713
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", wintypes.LPVOID),
        ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", wintypes.LPVOID)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
    )]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _configure_kernel32(kernel32: ctypes.WinDLL) -> None:
    """Declare every Win32 boundary used by the launcher with pointer-sized handles."""
    kernel32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.CreatePipe.restype = wintypes.BOOL
    kernel32.SetHandleInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.SetHandleInformation.restype = wintypes.BOOL
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
    kernel32.InitializeProcThreadAttributeList.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    kernel32.UpdateProcThreadAttribute.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_size_t,
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    kernel32.DeleteProcThreadAttributeList.argtypes = [wintypes.LPVOID]
    kernel32.DeleteProcThreadAttributeList.restype = None
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL


class AppContainerProcess:
    """Small Popen-compatible wrapper for an AppContainer root process."""

    def __init__(
        self,
        *,
        pid: int,
        process_handle: wintypes.HANDLE,
        job_handle: wintypes.HANDLE,
        stdout: BinaryIO,
        stderr: BinaryIO,
        ephemeral_profile: str | None = None,
        cleanup_access: tuple[tuple[Path, str, bool], ...] = (),
    ) -> None:
        self.pid = pid
        self._process_handle = process_handle
        self._job_handle = job_handle
        self.stdout = stdout
        self.stderr = stderr
        self.returncode: int | None = None
        self._ephemeral_profile = ephemeral_profile
        self._cleanup_access = cleanup_access

    def wait(self, timeout: float | None = None) -> int:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _configure_kernel32(kernel32)
        milliseconds = INFINITE if timeout is None else max(0, int(timeout * 1000))
        result = kernel32.WaitForSingleObject(self._process_handle, milliseconds)
        if result != WAIT_OBJECT_0:
            if result == 0x102:
                raise subprocess.TimeoutExpired(str(self.pid), timeout)
            raise ctypes.WinError(ctypes.get_last_error())
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(self._process_handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.returncode = int(code.value)
        self._close_job()
        return self.returncode

    def terminate(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _configure_kernel32(kernel32)
        if self._job_handle:
            if not kernel32.TerminateJobObject(self._job_handle, 1):
                raise ctypes.WinError(ctypes.get_last_error())
            self._close_job()
        elif not kernel32.TerminateProcess(self._process_handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def _close_job(self) -> None:
        if self._job_handle:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            _configure_kernel32(kernel32)
            kernel32.CloseHandle(self._job_handle)
            self._job_handle = wintypes.HANDLE()

    def close(self) -> None:
        self._close_job()
        if self._process_handle:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            _configure_kernel32(kernel32)
            kernel32.CloseHandle(self._process_handle)
            self._process_handle = wintypes.HANDLE()
        cleanup_errors = _cleanup_appcontainer_security_state(
            self._cleanup_access, self._ephemeral_profile
        )
        self._cleanup_access = ()
        self._ephemeral_profile = None
        if cleanup_errors:
            raise RuntimeError(
                "ephemeral AppContainer cleanup failed: " + "; ".join(cleanup_errors[:4])
            )


def appcontainer_profile_name(
    settings: Settings,
    program_key: str,
    *,
    workspace_write: bool = False,
    operation_id: str | None = None,
) -> str:
    if program_key == "adb":
        suffix = "AdbLoopback"
    elif workspace_write:
        suffix = "OfflineStagedWrite"
    elif program_key == "git":
        suffix = "OfflineWorkspaceRead"
    else:
        suffix = "OfflineStagedRead"
    profile_policy = "\0".join(
        [
            os.path.normcase(str(settings.workspace_root)),
            *(os.path.normcase(str(path)) for path in settings.safe_network_readable_paths),
        ]
    )
    workspace_id = hashlib.sha256(profile_policy.encode("utf-8")).hexdigest()[:12]
    if operation_id and program_key not in {"git", "adb"}:
        operation_digest = hashlib.sha256(operation_id.encode()).hexdigest()[:16]
        return (
            f"{settings.safe_network_profile_prefix[:16]}.{workspace_id}."
            f"Ephemeral.{operation_digest}"
        )
    return f"{settings.safe_network_profile_prefix}.{workspace_id}.{suffix}"


def create_appcontainer_profiles(settings: Settings) -> dict[str, object]:
    """One-time local setup. Creates stable profiles and grants only configured local paths."""
    if os.name != "nt":
        raise OSError("AppContainer setup is available only on Windows")
    sids: dict[str, str] = {}
    profiles = (
        ("git_read", "git", False),
        ("staged_read", "dart", False),
        ("offline_write", "dart", True),
        ("adb", "adb", False),
    )
    previous_ledger = _load_acl_ledger(settings)
    readable_paths = {
        str(path.resolve(strict=True)) for path in settings.safe_network_readable_paths
    }
    ledger_paths = set(readable_paths)
    for granted_root in (settings.workspace_root, *settings.safe_network_readable_paths):
        ledger_paths.update(str(path) for path in _traverse_ancestors(granted_root))
    profile_rows: list[tuple[str, str, bool, str, str]] = []
    for key, program_key, workspace_write in profiles:
        name = appcontainer_profile_name(
            settings, program_key, workspace_write=workspace_write
        )
        sid_pointer = _create_or_derive_profile(name)
        try:
            sid = _sid_to_string(sid_pointer)
        finally:
            _free_sid(sid_pointer)
        sids[key] = sid
        profile_rows.append((key, program_key, workspace_write, name, sid))
    # Write-ahead intent makes every possibly applied grant discoverable after interruption.
    _write_acl_ledger(
        settings,
        _acl_write_ahead_ledger(previous_ledger, set(sids.values()), ledger_paths),
    )
    unresolved_ledger: dict[str, set[str]] = {}
    for old_sid, old_paths in previous_ledger.items():
        if old_sid in sids.values():
            continue
        for old_path in old_paths:
            if Path(old_path).exists():
                _remove_appcontainer_access(Path(old_path), old_sid)
            else:
                unresolved_ledger.setdefault(old_sid, set()).add(old_path)
    for _key, program_key, _workspace_write, _name, sid in profile_rows:
        for stale_path in previous_ledger.get(sid, []):
            if stale_path not in ledger_paths and Path(stale_path).exists():
                _remove_appcontainer_access(Path(stale_path), sid)
            elif stale_path not in ledger_paths:
                unresolved_ledger.setdefault(sid, set()).add(stale_path)
        _remove_appcontainer_access(settings.workspace_root, sid)
        if program_key == "git":
            _grant_appcontainer_traverse_ancestors(settings.workspace_root, sid)
            _grant_appcontainer_access(settings.workspace_root, sid, "(OI)(CI)RX")
            _apply_workspace_denies(settings, sid, allow_git_metadata=True)
        for path in settings.safe_network_readable_paths:
            _grant_appcontainer_traverse_ancestors(path, sid)
            _grant_appcontainer_access(path, sid, "(OI)(CI)RX")
    loopback = subprocess.run(
        [
            windows_system_executable("CheckNetIsolation.exe"),
            "LoopbackExempt",
            "-a",
            f"-p={sids['adb']}",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
        shell=False,
    )
    if loopback.returncode != 0:
        raise PermissionError(
            "failed to grant the dedicated ADB AppContainer loopback exemption: "
            + loopback.stderr.strip()
        )
    final_ledger = {sid: set(ledger_paths) for sid in sids.values()}
    for unresolved_sid, unresolved_paths in unresolved_ledger.items():
        final_ledger.setdefault(unresolved_sid, set()).update(unresolved_paths)
    _write_acl_ledger(
        settings, {sid: sorted(paths) for sid, paths in final_ledger.items()}
    )
    return {
        "mode": "appcontainer",
        "profiles": sids,
        "workspace": str(settings.workspace_root),
        "readable_paths": [str(path) for path in settings.safe_network_readable_paths],
        "adb_loopback_exemption": True,
        "adb_requested_endpoint": "127.0.0.1:5037",
        "adb_effective_loopback_capability": "general AppContainer loopback exemption",
        "internet_lan_capabilities": "not granted",
    }


def _acl_write_ahead_ledger(
    previous_ledger: dict[str, list[str]],
    current_sids: set[str],
    current_paths: set[str],
) -> dict[str, list[str]]:
    """Keep displaced identities discoverable until their ACE removal finishes."""
    return {
        sid: sorted(
            set(previous_ledger.get(sid, []))
            | (current_paths if sid in current_sids else set())
        )
        for sid in set(previous_ledger) | current_sids
    }


def launch_appcontainer_process(
    *,
    settings: Settings,
    program_key: str,
    executable: str,
    args: list[str],
    cwd: str,
    environment: dict[str, str],
    creation_flags: int,
    workspace_write: bool = False,
    operation_id: str | None = None,
) -> AppContainerProcess:
    if os.name != "nt":
        raise OSError("required AppContainer isolation is unavailable on this OS")
    if Path(executable).suffix.casefold() in {".bat", ".cmd"}:
        script_command = subprocess.list2cmdline([executable, *args])
        executable = windows_system_executable("cmd.exe")
        args = ["/d", "/s", "/c", script_command]
    profile = appcontainer_profile_name(
        settings,
        program_key,
        workspace_write=workspace_write,
        operation_id=operation_id,
    )
    ephemeral = bool(operation_id and program_key not in {"git", "adb"})
    sid = _create_or_derive_profile(profile) if ephemeral else _derive_profile(profile)
    try:
        sid_text = _sid_to_string(sid)
        cleanup_access: list[tuple[Path, str, bool]] = []
        if ephemeral:
            for readable in settings.safe_network_readable_paths:
                for ancestor in _grant_appcontainer_traverse_ancestors(readable, sid_text):
                    cleanup_access.append((ancestor, sid_text, False))
                _grant_appcontainer_access(readable, sid_text, "(OI)(CI)RX")
                cleanup_access.append((readable, sid_text, True))
        if program_key == "git":
            _apply_workspace_denies(
                settings, _sid_to_string(sid), allow_git_metadata=True
            )
        resolved_cwd = Path(cwd).resolve(strict=True)
        outputs_root = (settings.data_dir / "outputs").resolve(strict=True)
        try:
            resolved_cwd.relative_to(outputs_root)
        except ValueError:
            pass
        else:
            runtime_directory = next(
                (
                    parent
                    for parent in (resolved_cwd, *resolved_cwd.parents)
                    if parent.parent == outputs_root and parent.name.endswith("-runtime")
                ),
                None,
            )
            if runtime_directory is not None:
                if ephemeral:
                    for ancestor in _grant_appcontainer_traverse_ancestors(
                        runtime_directory, sid_text
                    ):
                        cleanup_access.append((ancestor, sid_text, False))
                _grant_appcontainer_access(runtime_directory, sid_text, "(OI)(CI)M")
                cleanup_access.append((runtime_directory, sid_text, True))
            else:
                _grant_appcontainer_access(resolved_cwd, sid_text, "(OI)(CI)M")
                cleanup_access.append((resolved_cwd, sid_text, True))
        try:
            return _create_process(
                sid=sid,
                executable=executable,
                args=args,
                cwd=cwd,
                environment=environment,
                creation_flags=creation_flags,
                ephemeral_profile=profile if ephemeral else None,
                cleanup_access=tuple(cleanup_access),
            )
        except Exception as launch_error:
            cleanup_errors = _cleanup_appcontainer_security_state(
                tuple(cleanup_access), profile if ephemeral else None
            )
            if cleanup_errors:
                raise RuntimeError(
                    f"AppContainer launch failed ({type(launch_error).__name__}: "
                    f"{launch_error}) and security-state cleanup failed: "
                    + "; ".join(cleanup_errors[:4])
                ) from launch_error
            raise
    finally:
        _free_sid(sid)


def _cleanup_appcontainer_security_state(
    cleanup_access: tuple[tuple[Path, str, bool], ...],
    ephemeral_profile: str | None,
) -> list[str]:
    cleanup_errors: list[str] = []
    for path, sid, recursive in cleanup_access:
        if path.exists():
            try:
                _remove_appcontainer_access(path, sid, recursive=recursive)
            except Exception as error:  # noqa: BLE001 - attempt every revocation
                cleanup_errors.append(f"{path}: {type(error).__name__}: {error}")
    if ephemeral_profile is not None:
        try:
            _delete_appcontainer_profile(ephemeral_profile)
        except Exception as error:  # noqa: BLE001 - report after ACL attempts
            cleanup_errors.append(
                f"{ephemeral_profile}: {type(error).__name__}: {error}"
            )
    return cleanup_errors


def _create_process(
    *,
    sid: int,
    executable: str,
    args: list[str],
    cwd: str,
    environment: dict[str, str],
    creation_flags: int,
    ephemeral_profile: str | None,
    cleanup_access: tuple[tuple[Path, str, bool], ...],
) -> AppContainerProcess:
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _configure_kernel32(kernel32)
    read_out, write_out = wintypes.HANDLE(), wintypes.HANDLE()
    read_err, write_err = wintypes.HANDLE(), wintypes.HANDLE()
    nul = wintypes.HANDLE()
    attributes: ctypes.Array | None = None
    startup = STARTUPINFOEXW()
    process = PROCESS_INFORMATION()
    job = wintypes.HANDLE()
    transferred = False
    attribute_list_initialized = False
    stdout: BinaryIO | None = None
    stderr: BinaryIO | None = None
    capabilities = SECURITY_CAPABILITIES(sid, None, 0, 0)
    try:
        if not kernel32.CreatePipe(ctypes.byref(read_out), ctypes.byref(write_out), None, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.CreatePipe(ctypes.byref(read_err), ctypes.byref(write_err), None, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        for handle, inherit in (
            (read_out, False),
            (read_err, False),
            (write_out, True),
            (write_err, True),
        ):
            if not kernel32.SetHandleInformation(
                handle,
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT if inherit else 0,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        nul = wintypes.HANDLE(
            kernel32.CreateFileW(
                "NUL", 0x80000000, 0x00000001 | 0x00000002, None, 3, 0, None
            )
        )
        if not nul or nul.value == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.SetHandleInformation(
            nul, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        size = ctypes.c_size_t()
        kernel32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
        if not size.value:
            raise ctypes.WinError(ctypes.get_last_error())
        attributes = ctypes.create_string_buffer(size.value)
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = nul
        startup.StartupInfo.hStdOutput = write_out
        startup.StartupInfo.hStdError = write_err
        startup.lpAttributeList = ctypes.cast(attributes, wintypes.LPVOID)
        if not kernel32.InitializeProcThreadAttributeList(
            startup.lpAttributeList, 2, 0, ctypes.byref(size)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        attribute_list_initialized = True
        if not kernel32.UpdateProcThreadAttribute(
            startup.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            ctypes.byref(capabilities),
            ctypes.sizeof(capabilities),
            None,
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        inherited_handles = (wintypes.HANDLE * 3)(
            nul.value, write_out.value, write_err.value
        )
        if not kernel32.UpdateProcThreadAttribute(
            startup.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            ctypes.cast(inherited_handles, wintypes.LPVOID),
            ctypes.sizeof(inherited_handles),
            None,
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        command_line = ctypes.create_unicode_buffer(
            subprocess.list2cmdline([executable, *args])
        )
        environment_block = ctypes.create_unicode_buffer(
            "\0".join(f"{key}={value}" for key, value in sorted(environment.items())) + "\0\0"
        )
        if not kernel32.CreateProcessW(
            executable,
            command_line,
            None,
            None,
            True,
            creation_flags
            | EXTENDED_STARTUPINFO_PRESENT
            | CREATE_UNICODE_ENVIRONMENT
            | CREATE_SUSPENDED,
            environment_block,
            cwd,
            ctypes.byref(startup.StartupInfo),
            ctypes.byref(process),
        ):
            winerror = ctypes.get_last_error()
            raise OSError(
                winerror,
                f"CreateProcessW failed for AppContainer executable {executable} at cwd {cwd}: "
                f"{ctypes.FormatError(winerror)}",
            )
        job = wintypes.HANDLE(kernel32.CreateJobObjectW(None, None))
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.AssignProcessToJobObject(job, process.hProcess):
            raise ctypes.WinError(ctypes.get_last_error())
        if kernel32.ResumeThread(process.hThread) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(process.hThread)
        process.hThread = wintypes.HANDLE()
        stdout_fd = msvcrt.open_osfhandle(read_out.value, os.O_RDONLY)
        read_out = wintypes.HANDLE()
        stdout = os.fdopen(stdout_fd, "rb", buffering=0)
        stderr_fd = msvcrt.open_osfhandle(read_err.value, os.O_RDONLY)
        read_err = wintypes.HANDLE()
        stderr = os.fdopen(stderr_fd, "rb", buffering=0)
        transferred = True
        return AppContainerProcess(
            pid=int(process.dwProcessId),
            process_handle=wintypes.HANDLE(process.hProcess),
            job_handle=wintypes.HANDLE(job.value),
            stdout=stdout,
            stderr=stderr,
            ephemeral_profile=ephemeral_profile,
            cleanup_access=cleanup_access,
        )
    finally:
        if process.hThread:
            kernel32.CloseHandle(process.hThread)
            process.hThread = wintypes.HANDLE()
        if process.hProcess and not transferred:
            # Ownership was not transferred to AppContainerProcess.
            kernel32.TerminateProcess(process.hProcess, 1)
            kernel32.CloseHandle(process.hProcess)
        if job and not transferred:
            kernel32.CloseHandle(job)
        if attribute_list_initialized and startup.lpAttributeList:
            kernel32.DeleteProcThreadAttributeList(startup.lpAttributeList)
        if not transferred:
            if stdout is not None:
                stdout.close()
            if stderr is not None:
                stderr.close()
        for handle in (write_out, write_err, nul, read_out, read_err):
            if getattr(handle, "value", handle):
                kernel32.CloseHandle(handle)


def _create_or_derive_profile(name: str) -> int:
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    userenv.CreateAppContainerProfile.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.POINTER(SID_AND_ATTRIBUTES),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    userenv.CreateAppContainerProfile.restype = ctypes.c_long
    sid = wintypes.LPVOID()
    result = ctypes.c_long(
        userenv.CreateAppContainerProfile(
            name, name, "Windows Local MCP Safe Tier", None, 0, ctypes.byref(sid)
        )
    ).value
    if result == 0:
        return int(sid.value)
    if result == ERROR_ALREADY_EXISTS_HRESULT:
        return _derive_profile(name)
    raise OSError(result, f"CreateAppContainerProfile failed for {name}")


def _delete_appcontainer_profile(name: str) -> None:
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
    userenv.DeleteAppContainerProfile.restype = ctypes.c_long
    result = int(userenv.DeleteAppContainerProfile(name))
    if result not in {0, -2147024894}:  # S_OK or HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
        raise OSError(result, f"DeleteAppContainerProfile failed for {name}")


def _derive_profile(name: str) -> int:
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
    sid = wintypes.LPVOID()
    result = ctypes.c_long(
        userenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(sid))
    ).value
    if result != 0 or not sid.value:
        raise OSError(
            result,
            f"AppContainer profile is not set up: {name}; run setup-network-isolation",
        )
    return int(sid.value)


def _sid_to_string(sid: int) -> str:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.LPVOID]
    kernel32.LocalFree.restype = wintypes.LPVOID
    value = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid), ctypes.byref(value)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return value.value
    finally:
        kernel32.LocalFree(value)


def _free_sid(sid: int) -> None:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.FreeSid.argtypes = [wintypes.LPVOID]
    advapi32.FreeSid.restype = wintypes.LPVOID
    result = advapi32.FreeSid(ctypes.c_void_p(sid))
    if result:
        raise ctypes.WinError(ctypes.get_last_error())


def _grant_appcontainer_access(path: Path, sid: str, permission: str) -> None:
    resolved = path.resolve(strict=True)
    result = subprocess.run(
        [
            windows_system_executable("icacls.exe"),
            str(resolved),
            "/grant:r",
            f"*{sid}:{permission}",
            "/T",
            "/C",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
        shell=False,
    )
    if result.returncode != 0:
        raise PermissionError(f"failed to grant AppContainer ACL for {resolved}")


def _traverse_ancestors(path: Path) -> list[Path]:
    resolved = path.resolve(strict=True)
    return list(resolved.parents)


def _grant_appcontainer_traverse_ancestors(path: Path, sid: str) -> list[Path]:
    ancestors = _traverse_ancestors(path)
    for ancestor in ancestors:
        permission = "(X,RA)"
        result = subprocess.run(
            [
                windows_system_executable("icacls.exe"),
                str(ancestor),
                "/grant:r",
                f"*{sid}:{permission}",
                "/C",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
            shell=False,
        )
        if result.returncode != 0:
            raise PermissionError(
                f"failed to grant AppContainer traverse access for {ancestor}"
            )
    return ancestors


def _deny_appcontainer_access(path: Path, sid: str, permission: str) -> None:
    resolved = path.resolve(strict=True)
    result = subprocess.run(
        [
            windows_system_executable("icacls.exe"),
            str(resolved),
            "/deny",
            f"*{sid}:{permission}",
            "/T",
            "/C",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
        shell=False,
    )
    if result.returncode != 0:
        raise PermissionError(f"failed to deny AppContainer access for {resolved}")


def _apply_workspace_denies(
    settings: Settings, sid: str, *, allow_git_metadata: bool = False
) -> None:
    read_denied = {name.casefold() for name in settings.read_denied_directories}
    blocked = {name.casefold() for name in settings.blocked_file_names}
    for root, directories, files in os.walk(settings.workspace_root, followlinks=False):
        root_path = Path(root)
        for directory in directories:
            if directory.casefold() in read_denied and not (
                allow_git_metadata
                and root_path == settings.workspace_root
                and directory.casefold() == ".git"
            ):
                _deny_appcontainer_access(
                    root_path / directory, sid, "(OI)(CI)(R,W,D,DC)"
                )
        for file_name in files:
            folded = file_name.casefold()
            if folded in blocked or (
                folded.startswith(".env.") and folded != ".env.example"
            ):
                _deny_appcontainer_access(root_path / file_name, sid, "(R,W,D)")


def _remove_appcontainer_access(
    path: Path, sid: str, *, recursive: bool = True
) -> None:
    resolved = path.resolve(strict=True)
    command = [
        windows_system_executable("icacls.exe"),
        str(resolved),
        "/remove",
        f"*{sid}",
    ]
    if recursive:
        command.extend(["/T", "/C"])
    else:
        command.append("/C")
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
        shell=False,
    )
    if result.returncode != 0:
        raise PermissionError(f"failed to remove stale AppContainer ACLs for {resolved}")


def _acl_ledger_path(settings: Settings) -> Path:
    return settings.data_dir / "safe-sandbox-acl-ledger.json"


def _load_acl_ledger(settings: Settings) -> dict[str, list[str]]:
    path = _acl_ledger_path(settings)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError("Safe Sandbox ACL ledger is unreadable") from error
    grants = payload.get("grants")
    if not isinstance(grants, dict):
        raise TypeError("Safe Sandbox ACL ledger has an invalid schema")
    result: dict[str, list[str]] = {}
    for sid, values in grants.items():
        if not isinstance(sid, str) or not isinstance(values, list):
            raise TypeError("Safe Sandbox ACL ledger has an invalid grant entry")
        result[sid] = [str(Path(value).resolve(strict=False)) for value in values]
    return result


def _write_acl_ledger(settings: Settings, grants: dict[str, list[str]]) -> None:
    path = _acl_ledger_path(settings)
    payload = json.dumps(
        {"version": 1, "grants": grants},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=path.parent) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            temporary = Path(output.name)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
