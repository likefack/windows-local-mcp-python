from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
from ctypes import wintypes
from pathlib import Path
from typing import BinaryIO

from .config import Settings

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
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


class AppContainerProcess:
    """Small Popen-compatible wrapper for an AppContainer root process."""

    def __init__(
        self,
        *,
        pid: int,
        process_handle: int,
        job_handle: int,
        stdout: BinaryIO,
        stderr: BinaryIO,
    ) -> None:
        self.pid = pid
        self._process_handle = process_handle
        self._job_handle = job_handle
        self.stdout = stdout
        self.stderr = stderr
        self.returncode: int | None = None

    def wait(self, timeout: float | None = None) -> int:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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
        if self._job_handle:
            if not kernel32.TerminateJobObject(self._job_handle, 1):
                raise ctypes.WinError(ctypes.get_last_error())
            self._close_job()
        elif not kernel32.TerminateProcess(self._process_handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def _close_job(self) -> None:
        if self._job_handle:
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(self._job_handle)
            self._job_handle = 0

    def close(self) -> None:
        self._close_job()
        if self._process_handle:
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(self._process_handle)
            self._process_handle = 0


def appcontainer_profile_name(
    settings: Settings, program_key: str, *, workspace_write: bool = False
) -> str:
    if program_key == "adb":
        suffix = "AdbLoopback"
    elif workspace_write:
        suffix = "OfflineStagedWrite"
    elif program_key == "git":
        suffix = "OfflineWorkspaceRead"
    else:
        suffix = "OfflineStagedRead"
    workspace_id = hashlib.sha256(
        os.path.normcase(str(settings.workspace_root)).encode("utf-8")
    ).hexdigest()[:12]
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
    for key, program_key, workspace_write in profiles:
        name = appcontainer_profile_name(
            settings, program_key, workspace_write=workspace_write
        )
        sid_pointer = _create_or_derive_profile(name)
        try:
            sid = _sid_to_string(sid_pointer)
        finally:
            ctypes.WinDLL("advapi32", use_last_error=True).FreeSid(
                ctypes.c_void_p(sid_pointer)
            )
        sids[key] = sid
        if program_key == "git":
            _grant_appcontainer_access(settings.workspace_root, sid, "(OI)(CI)RX")
            _apply_workspace_denies(settings, sid)
        else:
            _remove_appcontainer_access(settings.workspace_root, sid)
        for path in settings.safe_network_readable_paths:
            _grant_appcontainer_access(path, sid, "(OI)(CI)RX")
    loopback = subprocess.run(
        [
            "CheckNetIsolation.exe",
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
    return {
        "mode": "appcontainer",
        "profiles": sids,
        "workspace": str(settings.workspace_root),
        "readable_paths": [str(path) for path in settings.safe_network_readable_paths],
        "adb_loopback_exemption": True,
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
) -> AppContainerProcess:
    if os.name != "nt":
        raise OSError("required AppContainer isolation is unavailable on this OS")
    profile = appcontainer_profile_name(
        settings, program_key, workspace_write=workspace_write
    )
    sid = _derive_profile(profile)
    try:
        if program_key == "git":
            _apply_workspace_denies(settings, _sid_to_string(sid))
        resolved_cwd = Path(cwd).resolve(strict=True)
        outputs_root = (settings.data_dir / "outputs").resolve(strict=True)
        try:
            resolved_cwd.relative_to(outputs_root)
        except ValueError:
            pass
        else:
            sid_text = _sid_to_string(sid)
            _grant_appcontainer_access(resolved_cwd, sid_text, "(OI)(CI)M")
            runtime_directory = next(
                (
                    parent
                    for parent in (resolved_cwd, *resolved_cwd.parents)
                    if parent.parent == outputs_root and parent.name.endswith("-runtime")
                ),
                None,
            )
            if runtime_directory is not None:
                operation_id = runtime_directory.name.removesuffix("-runtime")
                staging = settings.data_dir / "approval-staging" / operation_id
                if staging.exists():
                    _grant_appcontainer_access(staging, sid_text, "(OI)(CI)RX")
        return _create_process(
            sid=sid,
            executable=executable,
            args=args,
            cwd=cwd,
            environment=environment,
            creation_flags=creation_flags,
        )
    finally:
        ctypes.WinDLL("advapi32", use_last_error=True).FreeSid(ctypes.c_void_p(sid))


def _create_process(
    *,
    sid: int,
    executable: str,
    args: list[str],
    cwd: str,
    environment: dict[str, str],
    creation_flags: int,
) -> AppContainerProcess:
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    read_out, write_out = wintypes.HANDLE(), wintypes.HANDLE()
    read_err, write_err = wintypes.HANDLE(), wintypes.HANDLE()
    if not kernel32.CreatePipe(ctypes.byref(read_out), ctypes.byref(write_out), None, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel32.CreatePipe(ctypes.byref(read_err), ctypes.byref(write_err), None, 0):
        kernel32.CloseHandle(read_out)
        kernel32.CloseHandle(write_out)
        raise ctypes.WinError(ctypes.get_last_error())
    kernel32.SetHandleInformation(read_out, HANDLE_FLAG_INHERIT, 0)
    kernel32.SetHandleInformation(read_err, HANDLE_FLAG_INHERIT, 0)
    kernel32.SetHandleInformation(write_out, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
    kernel32.SetHandleInformation(write_err, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
    nul = kernel32.CreateFileW(
        "NUL", 0x80000000, 0x00000001 | 0x00000002, None, 3, 0, None
    )
    kernel32.SetHandleInformation(nul, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
    size = ctypes.c_size_t()
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    attributes = ctypes.create_string_buffer(size.value)
    startup = STARTUPINFOEXW()
    startup.StartupInfo.cb = ctypes.sizeof(startup)
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES
    startup.StartupInfo.hStdInput = nul
    startup.StartupInfo.hStdOutput = write_out
    startup.StartupInfo.hStdError = write_err
    startup.lpAttributeList = ctypes.cast(attributes, wintypes.LPVOID)
    process = PROCESS_INFORMATION()
    job = wintypes.HANDLE()
    transferred = False
    capabilities = SECURITY_CAPABILITIES(sid, None, 0, 0)
    try:
        if not kernel32.InitializeProcThreadAttributeList(
            startup.lpAttributeList, 1, 0, ctypes.byref(size)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
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
            raise ctypes.WinError(ctypes.get_last_error())
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
        stdout = os.fdopen(msvcrt.open_osfhandle(read_out.value, os.O_RDONLY), "rb", buffering=0)
        stderr = os.fdopen(msvcrt.open_osfhandle(read_err.value, os.O_RDONLY), "rb", buffering=0)
        read_out = wintypes.HANDLE()
        read_err = wintypes.HANDLE()
        transferred = True
        return AppContainerProcess(
            pid=int(process.dwProcessId),
            process_handle=int(process.hProcess),
            job_handle=int(job.value),
            stdout=stdout,
            stderr=stderr,
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
        if startup.lpAttributeList:
            kernel32.DeleteProcThreadAttributeList(startup.lpAttributeList)
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
    value = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid), ctypes.byref(value)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return value.value
    finally:
        kernel32.LocalFree(value)


def _grant_appcontainer_access(path: Path, sid: str, permission: str) -> None:
    resolved = path.resolve(strict=True)
    result = subprocess.run(
        ["icacls.exe", str(resolved), "/grant:r", f"*{sid}:{permission}", "/T", "/C"],
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


def _deny_appcontainer_access(path: Path, sid: str, permission: str) -> None:
    resolved = path.resolve(strict=True)
    result = subprocess.run(
        [
            "icacls.exe",
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


def _apply_workspace_denies(settings: Settings, sid: str) -> None:
    read_denied = {name.casefold() for name in settings.read_denied_directories}
    blocked = {name.casefold() for name in settings.blocked_file_names}
    for root, directories, files in os.walk(settings.workspace_root, followlinks=False):
        root_path = Path(root)
        for directory in directories:
            if directory.casefold() in read_denied:
                _deny_appcontainer_access(
                    root_path / directory, sid, "(OI)(CI)(R,W,D,DC)"
                )
        for file_name in files:
            folded = file_name.casefold()
            if folded in blocked or (
                folded.startswith(".env.") and folded != ".env.example"
            ):
                _deny_appcontainer_access(root_path / file_name, sid, "(R,W,D)")


def _remove_appcontainer_access(path: Path, sid: str) -> None:
    resolved = path.resolve(strict=True)
    result = subprocess.run(
        ["icacls.exe", str(resolved), "/remove", f"*{sid}", "/T", "/C"],
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
