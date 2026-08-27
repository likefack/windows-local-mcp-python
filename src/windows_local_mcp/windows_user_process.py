from __future__ import annotations

import ctypes
import msvcrt
import os
import subprocess
from collections.abc import Callable, Mapping
from ctypes import wintypes
from pathlib import Path
from typing import Any, BinaryIO

import psutil


class WindowsUserProcessUnavailable(RuntimeError):
    """A command could not be launched with the authority-bound user token."""


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _TOKEN_ASSIGN_PRIMARY = 0x0001
    _TOKEN_DUPLICATE = 0x0002
    _TOKEN_QUERY = 0x0008
    _MAXIMUM_ALLOWED = 0x02000000
    _SECURITY_IMPERSONATION = 2
    _TOKEN_PRIMARY = 1
    _TOKEN_ELEVATION = 20
    _CREATE_SUSPENDED = 0x00000004
    _CREATE_UNICODE_ENVIRONMENT = 0x00000400
    _STARTF_USESTDHANDLES = 0x00000100
    _HANDLE_FLAG_INHERIT = 0x00000001
    _WAIT_OBJECT_0 = 0
    _WAIT_TIMEOUT = 258
    _INFINITE = 0xFFFFFFFF
    _STILL_ACTIVE = 259
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x00000080

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _STARTUPINFOW(ctypes.Structure):
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

    class _PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class _TOKEN_ELEVATION_VALUE(ctypes.Structure):
        _fields_ = [("TokenIsElevated", wintypes.DWORD)]

    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.DWORD,
    ]
    _kernel32.CreatePipe.restype = wintypes.BOOL
    _kernel32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    _kernel32.SetHandleInformation.restype = wintypes.BOOL
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateProcess.restype = wintypes.BOOL
    _kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    _kernel32.ResumeThread.restype = wintypes.DWORD
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.DuplicateTokenEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.DuplicateTokenEx.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(_STARTUPINFOW),
        ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    _advapi32.CreateProcessAsUserW.restype = wintypes.BOOL


def _winerror(action: str) -> WindowsUserProcessUnavailable:
    return WindowsUserProcessUnavailable(f"{action} failed: WinError {ctypes.get_last_error()}")


def _environment_block(environment: Mapping[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    entries = [f"{key}={value}" for key, value in environment.items()]
    entries.sort(key=str.casefold)
    return ctypes.create_unicode_buffer("\0".join(entries) + "\0\0")


def _validate_requester_identity(pid: int, expected_create_time: float) -> None:
    try:
        actual = float(psutil.Process(pid).create_time())
    except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
        raise WindowsUserProcessUnavailable("requester process identity is unavailable") from error
    if abs(actual - float(expected_create_time)) > 0.01:
        raise WindowsUserProcessUnavailable("requester PID was reused before Approved Host launch")


def _duplicate_requester_primary_token(pid: int) -> wintypes.HANDLE:
    process = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        raise _winerror("OpenProcess(Approved Host requester)")
    token = wintypes.HANDLE()
    primary = wintypes.HANDLE()
    try:
        desired = _TOKEN_ASSIGN_PRIMARY | _TOKEN_DUPLICATE | _TOKEN_QUERY
        if not _advapi32.OpenProcessToken(process, desired, ctypes.byref(token)):
            raise _winerror("OpenProcessToken(Approved Host requester)")
        elevation = _TOKEN_ELEVATION_VALUE()
        returned = wintypes.DWORD()
        if not _advapi32.GetTokenInformation(
            token,
            _TOKEN_ELEVATION,
            ctypes.byref(elevation),
            ctypes.sizeof(elevation),
            ctypes.byref(returned),
        ):
            raise _winerror("GetTokenInformation(TokenElevation)")
        if elevation.TokenIsElevated:
            raise WindowsUserProcessUnavailable(
                "Approved Host requester token became elevated before child launch"
            )
        if not _advapi32.DuplicateTokenEx(
            token,
            _MAXIMUM_ALLOWED,
            None,
            _SECURITY_IMPERSONATION,
            _TOKEN_PRIMARY,
            ctypes.byref(primary),
        ):
            raise _winerror("DuplicateTokenEx(Approved Host requester)")
        return primary
    except Exception:
        if primary:
            _kernel32.CloseHandle(primary)
        raise
    finally:
        if token:
            _kernel32.CloseHandle(token)
        _kernel32.CloseHandle(process)


def _create_output_pipe() -> tuple[wintypes.HANDLE, wintypes.HANDLE]:
    security = _SECURITY_ATTRIBUTES(
        nLength=ctypes.sizeof(_SECURITY_ATTRIBUTES),
        lpSecurityDescriptor=None,
        bInheritHandle=True,
    )
    read_handle = wintypes.HANDLE()
    write_handle = wintypes.HANDLE()
    if not _kernel32.CreatePipe(
        ctypes.byref(read_handle),
        ctypes.byref(write_handle),
        ctypes.byref(security),
        0,
    ):
        raise _winerror("CreatePipe")
    if not _kernel32.SetHandleInformation(read_handle, _HANDLE_FLAG_INHERIT, 0):
        _kernel32.CloseHandle(read_handle)
        _kernel32.CloseHandle(write_handle)
        raise _winerror("SetHandleInformation")
    return read_handle, write_handle


def _open_inheritable_nul() -> wintypes.HANDLE:
    security = _SECURITY_ATTRIBUTES(
        nLength=ctypes.sizeof(_SECURITY_ATTRIBUTES),
        lpSecurityDescriptor=None,
        bInheritHandle=True,
    )
    handle = _kernel32.CreateFileW(
        "NUL",
        _GENERIC_READ | _GENERIC_WRITE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        ctypes.byref(security),
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, invalid):
        raise _winerror("CreateFileW(NUL)")
    return handle


def _binary_reader_from_handle(handle: wintypes.HANDLE) -> BinaryIO:
    descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDONLY)
    return os.fdopen(descriptor, "rb", buffering=0)


class WindowsCreatedProcess:
    def __init__(
        self,
        *,
        process_handle: wintypes.HANDLE,
        pid: int,
        stdout: BinaryIO,
        stderr: BinaryIO,
    ) -> None:
        self._handle = process_handle
        self.pid = pid
        self.stdout = stdout
        self.stderr = stderr
        self.returncode: int | None = None
        self._closed = False

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        code = wintypes.DWORD()
        if not _kernel32.GetExitCodeProcess(self._handle, ctypes.byref(code)):
            raise _winerror("GetExitCodeProcess")
        if code.value == _STILL_ACTIVE:
            return None
        self.returncode = int(code.value)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        milliseconds = (
            _INFINITE
            if timeout is None
            else max(0, min(0xFFFFFFFE, int(timeout * 1000)))
        )
        result = _kernel32.WaitForSingleObject(self._handle, milliseconds)
        if result == _WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(["approved-host-user-process"], timeout)
        if result != _WAIT_OBJECT_0:
            raise _winerror("WaitForSingleObject")
        polled = self.poll()
        if polled is None:
            raise WindowsUserProcessUnavailable("Approved Host process signaled without exit code")
        return polled

    def terminate(self) -> None:
        if self.poll() is not None:
            return
        if not _kernel32.TerminateProcess(self._handle, 1):
            raise _winerror("TerminateProcess")

    def kill(self) -> None:
        self.terminate()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._handle:
            _kernel32.CloseHandle(self._handle)
            self._handle = wintypes.HANDLE()


def popen_as_requester_in_job(
    job: Any,
    argv: list[str],
    *,
    requester_pid: int,
    requester_create_time: float,
    cwd: str | Path,
    environment: Mapping[str, str],
    creationflags: int = 0,
    on_process_created: Callable[[], None] | None = None,
) -> WindowsCreatedProcess:
    """Create a user process suspended, bind it to the SYSTEM-owned Job, then resume."""
    if os.name != "nt":
        raise WindowsUserProcessUnavailable("Approved Host user-token launch requires native Windows")
    _validate_requester_identity(requester_pid, requester_create_time)
    primary_token = _duplicate_requester_primary_token(requester_pid)
    stdout_read = wintypes.HANDLE()
    stdout_write = wintypes.HANDLE()
    stderr_read = wintypes.HANDLE()
    stderr_write = wintypes.HANDLE()
    stdin_handle = wintypes.HANDLE()
    process_info = _PROCESS_INFORMATION()
    process_created = False
    try:
        stdout_read, stdout_write = _create_output_pipe()
        stderr_read, stderr_write = _create_output_pipe()
        stdin_handle = _open_inheritable_nul()
        startup = _STARTUPINFOW()
        startup.cb = ctypes.sizeof(startup)
        startup.lpDesktop = "winsta0\\default"
        startup.dwFlags = _STARTF_USESTDHANDLES
        startup.hStdInput = stdin_handle
        startup.hStdOutput = stdout_write
        startup.hStdError = stderr_write
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
        env_block = _environment_block(environment)
        flags = int(creationflags) | _CREATE_SUSPENDED | _CREATE_UNICODE_ENVIRONMENT
        if not _advapi32.CreateProcessAsUserW(
            primary_token,
            str(Path(argv[0]).resolve(strict=True)),
            command_line,
            None,
            None,
            True,
            flags,
            env_block,
            str(cwd),
            ctypes.byref(startup),
            ctypes.byref(process_info),
        ):
            raise _winerror("CreateProcessAsUserW")
        process_created = True
        if on_process_created is not None:
            on_process_created()
        if not job._job:
            raise WindowsUserProcessUnavailable("Approved Host Job Object is unavailable")
        if not _kernel32.AssignProcessToJobObject(job._job, process_info.hProcess):
            raise _winerror("AssignProcessToJobObject")
        job._start_watcher()
        resumed = _kernel32.ResumeThread(process_info.hThread)
        if resumed == 0xFFFFFFFF:
            raise _winerror("ResumeThread")
        _kernel32.CloseHandle(process_info.hThread)
        process_info.hThread = wintypes.HANDLE()
        _kernel32.CloseHandle(stdout_write)
        stdout_write = wintypes.HANDLE()
        _kernel32.CloseHandle(stderr_write)
        stderr_write = wintypes.HANDLE()
        _kernel32.CloseHandle(stdin_handle)
        stdin_handle = wintypes.HANDLE()
        stdout = _binary_reader_from_handle(stdout_read)
        stdout_read = wintypes.HANDLE()
        stderr = _binary_reader_from_handle(stderr_read)
        stderr_read = wintypes.HANDLE()
        owned_process_handle = process_info.hProcess
        process_info.hProcess = wintypes.HANDLE()
        return WindowsCreatedProcess(
            process_handle=owned_process_handle,
            pid=int(process_info.dwProcessId),
            stdout=stdout,
            stderr=stderr,
        )
    except Exception:
        if process_created and process_info.hProcess:
            _kernel32.TerminateProcess(process_info.hProcess, 1)
        if process_info.hThread:
            _kernel32.CloseHandle(process_info.hThread)
            process_info.hThread = wintypes.HANDLE()
        if process_info.hProcess:
            _kernel32.CloseHandle(process_info.hProcess)
            process_info.hProcess = wintypes.HANDLE()
        raise
    finally:
        for handle in (
            stdout_read,
            stdout_write,
            stderr_read,
            stderr_write,
            stdin_handle,
            primary_token,
        ):
            if handle:
                _kernel32.CloseHandle(handle)
