from __future__ import annotations

import ctypes
import os
import subprocess
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Self


class WindowsJobUnavailable(RuntimeError):
    """A required Windows Job Object boundary could not be established."""


@dataclass(frozen=True)
class WindowsJobLimits:
    max_processes: int
    max_memory_bytes: int


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
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

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _JOBOBJECT_ASSOCIATE_COMPLETION_PORT(ctypes.Structure):
        _fields_ = [
            ("CompletionKey", ctypes.c_void_p),
            ("CompletionPort", wintypes.HANDLE),
        ]

    class _THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    _kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.CreateIoCompletionPort.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.c_size_t,
        wintypes.DWORD,
    ]
    _kernel32.CreateIoCompletionPort.restype = wintypes.HANDLE
    _kernel32.GetQueuedCompletionStatus.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.DWORD,
    ]
    _kernel32.GetQueuedCompletionStatus.restype = wintypes.BOOL
    _kernel32.PostQueuedCompletionStatus.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
    ]
    _kernel32.PostQueuedCompletionStatus.restype = wintypes.BOOL
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    _kernel32.Thread32First.restype = wintypes.BOOL
    _kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    _kernel32.Thread32Next.restype = wintypes.BOOL
    _kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenThread.restype = wintypes.HANDLE
    _kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    _kernel32.ResumeThread.restype = wintypes.DWORD
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL


_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION = 7
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT = 3
_JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO = 4
_JOB_OBJECT_MSG_JOB_MEMORY_LIMIT = 10
_CREATE_SUSPENDED = 0x00000004
_TH32CS_SNAPTHREAD = 0x00000004
_THREAD_SUSPEND_RESUME = 0x0002
_WAIT_TIMEOUT = 258
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _winerror(operation: str) -> WindowsJobUnavailable:
    return WindowsJobUnavailable(f"{operation} failed: WinError {ctypes.get_last_error()}")


class WindowsSandboxJob:
    """Own an OS-enforced, kill-on-close resource boundary for one Sandbox tree."""

    def __init__(self, limits: WindowsJobLimits) -> None:
        if os.name != "nt":
            raise WindowsJobUnavailable("Windows Job Objects require native Windows")
        if limits.max_processes < 1 or limits.max_memory_bytes < 1:
            raise ValueError("Windows Job Object limits must be positive")
        self.limits = limits
        self._job = _kernel32.CreateJobObjectW(None, None)
        if not self._job:
            raise _winerror("CreateJobObjectW")
        self._completion_port = wintypes.HANDLE()
        self._closed = False
        self._violation: str | None = None
        self._violation_event = threading.Event()
        self._active_zero = threading.Event()
        self._watcher: threading.Thread | None = None
        try:
            self._configure_limits()
            self._configure_completion_port()
        except Exception:
            self.close()
            raise

    @property
    def violation(self) -> str | None:
        return self._violation

    @property
    def violation_event(self) -> threading.Event:
        return self._violation_event

    def _configure_limits(self) -> None:
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | _JOB_OBJECT_LIMIT_JOB_MEMORY
            | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        info.BasicLimitInformation.ActiveProcessLimit = self.limits.max_processes
        info.JobMemoryLimit = self.limits.max_memory_bytes
        if not _kernel32.SetInformationJobObject(
            self._job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            raise _winerror("SetInformationJobObject(limits)")

    def _configure_completion_port(self) -> None:
        invalid = wintypes.HANDLE(_INVALID_HANDLE_VALUE)
        port = _kernel32.CreateIoCompletionPort(invalid, None, 0, 1)
        if not port:
            raise _winerror("CreateIoCompletionPort")
        self._completion_port = port
        association = _JOBOBJECT_ASSOCIATE_COMPLETION_PORT(
            CompletionKey=ctypes.c_void_p(id(self)),
            CompletionPort=port,
        )
        if not _kernel32.SetInformationJobObject(
            self._job,
            _JOB_OBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION,
            ctypes.byref(association),
            ctypes.sizeof(association),
        ):
            raise _winerror("SetInformationJobObject(completion_port)")

    def popen(self, argv: list[str], **kwargs: Any) -> subprocess.Popen[Any]:
        creationflags = int(kwargs.pop("creationflags", 0)) | _CREATE_SUSPENDED
        process = subprocess.Popen(argv, creationflags=creationflags, **kwargs)
        try:
            process_handle = wintypes.HANDLE(int(process._handle))  # type: ignore[attr-defined]
            if not _kernel32.AssignProcessToJobObject(self._job, process_handle):
                raise _winerror("AssignProcessToJobObject")
            self._start_watcher()
            self._resume_initial_thread(process.pid)
            return process
        except Exception:
            self.terminate()
            try:
                process.kill()
            except OSError:
                pass
            process.wait(timeout=10)
            raise

    def _start_watcher(self) -> None:
        if self._watcher is not None:
            return
        self._watcher = threading.Thread(
            target=self._watch_completion_port,
            name="wlmcp-windows-job",
            daemon=True,
        )
        self._watcher.start()

    def _watch_completion_port(self) -> None:
        while not self._closed:
            message = wintypes.DWORD()
            key = ctypes.c_size_t()
            overlapped = ctypes.c_void_p()
            ok = _kernel32.GetQueuedCompletionStatus(
                self._completion_port,
                ctypes.byref(message),
                ctypes.byref(key),
                ctypes.byref(overlapped),
                500,
            )
            if not ok:
                if ctypes.get_last_error() == _WAIT_TIMEOUT:
                    continue
                if self._closed:
                    return
                self._record_violation("job_completion_port_failure")
                return
            if key.value == 0 and message.value == 0:
                return
            if message.value == _JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO:
                self._active_zero.set()
            elif message.value == _JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT:
                self._record_violation("process_count_limit")
                return
            elif message.value == _JOB_OBJECT_MSG_JOB_MEMORY_LIMIT:
                self._record_violation("process_tree_memory_limit")
                return

    def _record_violation(self, violation: str) -> None:
        if self._violation is None:
            self._violation = violation
            self._violation_event.set()
        self.terminate()

    def _resume_initial_thread(self, pid: int) -> None:
        snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot in (None, _INVALID_HANDLE_VALUE):
            raise _winerror("CreateToolhelp32Snapshot")
        thread_handle = wintypes.HANDLE()
        try:
            entry = _THREADENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            found = bool(_kernel32.Thread32First(snapshot, ctypes.byref(entry)))
            while found:
                if int(entry.th32OwnerProcessID) == pid:
                    thread_handle = _kernel32.OpenThread(
                        _THREAD_SUSPEND_RESUME, False, entry.th32ThreadID
                    )
                    if not thread_handle:
                        raise _winerror("OpenThread")
                    resumed = _kernel32.ResumeThread(thread_handle)
                    if resumed == 0xFFFFFFFF:
                        raise _winerror("ResumeThread")
                    return
                found = bool(_kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
            raise WindowsJobUnavailable("suspended process initial thread was not found")
        finally:
            if thread_handle:
                _kernel32.CloseHandle(thread_handle)
            _kernel32.CloseHandle(snapshot)

    def accounting(self) -> dict[str, int]:
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        returned = wintypes.DWORD()
        if not _kernel32.QueryInformationJobObject(
            self._job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
            ctypes.byref(returned),
        ):
            raise _winerror("QueryInformationJobObject")
        return {
            "active_processes": self._active_process_count(),
            "peak_job_memory_bytes": int(info.PeakJobMemoryUsed),
        }

    def _active_process_count(self) -> int:
        class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        info = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        returned = wintypes.DWORD()
        if not _kernel32.QueryInformationJobObject(
            self._job, 1, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(returned)
        ):
            raise _winerror("QueryInformationJobObject(accounting)")
        return int(info.ActiveProcesses)

    def terminate(self, exit_code: int = 1) -> bool:
        if self._closed or not self._job:
            return True
        if _kernel32.TerminateJobObject(self._job, exit_code):
            return True
        error = ctypes.get_last_error()
        return error in (0, 6)

    def wait_empty(self, timeout: float = 10) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if self._active_process_count() == 0:
                    return True
            except WindowsJobUnavailable:
                return False
            self._active_zero.wait(min(0.05, max(0.0, deadline - time.monotonic())))
        return False

    def close(self) -> None:
        if self._closed:
            return
        self.terminate()
        self.wait_empty(timeout=10)
        self._closed = True
        if self._completion_port:
            _kernel32.PostQueuedCompletionStatus(self._completion_port, 0, 0, None)
        if self._watcher is not None:
            self._watcher.join(timeout=2)
        if self._completion_port:
            _kernel32.CloseHandle(self._completion_port)
            self._completion_port = wintypes.HANDLE()
        if self._job:
            _kernel32.CloseHandle(self._job)
            self._job = wintypes.HANDLE()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()
