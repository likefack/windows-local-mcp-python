from __future__ import annotations

import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from windows_local_mcp import windows_user_process
from windows_local_mcp.approved_host_service import _process_token_details


def test_binary_reader_uses_ctypes_handle_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    sentinel = object()

    def open_osfhandle(handle: int, flags: int) -> int:
        observed["handle"] = handle
        observed["flags"] = flags
        return 73

    def fdopen(descriptor: int, mode: str, *, buffering: int) -> object:
        observed["descriptor"] = descriptor
        observed["mode"] = mode
        observed["buffering"] = buffering
        return sentinel

    monkeypatch.setattr(windows_user_process.msvcrt, "open_osfhandle", open_osfhandle)
    monkeypatch.setattr(windows_user_process.os, "fdopen", fdopen)

    reader = windows_user_process._binary_reader_from_handle(wintypes.HANDLE(0x3B4))

    assert reader is sentinel
    assert observed == {
        "handle": 0x3B4,
        "flags": windows_user_process.os.O_RDONLY,
        "descriptor": 73,
        "mode": "rb",
        "buffering": 0,
    }


def test_binary_reader_rejects_null_handle() -> None:
    with pytest.raises(
        windows_user_process.WindowsUserProcessUnavailable,
        match="pipe HANDLE is null",
    ):
        windows_user_process._binary_reader_from_handle(wintypes.HANDLE())


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows token HANDLEs")
def test_captured_requester_token_survives_requester_exit() -> None:
    """The SYSTEM handoff must not depend on the approval UI staying alive."""
    requester = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        sid, elevated = _process_token_details(requester.pid)
        if elevated:
            pytest.skip("normal-user token handoff requires a non-elevated test user")
        created = psutil.Process(requester.pid).create_time()
        with pytest.raises(
            windows_user_process.WindowsUserProcessUnavailable,
            match="PID was reused",
        ):
            windows_user_process.RequesterPrimaryToken.capture(
                requester.pid, created - 60, sid
            )
        with pytest.raises(
            windows_user_process.WindowsUserProcessUnavailable,
            match="SID changed",
        ):
            windows_user_process.RequesterPrimaryToken.capture(
                requester.pid, created, "S-1-5-18"
            )
        with windows_user_process.RequesterPrimaryToken.capture(
            requester.pid, created, sid
        ) as token:
            requester.terminate()
            requester.wait(timeout=10)
            token.verify()
            startup = subprocess.STARTUPINFO()
            startup.lpAttributeList = {"handle_list": [token.handle]}
            os.set_handle_inheritable(token.handle, True)
            source_root = str(Path(__file__).resolve().parents[1] / "src")
            probe = (
                "import sys;"
                "sys.path.insert(0,sys.argv[1]);"
                "from windows_local_mcp.windows_user_process import RequesterPrimaryToken;"
                "lease=RequesterPrimaryToken.from_inherited(int(sys.argv[2]),sys.argv[3]);"
                "lease.verify();lease.close();print('verified')"
            )
            try:
                child = subprocess.run(
                    [sys.executable, "-I", "-B", "-c", probe,
                     source_root, str(token.handle), sid],
                    check=False,
                    capture_output=True,
                    text=True,
                    close_fds=True,
                    startupinfo=startup,
                    timeout=15,
                )
            finally:
                os.set_handle_inheritable(token.handle, False)
            assert child.returncode == 0, child.stderr
            assert child.stdout.strip() == "verified"
    finally:
        if requester.poll() is None:
            requester.kill()
            requester.wait(timeout=10)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows HANDLEs")
def test_child_launch_uses_inherited_token_without_closing_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class ProbeStop(Exception):
        pass

    closed: list[int] = []
    token = windows_user_process.RequesterPrimaryToken(42, "S-1-5-21-123")
    monkeypatch.setattr(token, "verify", lambda: None)

    def initialize(_list: object, _count: int, _flags: int, size: object) -> bool:
        size._obj.value = 64
        return True

    def create_process(primary: wintypes.HANDLE, *_args: object) -> None:
        assert primary.value == 42
        raise ProbeStop

    kernel = SimpleNamespace(
        InitializeProcThreadAttributeList=initialize,
        UpdateProcThreadAttribute=lambda *_: True,
        DeleteProcThreadAttributeList=lambda *_: None,
        CloseHandle=lambda handle: closed.append(handle.value),
    )
    monkeypatch.setattr(windows_user_process, "_kernel32", kernel)
    monkeypatch.setattr(
        windows_user_process,
        "_advapi32",
        SimpleNamespace(CreateProcessAsUserW=create_process),
    )
    monkeypatch.setattr(
        windows_user_process,
        "_create_output_pipe",
        lambda: (wintypes.HANDLE(10), wintypes.HANDLE(11)),
    )
    monkeypatch.setattr(
        windows_user_process, "_open_inheritable_nul", lambda: wintypes.HANDLE(12)
    )
    with pytest.raises(ProbeStop):
        windows_user_process.popen_as_requester_in_job(
            SimpleNamespace(_job=None),
            [r"C:\Windows\System32\whoami.exe", "/user"],
            requester_pid=999,
            requester_create_time=1.0,
            requester_token=token,
            cwd=tmp_path,
            environment={},
        )
    assert 42 not in closed
