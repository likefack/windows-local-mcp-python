from __future__ import annotations

from ctypes import wintypes

import pytest

from windows_local_mcp import windows_user_process


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
