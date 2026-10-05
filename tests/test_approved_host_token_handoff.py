from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest

from windows_local_mcp import approved_host_service


def test_service_captures_verified_token_before_arm_and_lists_only_that_handle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[object] = []
    context = tmp_path / "context.json"
    context.write_text("{}", encoding="utf-8")

    class Store:
        root = tmp_path

        def read_active(self) -> None:
            return None

        def arm(self, **kwargs: Any) -> None:
            events.append(("arm", kwargs["requester_sid"]))

        def mark_running(self, _identity: object) -> None:
            events.append("running")

    class Token:
        handle = 1234

        def __enter__(self) -> Self:
            events.append("token_enter")
            return self

        def __exit__(self, *_args: object) -> None:
            events.append("token_close")

    def capture(pid: int, created: float, sid: str) -> Token:
        events.append(("capture", pid, created, sid))
        return Token()

    def popen(_argv: list[str], **kwargs: Any) -> SimpleNamespace:
        events.append(
            (
                "spawn",
                kwargs["startupinfo"].lpAttributeList,
                kwargs["close_fds"],
            )
        )
        return SimpleNamespace(pid=5678)

    class Thread:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def start(self) -> None:
            events.append("watcher")

    monkeypatch.setattr(approved_host_service, "_requester_create_time", lambda _pid: 42.0)
    monkeypatch.setattr(approved_host_service, "requester_username", lambda *_: "HOST\\user")
    monkeypatch.setattr(
        approved_host_service.RequesterPrimaryToken, "capture", capture
    )
    monkeypatch.setattr(approved_host_service.os, "set_handle_inheritable", lambda h, v: events.append(("inherit", h, v)))
    monkeypatch.setattr(approved_host_service.subprocess, "Popen", popen)
    monkeypatch.setattr(
        approved_host_service,
        "capture_process_identity",
        lambda *_: SimpleNamespace(pid=5678, create_time=43.0, executable="worker.exe"),
    )
    monkeypatch.setattr(approved_host_service.threading, "Thread", Thread)

    server = object.__new__(approved_host_service.ApprovedHostAuthorityServer)
    server.runtime_sid = "S-1-5-21-123"
    server.service_epoch = "epoch"
    server.store = Store()
    server._workers_lock = threading.Lock()
    server._workers = {}
    result = server._launch(
        900,
        {
            "requester_pid": 900,
            "requester_create_time": 42.0,
            "operation_id": "operation",
            "context_sha256": "digest",
            "process_nonce": "nonce",
            "context_path": str(context),
            "worker_environment": {"WINDOWS_LOCAL_MCP_JOB_NONCE": "nonce"},
        },
    )

    assert result["worker"]["pid"] == 5678
    assert events.index(("capture", 900, 42.0, "S-1-5-21-123")) < events.index(
        ("arm", "S-1-5-21-123")
    )
    assert ("spawn", {"handle_list": [1234]}, True) in events
    assert ("inherit", 1234, True) in events
    assert ("inherit", 1234, False) in events
    assert events[-1] == "watcher"
    assert "token_close" in events
