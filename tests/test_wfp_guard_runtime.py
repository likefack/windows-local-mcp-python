from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from multiprocessing.connection import Listener

import pytest

from windows_local_mcp import wfp_guard_runtime as runtime
from windows_local_mcp.util import canonical_json
from windows_local_mcp.wfp_guard import (
    APP_ISOLATION_SUBLAYER_KEY,
    GUARD_POLICY_GENERATION,
    GUARD_SUBLAYER_KEY,
    GUARD_SUBLAYER_WEIGHT,
    GUARD_V4_FILTER_KEY,
    GUARD_V6_FILTER_KEY,
    GUARD_VERSION,
    TARGET_ACCOUNT,
    GuardVerification,
    WfpGuardError,
    WfpGuardMissingError,
    WfpGuardStateMismatchError,
)

_GUARD_IMPLEMENTATION_DIGEST = "a" * 64


def _verification() -> GuardVerification:
    return GuardVerification(
        guard_version=GUARD_VERSION,
        policy_generation=GUARD_POLICY_GENERATION,
        target_account=TARGET_ACCOUNT,
        target_computer_name="TESTPC",
        target_qualified_account=rf"TESTPC\{TARGET_ACCOUNT}",
        target_sid_name_use=1,
        target_sid="S-1-5-21-100-200-300-1004",
        app_isolation_sublayer_key=str(APP_ISOLATION_SUBLAYER_KEY),
        app_isolation_weight=7,
        guard_sublayer_key=str(GUARD_SUBLAYER_KEY),
        guard_sublayer_weight=GUARD_SUBLAYER_WEIGHT,
        v4_filter_key=str(GUARD_V4_FILTER_KEY),
        v4_filter_id=501,
        v4_effective_weight=100,
        v6_filter_key=str(GUARD_V6_FILTER_KEY),
        v6_filter_id=502,
        v6_effective_weight=100,
    )


class _FakeConnection:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.recv_called = False
        self.sent: list[bytes] = []
        self.closed = False

    def fileno(self) -> int:
        return 9001

    def recv_bytes(self) -> bytes:
        self.recv_called = True
        return self.payload

    def send_bytes(self, payload: bytes) -> None:
        self.sent.append(payload)

    def close(self) -> None:
        self.closed = True


class _FakeListener:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection
        self.closed = False

    def accept(self) -> _FakeConnection:
        return self.connection

    def close(self) -> None:
        self.closed = True


def _install_elevated_parent_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    connection: _FakeConnection,
    client_pid: int,
    client_executable: str = r"C:\Python314\python.exe",
    elevated_executable: str = r"C:\repo\.venv\Scripts\python.exe",
    expected_launcher: str = r"C:\repo\.venv\Scripts\python.exe",
    expected_base: str = r"C:\Python314\python.exe",
) -> tuple[_FakeListener, list[object]]:
    listener = _FakeListener(connection)
    closed_handles: list[object] = []

    def fake_listener(address: str, *, family: str) -> _FakeListener:
        assert address.startswith(r"\\.\pipe\wlmcp-wfp-guard-")
        assert family == "AF_PIPE"
        return listener

    monkeypatch.setattr(runtime, "Listener", fake_listener)
    monkeypatch.setattr(runtime, "_shell_execute_elevated", lambda _pipe: 7001)
    monkeypatch.setattr(runtime, "_process_id_from_handle", lambda _handle: 4242)
    monkeypatch.setattr(runtime, "_named_pipe_client_process_id", lambda _handle: client_pid)
    monkeypatch.setattr(runtime, "_process_parent_id", lambda _pid: 9999)
    monkeypatch.setattr(runtime, "_expected_venv_launcher_path", lambda: expected_launcher)
    monkeypatch.setattr(runtime, "_expected_base_python_path", lambda: expected_base)
    monkeypatch.setattr(
        runtime,
        "_same_executable_path",
        lambda actual, expected: (
            os.path.normcase(os.path.normpath(actual))
            == os.path.normcase(os.path.normpath(expected))
        ),
    )
    monkeypatch.setattr(
        runtime,
        "_process_executable_path",
        lambda process_id: elevated_executable if process_id == 4242 else client_executable,
    )
    monkeypatch.setattr(runtime, "_wait_for_elevated_exit", lambda _handle: None)
    monkeypatch.setattr(runtime, "_close_process_handle", closed_handles.append)
    monkeypatch.setattr(
        runtime,
        "capture_wfp_guard_implementation_identity",
        lambda: {"digest": _GUARD_IMPLEMENTATION_DIGEST},
    )
    return listener, closed_handles


def test_elevated_parent_accepts_readback_from_exact_runas_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = canonical_json(
        {
            "ok": True,
            "verification": _verification().as_dict(),
            "guard_implementation_digest": _GUARD_IMPLEMENTATION_DIGEST,
        }
    ).encode()
    connection = _FakeConnection(payload)
    listener, closed_handles = _install_elevated_parent_fakes(
        monkeypatch, connection=connection, client_pid=4242
    )

    assert runtime._run_elevated_ensure() == _verification()
    assert connection.recv_called is True
    assert connection.sent == [runtime._PIPE_PROCEED]
    assert connection.closed is True
    assert listener.closed is True
    assert closed_handles == [7001]


def test_elevated_parent_rejects_readback_from_different_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection(b"untrusted")
    listener, closed_handles = _install_elevated_parent_fakes(
        monkeypatch, connection=connection, client_pid=4243
    )

    with pytest.raises(WfpGuardError, match="unexpected process"):
        runtime._run_elevated_ensure()

    assert connection.recv_called is False
    assert connection.sent == []
    assert connection.closed is True
    assert listener.closed is True
    assert closed_handles == [7001]


def test_elevated_parent_accepts_direct_child_of_venv_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = canonical_json(
        {
            "ok": True,
            "verification": _verification().as_dict(),
            "guard_implementation_digest": _GUARD_IMPLEMENTATION_DIGEST,
        }
    ).encode()
    connection = _FakeConnection(payload)
    _install_elevated_parent_fakes(monkeypatch, connection=connection, client_pid=5151)
    monkeypatch.setattr(runtime, "_process_parent_id", lambda process_id: 4242)

    assert runtime._run_elevated_ensure() == _verification()
    assert connection.recv_called is True
    assert connection.sent == [runtime._PIPE_PROCEED]


def test_elevated_parent_rejects_unexpected_executable_with_matching_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection(b"untrusted")
    _install_elevated_parent_fakes(
        monkeypatch,
        connection=connection,
        client_pid=5151,
        client_executable=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    monkeypatch.setattr(runtime, "_process_parent_id", lambda _pid: 4242)

    with pytest.raises(WfpGuardError, match="unexpected process"):
        runtime._run_elevated_ensure()

    assert connection.recv_called is False
    assert connection.sent == []


def test_elevated_parent_rejects_unexpected_runas_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection(b"untrusted")
    _install_elevated_parent_fakes(
        monkeypatch,
        connection=connection,
        client_pid=5151,
        elevated_executable=r"C:\Python314\python.exe",
        expected_launcher=r"C:\repo\.venv\Scripts\python.exe",
    )
    monkeypatch.setattr(runtime, "_process_parent_id", lambda _pid: 4242)

    with pytest.raises(WfpGuardError, match="unexpected process"):
        runtime._run_elevated_ensure()

    assert connection.recv_called is False
    assert connection.sent == []


def test_force_elevated_route_uses_production_guard_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace: dict[str, object] = {}
    calls: list[dict[str, object] | None] = []

    def fake_run(*, diagnostic_trace: dict[str, object] | None = None) -> GuardVerification:
        calls.append(diagnostic_trace)
        return _verification()

    monkeypatch.setattr(runtime, "_is_administrator", lambda: False)
    monkeypatch.setattr(runtime, "_run_elevated_ensure", fake_run)

    assert runtime.ensure_runtime_codex_loopback_guard(
        force_elevated=True, diagnostic_trace=trace
    ) == _verification()
    assert calls == [trace]


def test_missing_exact_guard_object_uses_trusted_ensure_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def missing(_api: object) -> GuardVerification:
        calls.append("verify-missing")
        raise WfpGuardMissingError("fixed filter is missing")

    def elevated(*, diagnostic_trace: dict[str, object] | None = None) -> GuardVerification:
        assert diagnostic_trace is None
        calls.append("trusted-elevated-ensure")
        return _verification()

    monkeypatch.setattr(runtime, "verify_codex_loopback_block", missing)
    monkeypatch.setattr(runtime, "new_windows_wfp_api", lambda: object())
    monkeypatch.setattr(runtime, "_is_administrator", lambda: False)
    monkeypatch.setattr(runtime, "_run_elevated_ensure", elevated)

    assert runtime.ensure_runtime_codex_loopback_guard(
        allow_elevation=True
    ) == _verification()
    assert calls == ["verify-missing", "trusted-elevated-ensure"]


def test_missing_guard_never_elevates_during_normal_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def missing(_api: object) -> GuardVerification:
        calls.append("verify-missing")
        raise WfpGuardMissingError("fixed filter is missing")

    def forbidden(*_args: object, **_kwargs: object) -> GuardVerification:
        calls.append("forbidden-elevation")
        raise AssertionError("normal launch must not request elevation")

    monkeypatch.setattr(runtime, "verify_codex_loopback_block", missing)
    monkeypatch.setattr(runtime, "new_windows_wfp_api", lambda: object())
    monkeypatch.setattr(runtime, "_is_administrator", lambda: False)
    monkeypatch.setattr(runtime, "_run_elevated_ensure", forbidden)

    with pytest.raises(WfpGuardMissingError, match="fixed filter is missing"):
        runtime.ensure_runtime_codex_loopback_guard()
    assert calls == ["verify-missing"]


def test_unreadable_guard_never_elevates_during_normal_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def unreadable(_api: object) -> GuardVerification:
        calls.append("verify-unreadable")
        raise PermissionError("WFP read-back denied")

    def forbidden(*_args: object, **_kwargs: object) -> GuardVerification:
        calls.append("forbidden-elevation")
        raise AssertionError("normal launch must not request elevation")

    monkeypatch.setattr(runtime, "verify_codex_loopback_block", unreadable)
    monkeypatch.setattr(runtime, "new_windows_wfp_api", lambda: object())
    monkeypatch.setattr(runtime, "_is_administrator", lambda: False)
    monkeypatch.setattr(runtime, "_run_elevated_ensure", forbidden)

    with pytest.raises(PermissionError, match="read-back denied"):
        runtime.ensure_runtime_codex_loopback_guard()
    assert calls == ["verify-unreadable"]


def test_unreadable_guard_never_elevates_during_explicit_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def unreadable(_api: object) -> GuardVerification:
        calls.append("verify-unreadable")
        raise PermissionError("WFP read-back denied")

    def forbidden(*_args: object, **_kwargs: object) -> GuardVerification:
        calls.append("forbidden-elevation")
        raise AssertionError("unreadable state is not exact missing state")

    monkeypatch.setattr(runtime, "verify_codex_loopback_block", unreadable)
    monkeypatch.setattr(runtime, "new_windows_wfp_api", lambda: object())
    monkeypatch.setattr(runtime, "_is_administrator", lambda: False)
    monkeypatch.setattr(runtime, "_run_elevated_ensure", forbidden)

    with pytest.raises(PermissionError, match="read-back denied"):
        runtime.ensure_runtime_codex_loopback_guard(allow_elevation=True)
    assert calls == ["verify-unreadable"]


def test_existing_guard_state_mismatch_never_uses_silent_repair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def mismatch(_api: object) -> GuardVerification:
        calls.append("verify-mismatch")
        raise WfpGuardStateMismatchError("fixed filter conflicts")

    def forbidden(*_args: object, **_kwargs: object) -> GuardVerification:
        calls.append("forbidden-repair")
        raise AssertionError("conflicting state must not be repaired")

    monkeypatch.setattr(runtime, "verify_codex_loopback_block", mismatch)
    monkeypatch.setattr(runtime, "new_windows_wfp_api", lambda: object())
    monkeypatch.setattr(runtime, "_is_administrator", lambda: False)
    monkeypatch.setattr(runtime, "_run_elevated_ensure", forbidden)
    monkeypatch.setattr(runtime, "ensure_codex_loopback_block", forbidden)

    with pytest.raises(WfpGuardStateMismatchError, match="conflicts"):
        runtime.ensure_runtime_codex_loopback_guard()
    assert calls == ["verify-mismatch"]


@pytest.mark.parametrize("inherited_auth", [None, "not-inherited-or-used"])
def test_elevated_main_does_not_require_inherited_environment(
    monkeypatch: pytest.MonkeyPatch, inherited_auth: str | None
) -> None:
    sent: list[bytes] = []

    class FakeClient:
        def recv_bytes(self) -> bytes:
            return runtime._PIPE_PROCEED

        def send_bytes(self, payload: bytes) -> None:
            sent.append(payload)

        def close(self) -> None:
            pass

    def fake_client(pipe_name: str, *, family: str) -> FakeClient:
        assert pipe_name == r"\\.\pipe\test-wfp-guard"
        assert family == "AF_PIPE"
        return FakeClient()

    monkeypatch.setattr(runtime, "_is_administrator", lambda: True)
    monkeypatch.setattr(runtime, "new_windows_wfp_api", lambda: object())
    monkeypatch.setattr(runtime, "ensure_codex_loopback_block", lambda _api: _verification())
    monkeypatch.setattr(
        runtime,
        "capture_wfp_guard_implementation_identity",
        lambda: {"digest": _GUARD_IMPLEMENTATION_DIGEST},
    )
    monkeypatch.setattr(runtime, "Client", fake_client)
    if inherited_auth is None:
        monkeypatch.delenv("WLMCP_WFP_GUARD_AUTH", raising=False)
    else:
        monkeypatch.setenv("WLMCP_WFP_GUARD_AUTH", inherited_auth)

    assert runtime._elevated_main(r"\\.\pipe\test-wfp-guard") == 0
    assert json.loads(sent[0]) == {
        "ok": True,
        "verification": _verification().as_dict(),
        "guard_implementation_digest": _GUARD_IMPLEMENTATION_DIGEST,
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe peer identity")
def test_named_pipe_reports_actual_client_process_id() -> None:
    pipe_name = rf"\\.\pipe\wlmcp-wfp-guard-pid-test-{uuid.uuid4().hex}"
    listener = Listener(pipe_name, family="AF_PIPE")
    code = (
        "import os, sys; "
        "from multiprocessing.connection import Client; "
        "connection = Client(sys.argv[1], family='AF_PIPE'); "
        "connection.recv_bytes(); "
        "connection.send_bytes(f'{os.getpid()}:{os.getppid()}'.encode()); "
        "connection.close()"
    )
    child = subprocess.Popen([sys.executable, "-c", code, pipe_name])
    try:
        connection = listener.accept()
        try:
            actual_pid = runtime._named_pipe_client_process_id(connection.fileno())
            actual_parent = runtime._process_parent_id(actual_pid)
            connection.send_bytes(runtime._PIPE_PROCEED)
            reported_pid, reported_parent = map(int, connection.recv_bytes().decode().split(":"))
            assert actual_pid == reported_pid
            assert actual_parent == reported_parent
        finally:
            connection.close()
        assert child.wait(timeout=10) == 0
    finally:
        listener.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
