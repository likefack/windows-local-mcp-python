import os
import sys
from pathlib import Path

from windows_local_mcp.process_utils import ProcessIdentity, terminate_process_tree


class FakeProcess:
    def __init__(
        self,
        create_time: float,
        executable: str,
        nonce: str,
        *,
        running: bool = True,
        children: list["FakeProcess"] | None = None,
    ) -> None:
        self._create_time = create_time
        self._executable = executable
        self._nonce = nonce
        self._running = running
        self._children = list(children or [])
        self.terminated = False

    def create_time(self) -> float:
        return self._create_time

    def exe(self) -> str:
        return self._executable

    def environ(self) -> dict[str, str]:
        return {"WINDOWS_LOCAL_MCP_JOB_NONCE": self._nonce}

    def children(self, recursive: bool = False) -> list["FakeProcess"]:
        assert recursive is True
        return list(self._children)

    def is_running(self) -> bool:
        return self._running

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        raise AssertionError("no process should require force-kill in this test")


def test_terminate_process_tree_uses_the_verified_process_object(monkeypatch) -> None:
    expected_executable = os.path.normcase(str(Path(sys.executable).resolve()))
    identity = ProcessIdentity(
        pid=4321,
        create_time=20.0,
        executable=expected_executable,
        nonce="nonce",
    )
    verified = FakeProcess(20.0, sys.executable, "nonce")
    replacement = FakeProcess(30.0, sys.executable, "different-nonce")
    processes = iter((verified, replacement))
    opened_pids: list[int] = []

    def open_process(pid: int) -> FakeProcess:
        opened_pids.append(pid)
        return next(processes)

    monkeypatch.setattr("windows_local_mcp.process_utils.psutil.Process", open_process)
    monkeypatch.setattr(
        "windows_local_mcp.process_utils.psutil.wait_procs",
        lambda processes, timeout: (processes, []),
    )

    assert terminate_process_tree(identity)
    assert opened_pids == [identity.pid]
    assert verified.terminated is True
    assert replacement.terminated is False


def test_terminate_process_tree_fails_closed_if_parent_binding_changes_after_enumeration(
    monkeypatch,
) -> None:
    expected_executable = os.path.normcase(str(Path(sys.executable).resolve()))
    identity = ProcessIdentity(
        pid=4321,
        create_time=20.0,
        executable=expected_executable,
        nonce="nonce",
    )
    unrelated_child = FakeProcess(31.0, sys.executable, "other")
    verified = FakeProcess(
        20.0,
        sys.executable,
        "nonce",
        running=False,
        children=[unrelated_child],
    )

    monkeypatch.setattr(
        "windows_local_mcp.process_utils.psutil.Process", lambda _pid: verified
    )

    assert terminate_process_tree(identity) is False
    assert verified.terminated is False
    assert unrelated_child.terminated is False
