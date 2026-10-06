from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Self

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "runtime_update_support",
    Path(__file__).resolve().parents[1] / "scripts" / "runtime_update_support.py",
)
assert _SPEC is not None and _SPEC.loader is not None
support = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(support)


@pytest.fixture
def source(tmp_path: Path) -> Path:
    root = tmp_path / "日本語 source"
    root.mkdir()
    files = {
        "pyproject.toml": "[project]\nname='windows-local-mcp'\n",
        "README.md": "更新の説明\n",
        "config.example.toml": "git_enabled=false\n",
        "src/windows_local_mcp/__init__.py": "",
        "src/windows_local_mcp/main.py": "VALUE = 1\n",
        "scripts/runtime_update_support.py": "# helper\n",
        "update-localmcp.ps1": "# updater\n",
        "update-localmcp.bat": "@echo off\n",
        ".venv/private.py": "secret\n",
        ".dev-tmp/private.ps1": "secret\n",
        ".git/config": "secret\n",
        "tests/test_private.py": "secret\n",
        "config.toml": "secret\n",
        "src/windows_local_mcp/__pycache__/main.pyc": "cache\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def test_snapshot_whitelist_round_trip_and_manifest(source: Path) -> None:
    destination = source / ".dev-tmp" / "snapshot"
    result = support.snapshot(source, destination)
    assert result["file_count"] == 8
    assert support.verify(destination, result["digest"]) == result
    assert not (destination / ".venv").exists()
    assert not (destination / "config.toml").exists()
    assert (destination / "update-localmcp.ps1").exists()
    manifest = json.loads((destination / support.MANIFEST_NAME).read_text(encoding="utf-8"))
    assert result["digest"] == support._digest(manifest)


@pytest.mark.parametrize("change", ["edit", "remove", "add", "forbidden", "manifest"])
def test_verify_rejects_every_snapshot_change(source: Path, tmp_path: Path, change: str) -> None:
    destination = tmp_path / "snapshot"
    result = support.snapshot(source, destination)
    if change == "edit":
        (destination / "README.md").write_text("changed", encoding="utf-8")
    elif change == "remove":
        (destination / "src/windows_local_mcp/main.py").unlink()
    elif change == "add":
        (destination / "src/windows_local_mcp/extra.py").write_text("", encoding="utf-8")
    elif change == "forbidden":
        (destination / "secret.env").write_text("", encoding="utf-8")
    else:
        manifest = destination / support.MANIFEST_NAME
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace('"version":1', '"version":2'),
            encoding="utf-8",
        )
    with pytest.raises(support.UpdateCheckError):
        support.verify(destination, result["digest"])


def test_snapshot_rejects_changes_during_copy(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = support.shutil.copyfile

    def changing_copy(src: Path, dst: Path) -> None:
        original(src, dst)
        if Path(src).name == "README.md":
            Path(src).write_text("changed while copying", encoding="utf-8")

    monkeypatch.setattr(support.shutil, "copyfile", changing_copy)
    with pytest.raises(support.UpdateCheckError, match="変化"):
        support.snapshot(source, tmp_path / "snapshot")


def test_reparse_in_package_is_rejected(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows junction の属性を再現する。権限を要する実 junction 作成は行わない。
    directory = source / "src/windows_local_mcp/nested"
    directory.mkdir()
    original = Path.lstat

    def lstat(path: Path, *args: object, **kwargs: object) -> object:
        details = original(path, *args, **kwargs)
        if path == directory:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        return details

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(support.UpdateCheckError, match="reparse"):
        support.snapshot(source, tmp_path / "snapshot")


class Distribution:
    def __init__(self, name: str, version: str, direct: str | None = None):
        self.metadata = {"Name": name}
        self.version = version
        self.direct = direct

    def read_text(self, name: str) -> str | None:
        assert name == "direct_url.json"
        return self.direct


def test_constraints_pins_pip_and_excludes_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        support.importlib.metadata,
        "distributions",
        lambda: [
            Distribution("pip", "25.1"),
            Distribution("A_b", "1.2.0"),
            Distribution("a-b", "1.2.0"),
            Distribution("windows-local-mcp", "0.6", "{}"),
        ],
    )
    path = tmp_path / "constraints.txt"
    assert support.constraints(path) == {"package_count": 2, "pip_version": "25.1"}
    assert path.read_text(encoding="utf-8") == "a-b==1.2.0\npip==25.1\n"


@pytest.mark.parametrize(
    "distribution",
    [
        Distribution("a", "1.0", '{"dir_info":{"editable":true}}'),
        Distribution("a", "https://example.test/a"),
        Distribution("a\n--extra-index-url", "1.0"),
        Distribution("pip", "99.0"),
    ],
)
def test_constraints_rejects_unsafe_or_conflicting_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, distribution: Distribution
) -> None:
    monkeypatch.setattr(
        support.importlib.metadata,
        "distributions",
        lambda: [Distribution("pip", "25.1"), distribution],
    )
    with pytest.raises(support.UpdateCheckError):
        support.constraints(tmp_path / "constraints.txt")
    assert not (tmp_path / "constraints.txt").exists()


@pytest.mark.parametrize(
    "status", ["queued", "running", "pending_approval", "approved", "committing", "unknown"]
)
def test_audit_nonterminal_is_read_only(tmp_path: Path, status: str) -> None:
    database = tmp_path / "audit.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE operations (status TEXT)")
        connection.executemany(
            "INSERT INTO operations VALUES (?)",
            [(item,) for item in support.TERMINAL_STATUSES | {status}],
        )
    before = database.read_bytes()
    assert support.audit_nonterminal_count(database) == 1
    assert database.read_bytes() == before


def test_audit_only_terminal_and_missing_database(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    assert support.audit_nonterminal_count(database) == 0
    assert not database.exists()
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE operations (status TEXT)")
        connection.executemany(
            "INSERT INTO operations VALUES (?)", [(item,) for item in support.TERMINAL_STATUSES]
        )
    assert support.audit_nonterminal_count(database) == 0


PROCESS_ROOTS = {
    "install_root": Path("C:/Runtime"),
    "launcher_root": Path("C:/Repo"),
    "config": Path("C:/Profiles/config.toml"),
    "profile": Path("C:/Profiles/main.yaml"),
}


@pytest.mark.parametrize(
    ("exe", "args", "expected"),
    [
        ("C:/Runtime/runtime/Scripts/python.exe", [], True),
        ("C:/Runtime-copy/python.exe", [], False),
        ("C:/Windows/powershell.exe", ["-File", "C:/Runtime/run-server.ps1"], True),
        ("C:/Windows/powershell.exe", ["-File", "C:/Repo/run-localmcp.ps1"], True),
        ("C:/Windows/powershell.exe", ["-File", "C:/Repo/update-localmcp.ps1"], False),
        ("C:/Python/python.exe", ["-m", "windows_local_mcp.cli", "C:/Profiles/config.toml"], True),
        (
            "C:/Python/python.exe",
            ["-m", "windows_local_mcp.cli", "C:/Profiles/config.toml.backup"],
            False,
        ),
        ("C:/Tools/tunnel-client.exe", ["run", "--profile-file", "C:/Profiles/main.yaml"], True),
        (
            "C:/Tools/tunnel-client.exe",
            ["run", "--profile-file", "C:/Profiles/main.yaml.bak"],
            False,
        ),
    ],
)
def test_process_match_uses_complete_paths(exe: str, args: list[str], expected: bool) -> None:
    assert support.process_matches(exe, args, **PROCESS_ROOTS) is expected


def test_process_scan_excludes_only_self_and_scm_service(monkeypatch: pytest.MonkeyPatch) -> None:
    import psutil

    monkeypatch.setattr(support.sys, "_base_executable", support.sys.executable)

    def process(pid: int) -> SimpleNamespace:
        return SimpleNamespace(
            pid=pid,
            info={
                "pid": pid,
                "name": "python.exe",
                "exe": "C:/Runtime/runtime/Scripts/python.exe",
                "cmdline": [],
                "username": "user",
            },
        )

    def current_only(pid: int | None = None) -> object:
        if pid is not None:
            raise psutil.AccessDenied(pid)
        return SimpleNamespace(username=lambda: "user")

    monkeypatch.setattr(psutil, "Process", current_only)
    monkeypatch.setattr(support, "_authority_service_pid", lambda: 101)
    monkeypatch.setattr(
        psutil, "process_iter", lambda *args, **kwargs: [process(os.getpid()), process(101)]
    )
    assert support.assert_no_runtime_processes(**PROCESS_ROOTS) == 0
    # service の worker は別 PID なので拒否する。停止APIは用意も呼出しもしない。
    monkeypatch.setattr(psutil, "process_iter", lambda *args, **kwargs: [process(102)])
    with pytest.raises(support.UpdateCheckError, match="起動中"):
        support.assert_no_runtime_processes(**PROCESS_ROOTS)


def test_process_scan_unreadable_same_user_refuses_other_user_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import psutil

    monkeypatch.setattr(support.sys, "_base_executable", support.sys.executable)

    item = SimpleNamespace(
        pid=102,
        info={
            "name": "python.exe",
            "exe": None,
            "cmdline": None,
            "username": "NT AUTHORITY\\SYSTEM",
        },
    )
    monkeypatch.setattr(psutil, "Process", lambda: SimpleNamespace(username=lambda: "user"))
    monkeypatch.setattr(support, "_authority_service_pid", lambda: 0)
    monkeypatch.setattr(psutil, "process_iter", lambda *args, **kwargs: [item])
    assert support.assert_no_runtime_processes(**PROCESS_ROOTS) == 1
    item.info["username"] = "user"
    with pytest.raises(support.UpdateCheckError, match="所属"):
        support.assert_no_runtime_processes(**PROCESS_ROOTS)


@pytest.mark.skipif(os.name != "nt", reason="Windows venv 起動用プロセスの判定")
@pytest.mark.parametrize(
    "mismatch",
    [
        None,
        "parent_exe",
        "child_exe",
        "arguments",
        "empty_arguments",
        "birth_order",
        "parent_pid",
        "dead_parent",
        "reused_pid",
        "unreadable_parent",
        "other_process",
    ],
)
def test_process_scan_excludes_only_verified_immediate_venv_launcher(
    monkeypatch: pytest.MonkeyPatch, mismatch: str | None
) -> None:
    import psutil

    executable = "C:/Runtime/runtime/Scripts/python.exe"
    base = "C:/Python/python.exe"
    arguments = [
        executable,
        "-I",
        "-B",
        "-X",
        "utf8",
        "C:/Repo/scripts/runtime_update_support.py",
        "offline",
    ]
    monkeypatch.setattr(support.sys, "executable", executable)
    monkeypatch.setattr(support.sys, "_base_executable", base)

    class Process:
        def __init__(self, pid: int, exe: str, created: float, args: list[str]) -> None:
            self.pid, self.executable, self.created, self.arguments = pid, exe, created, args
            self.info = {"name": "python.exe", "exe": exe, "cmdline": args, "username": "user"}

        def username(self) -> str:
            return "user"

        def exe(self) -> str:
            if mismatch == "unreadable_parent" and self.pid == 101:
                raise psutil.AccessDenied(self.pid)
            return self.executable

        def cmdline(self) -> list[str]:
            return self.arguments

        def create_time(self) -> float:
            return self.created

        def is_running(self) -> bool:
            return not (mismatch == "dead_parent" and self.pid == 101)

        def ppid(self) -> int:
            return 199 if mismatch == "parent_pid" else 101

        def parent(self) -> Process:
            return parent

    parent = Process(101, executable, 10.0, arguments.copy())
    current = Process(os.getpid(), base, 11.0, arguments.copy())
    if mismatch == "parent_exe":
        parent.executable = "C:/Runtime/other/python.exe"
    elif mismatch == "child_exe":
        current.executable = "C:/Python/other-python.exe"
    elif mismatch == "arguments":
        parent.arguments = [executable, "-m", "windows_local_mcp.cli", "server"]
    elif mismatch == "empty_arguments":
        parent.arguments = current.arguments = []
    elif mismatch == "birth_order":
        parent.created = 12.0
    parent_entry = (
        parent if mismatch != "reused_pid" else Process(101, executable, 12.0, arguments.copy())
    )
    processes = [current, parent_entry]
    if mismatch == "other_process":
        # 同じ helper を使う別 process も、即親として検証した PID 以外は拒否する。
        processes.append(Process(102, executable, 10.0, arguments.copy()))
    monkeypatch.setattr(psutil, "Process", lambda: current)
    monkeypatch.setattr(psutil, "process_iter", lambda *args, **kwargs: processes)
    monkeypatch.setattr(support, "_authority_service_pid", lambda: 0)
    if mismatch is None:
        assert support.assert_no_runtime_processes(**PROCESS_ROOTS) == 0
    else:
        with pytest.raises(support.UpdateCheckError, match="起動中"):
            support.assert_no_runtime_processes(**PROCESS_ROOTS)


def test_process_scan_direct_python_keeps_parent_as_target(monkeypatch: pytest.MonkeyPatch) -> None:
    import psutil

    executable = "C:/Runtime/runtime/Scripts/python.exe"
    monkeypatch.setattr(support.sys, "executable", executable)
    monkeypatch.setattr(support.sys, "_base_executable", executable)
    monkeypatch.setattr(psutil, "Process", lambda: SimpleNamespace(username=lambda: "user"))
    monkeypatch.setattr(support, "_authority_service_pid", lambda: 0)
    monkeypatch.setattr(psutil, "process_iter", lambda *args, **kwargs: [])
    assert support.assert_no_runtime_processes(**PROCESS_ROOTS) == 0
    parent = SimpleNamespace(
        pid=101, info={"name": "python.exe", "exe": executable, "cmdline": [], "username": "user"}
    )
    monkeypatch.setattr(psutil, "process_iter", lambda *args, **kwargs: [parent])
    with pytest.raises(support.UpdateCheckError, match="起動中"):
        support.assert_no_runtime_processes(**PROCESS_ROOTS)


@pytest.mark.skipif(os.name != "nt", reason="Windows service の venv 起動用プロセスの判定")
@pytest.mark.parametrize(
    "mismatch",
    [
        None,
        "parent_exe",
        "child_exe",
        "birth_order",
        "parent_pid",
        "dead_parent",
        "dead_service",
        "unreadable_parent",
        "unreadable_service",
        "reused_parent_pid",
        "reused_service_pid",
        "service_disappears",
        "service_unreadable_later",
        "service_reparented",
        "service_dies_later",
        "worker",
        "ancestor",
    ],
)
def test_process_scan_excludes_only_scm_bound_service_venv_parent(
    monkeypatch: pytest.MonkeyPatch, mismatch: str | None
) -> None:
    import psutil

    executable = "C:/Runtime/runtime/Scripts/python.exe"
    base = "C:/Python/python.exe"
    # helper 自身の venv 判定とは独立して service の起動用プロセスを検査する。
    monkeypatch.setattr(support.sys, "executable", base)
    monkeypatch.setattr(support.sys, "_base_executable", base)

    class Process:
        def __init__(self, pid: int, exe: str, created: float, parent_pid: int) -> None:
            self.pid, self.executable, self.created, self.parent_pid = pid, exe, created, parent_pid
            self.alive = True
            self.info = {"name": "python.exe", "exe": exe, "cmdline": None, "username": None}

        def username(self) -> str:
            raise AssertionError("service の username に依存してはならない")

        def cmdline(self) -> list[str]:
            raise AssertionError("service の cmdline に依存してはならない")

        def exe(self) -> str:
            if (mismatch == "unreadable_parent" and self.pid == 201) or (
                mismatch == "unreadable_service" and self.pid == 202
            ):
                raise psutil.AccessDenied(self.pid)
            return self.executable

        def create_time(self) -> float:
            return self.created

        def ppid(self) -> int:
            return self.parent_pid

        def is_running(self) -> bool:
            return self.alive

        def parent(self) -> Process:
            assert self.pid == 202
            return parent

    parent = Process(201, executable, 10.0, 200)
    service = Process(202, base, 11.0, 201)
    if mismatch == "parent_exe":
        parent.executable = "C:/Runtime/other/python.exe"
    elif mismatch == "child_exe":
        service.executable = "C:/Python/other-python.exe"
    elif mismatch == "birth_order":
        parent.created = 12.0
    elif mismatch == "parent_pid":
        service.parent_pid = 299
    elif mismatch == "dead_parent":
        parent.alive = False
    elif mismatch == "dead_service":
        service.alive = False
    parent_entry = (
        Process(201, executable, 12.0, 200) if mismatch == "reused_parent_pid" else parent
    )
    service_later = Process(202, base, 12.0 if mismatch == "reused_service_pid" else 11.0, 201)
    if mismatch == "service_reparented":
        service_later.parent_pid = 299
    if mismatch == "service_dies_later":
        service_later.alive = False
    processes = [service, parent_entry]
    if mismatch == "worker":
        processes.append(Process(203, executable, 12.0, 202))
    if mismatch == "ancestor":
        # parent の親をたどって一括除外しない。
        processes.append(Process(200, executable, 9.0, 199))
    lookup_count = 0

    def get_process(pid: int | None = None) -> object:
        nonlocal lookup_count
        if pid is None:
            return SimpleNamespace(username=lambda: "user")
        assert pid == 202
        lookup_count += 1
        if lookup_count == 1:
            return service
        if mismatch == "service_disappears":
            raise psutil.NoSuchProcess(pid)
        if mismatch == "service_unreadable_later":
            raise psutil.AccessDenied(pid)
        return service_later

    monkeypatch.setattr(psutil, "Process", get_process)
    monkeypatch.setattr(psutil, "process_iter", lambda *args, **kwargs: processes)
    monkeypatch.setattr(support, "_authority_service_pid", lambda: 202)
    if mismatch is None:
        assert support.assert_no_runtime_processes(**PROCESS_ROOTS) == 0
        assert lookup_count == 2
    else:
        with pytest.raises(support.UpdateCheckError, match="起動中"):
            support.assert_no_runtime_processes(**PROCESS_ROOTS)


@pytest.mark.skipif(os.name != "nt", reason="Windows SCM API の型を使用")
@pytest.mark.parametrize(("state", "pid", "expected"), [(4, 101, 101), (1, 0, 0), (3, 101, None)])
def test_service_pid_uses_only_query_status_and_handles_stopped(
    monkeypatch: pytest.MonkeyPatch, state: int, pid: int, expected: int | None
) -> None:
    import ctypes

    from windows_local_mcp import approved_host_authority as authority_api

    closed = []

    class Api:
        @staticmethod
        def OpenSCManagerW(machine: object, database: object, access: int) -> int:
            assert machine is None and database is None and access == 0x0001
            return 11

        @staticmethod
        def OpenServiceW(manager: int, name: str, access: int) -> int:
            assert manager == 11 and name == "WindowsLocalMCPApprovedHost"
            assert access == 0x0004  # QUERY_CONFIG / CHANGE_CONFIG は要求しない。
            return 12

        @staticmethod
        def QueryServiceStatusEx(
            service: int, level: int, status: object, size: int, needed: object
        ) -> bool:
            assert service == 12 and level == 0
            record = ctypes.cast(
                status, ctypes.POINTER(authority_api._SERVICE_STATUS_PROCESS)
            ).contents
            record.dwCurrentState = state
            record.dwProcessId = pid
            return True

        @staticmethod
        def CloseServiceHandle(handle: int) -> bool:
            closed.append(handle)
            return True

    monkeypatch.setattr(authority_api, "_advapi32", Api())
    if expected is None:
        with pytest.raises(support.UpdateCheckError, match="状態遷移中"):
            support._authority_service_pid()
    else:
        assert support._authority_service_pid() == expected
    assert closed == [12, 11]


def test_offline_rejects_recovery_without_audit_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from windows_local_mcp import config, workspace_history

    settings = SimpleNamespace(data_dir=tmp_path / "data", workspace_root=tmp_path / "workspace")
    monkeypatch.setattr(
        config, "validate_configuration_candidate", lambda *args, **kwargs: settings
    )
    monkeypatch.setattr(workspace_history, "workspace_recovery_required", lambda _: True)
    with pytest.raises(support.UpdateCheckError, match="復旧待ち"):
        support.offline(tmp_path / "config.toml", tmp_path / "runtime", tmp_path / "repo")
    assert not settings.data_dir.exists()


def test_cli_sanitizes_library_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail() -> None:
        raise RuntimeError("secret-token-canary")

    monkeypatch.setattr(support, "authority", fail)
    assert support.main(["authority"]) == 1
    captured = capsys.readouterr()
    assert "secret-token-canary" not in captured.err
    assert json.loads(captured.err)["error_type"] == "RuntimeError"


@pytest.mark.parametrize("wrong_content", [False, True])
@pytest.mark.parametrize("paging", ["single", "paged", "cycle"])
def test_smoke_scrubs_environment_and_requires_readback(
    tmp_path: Path, source: Path, monkeypatch: pytest.MonkeyPatch, wrong_content: bool, paging: str
) -> None:
    import mcp
    import mcp.client.stdio

    from windows_local_mcp import approved_host_policy

    monkeypatch.setattr(approved_host_policy, "_authority_service_installed", lambda: False)

    captured = {}
    monkeypatch.setenv("LOCAL_MCP_ROOT", "production-canary")
    monkeypatch.setenv("LOCAL_MCP_CONFIG", "production-secret-config-canary")
    monkeypatch.setenv("PYTHONPATH", "production-pythonpath-canary")

    def transport(parameters: object, *, errlog: object) -> object:
        captured["parameters"] = parameters
        assert parameters.args[:4] == ["-I", "-B", "-X", "utf8"]
        assert "LOCAL_MCP_ROOT" not in parameters.env
        assert "PYTHONPATH" not in parameters.env
        assert "production-secret-config-canary" not in parameters.env.values()
        assert Path(parameters.env["LOCAL_MCP_CONFIG"]).is_file()
        return parameters

    class Client:
        def __init__(self, transport: object) -> None:
            self.transport = transport

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def list_tools(self, *, cursor: str | None = None) -> object:
            first_page = paging != "single" and cursor is None
            return SimpleNamespace(
                tools=[
                    SimpleNamespace(
                        model_dump=lambda **_: {
                            "name": "session_info" if first_page else "read_file",
                            "inputSchema": {"type": "object"},
                        }
                    )
                ],
                next_cursor="page-2" if first_page or paging == "cycle" else None,
            )

        async def call_tool(self, name: str, arguments: dict) -> object:
            assert name == "read_file" and arguments == {"path": "readback.txt"}
            return SimpleNamespace(
                is_error=False,
                structured_content={
                    "content": "wrong"
                    if wrong_content
                    else "Windows Local MCP update read-back: 日本語"
                },
            )

    monkeypatch.setattr(mcp, "Client", Client)
    monkeypatch.setattr(mcp.client.stdio, "stdio_client", transport)
    scratch = tmp_path / "smoke"
    if paging == "cycle":
        with pytest.raises(support.UpdateCheckError, match="ページ送り"):
            support.smoke(scratch, source)
    elif wrong_content:
        with pytest.raises(support.UpdateCheckError, match="読み戻し"):
            support.smoke(scratch, source)
    else:
        result = support.smoke(scratch, source)
        assert result["tool_count"] == (1 if paging == "single" else 2)
        assert len(result["tool_schema_sha256"]) == 64
    assert str(source / "src") in captured["parameters"].args[5].replace("\\\\", "\\")
    assert list(scratch.iterdir()) == []


def test_smoke_reports_unavailable_authority_without_bypassing_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from windows_local_mcp import approved_host_policy

    monkeypatch.setattr(approved_host_policy, "_authority_service_installed", lambda: True)

    def unavailable() -> None:
        raise PermissionError("secret-pipe-detail")

    monkeypatch.setattr(
        approved_host_policy, "assert_approved_host_authority_available", unavailable
    )
    with pytest.raises(support.UpdateCheckError, match="監視サービス") as caught:
        support.smoke(tmp_path / "smoke")
    assert "secret-pipe-detail" not in str(caught.value)
    assert not (tmp_path / "smoke").exists()


def test_cli_unwraps_safe_group_errors_without_library_messages(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail() -> None:
        raise ExceptionGroup(
            "secret-group-message",
            [
                ExceptionGroup("nested-secret", [support.UpdateCheckError("読み戻し失敗")]),
                RuntimeError("secret-library-message"),
            ],
        )

    monkeypatch.setattr(support, "authority", fail)
    assert support.main(["authority"]) == 1
    captured = capsys.readouterr()
    assert "secret" not in captured.err
    result = json.loads(captured.err)
    assert result["check_errors"] == ["読み戻し失敗"]
    assert result["cause_types"] == ["RuntimeError", "UpdateCheckError"]


def test_idle_does_not_require_server_exit_and_offline_still_checks_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from windows_local_mcp import config, workspace_history

    settings = SimpleNamespace(data_dir=tmp_path / "data", workspace_root=tmp_path / "workspace")
    monkeypatch.setattr(config, "validate_configuration_candidate", lambda *a, **kw: settings)
    monkeypatch.setattr(workspace_history, "workspace_recovery_required", lambda _: False)

    def running(**kwargs: object) -> None:
        raise support.UpdateCheckError("起動中")

    monkeypatch.setattr(support, "assert_no_runtime_processes", running)
    assert support.idle(tmp_path / "config.toml")["nonterminal_count"] == 0
    with pytest.raises(support.UpdateCheckError, match="起動中"):
        support.offline(tmp_path / "config.toml", tmp_path / "runtime", tmp_path / "repo")
    assert not settings.data_dir.exists()


@pytest.fixture
def approval_chain(monkeypatch: pytest.MonkeyPatch) -> list:
    import psutil

    powershell = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    executable = "C:/Runtime/runtime/Scripts/python.exe"
    base = "C:/Python/python.exe"
    monkeypatch.setenv("SystemRoot", "C:/Windows")
    monkeypatch.setattr(support.sys, "_base_executable", base)

    class Process:
        def __init__(self, pid, exe, args, created, parent=None):
            self.pid, self.executable, self.arguments = pid, exe, args
            self.created, self.owner, self.alive = created, "user", True
            self.parent_process, self.child_processes = parent, []
            if parent is not None:
                parent.child_processes.append(self)

        def exe(self):
            return self.executable

        def cmdline(self):
            return self.arguments

        def username(self):
            return self.owner

        def is_running(self):
            return self.alive

        def create_time(self):
            return self.created

        def parent(self):
            return self.parent_process

        def ppid(self):
            return self.parent_process.pid if self.parent_process else 0

        def children(self):
            return self.child_processes

    wrapper = Process(
        301,
        powershell,
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "C:/Runtime/run-approvals.ps1",
            "-Config",
            "C:/Profiles/config.toml",
        ],
        1.0,
    )
    args = [executable, "-I", "-B", "-m", "windows_local_mcp.cli", "approvals"]
    launcher = Process(302, executable, args.copy(), 2.0, wrapper)
    child = Process(303, base, args.copy(), 3.0, launcher)
    monkeypatch.setattr(psutil, "Process", lambda: SimpleNamespace(username=lambda: "user"))
    monkeypatch.setattr(psutil, "process_iter", lambda: [wrapper, launcher, child])
    return [wrapper, launcher, child]


@pytest.mark.parametrize(
    "mismatch",
    [
        None,
        "config",
        "wrapper",
        "extra_arg",
        "command",
        "venv",
        "base",
        "child_args",
        "user",
        "birth",
        "dead",
        "extra_child",
        "no_child",
    ],
)
def test_approval_chain_requires_exact_dedicated_wrapper(approval_chain, mismatch):
    wrapper, launcher, child = approval_chain
    if mismatch == "config":
        wrapper.arguments[-1] += ".other"
    elif mismatch == "wrapper":
        wrapper.arguments[-3] = "C:/Runtime/run-server.ps1"
    elif mismatch == "extra_arg":
        wrapper.arguments.append("-NoExit")
    elif mismatch == "command":
        launcher.arguments[-1] = "worker"
    elif mismatch == "venv":
        launcher.executable = "C:/Other/python.exe"
    elif mismatch == "base":
        child.executable = "C:/Other/python.exe"
    elif mismatch == "child_args":
        child.arguments[-1] = "worker"
    elif mismatch == "user":
        child.owner = "other-user"
    elif mismatch == "birth":
        wrapper.created = 4.0
    elif mismatch == "dead":
        child.alive = False
    elif mismatch == "extra_child":
        launcher.child_processes.append(wrapper)
    elif mismatch == "no_child":
        launcher.child_processes.clear()
    result = support._approval_process_chain(
        launcher, PROCESS_ROOTS["install_root"], PROCESS_ROOTS["config"]
    )
    assert result == (approval_chain if mismatch is None else [])


def test_approval_scan_does_not_read_unrelated_process_arguments():
    def forbidden():
        raise AssertionError("無関係なプロセスの引数を読み取ってはならない")

    process = SimpleNamespace(exe=lambda: "C:/Windows/System32/cmd.exe", cmdline=forbidden)
    assert (
        support._approval_process_chain(
            process, PROCESS_ROOTS["install_root"], PROCESS_ROOTS["config"]
        )
        == []
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows console の終了通知")
@pytest.mark.parametrize("case", ["ok", "shared", "attach_failed", "changed"])
def test_approval_console_checks_membership_before_ctrl_c(monkeypatch, approval_chain, case):
    import ctypes

    calls = []

    class Function:
        def __init__(self, call):
            self.call = call

        def __call__(self, *args):
            return self.call(*args)

    def members(array, capacity):
        pids = [301, 302, 303, os.getpid()]
        if case == "shared":
            pids.append(999)
        for index, pid in enumerate(pids):
            array[index] = pid
        return len(pids)

    api = SimpleNamespace(
        FreeConsole=Function(lambda: calls.append("free") or True),
        AttachConsole=Function(
            lambda pid: calls.append(("attach", pid)) or case != "attach_failed"
        ),
        SetConsoleCtrlHandler=Function(lambda handler, ignored: calls.append("ignore") or True),
        GetConsoleProcessList=Function(members),
        GenerateConsoleCtrlEvent=Function(
            lambda event, group: calls.append(("ctrl", event, group)) or True
        ),
    )
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **kw: api)

    def recheck():
        calls.append("check")
        if case == "changed":
            raise support.UpdateCheckError("変化")

    if case == "ok":
        support._interrupt_approval_console(approval_chain, recheck)
        assert calls == ["free", ("attach", 301), "ignore", "check", ("ctrl", 0, 0), "free"]
    else:
        with pytest.raises(support.UpdateCheckError):
            support._interrupt_approval_console(approval_chain, recheck)
        assert not any(isinstance(item, tuple) and item[0] == "ctrl" for item in calls)
        if case != "attach_failed":
            assert calls[-1] == "free"


@pytest.mark.skipif(os.name != "nt", reason="Windows console の終了通知")
@pytest.mark.parametrize("case", ["ok", "busy", "authority", "timeout", "reused"])
def test_close_ui_protects_work_and_waits_without_kill(monkeypatch, approval_chain, case):
    import psutil

    calls = []

    def gate(name):
        calls.append(name)
        if case == name:
            raise support.UpdateCheckError("待機中")

    monkeypatch.setattr(support, "authority", lambda: gate("authority"))
    monkeypatch.setattr(support, "idle", lambda config: gate("busy"))

    def notify(chain, recheck):
        if case == "reused":
            approval_chain[2].created += 1
        recheck()
        calls.append("notify")

    monkeypatch.setattr(support, "_interrupt_approval_console", notify)
    monkeypatch.setattr(
        psutil, "wait_procs", lambda chain, timeout: ([], chain if case == "timeout" else [])
    )
    if case == "ok":
        assert support.close_ui(PROCESS_ROOTS["config"], PROCESS_ROOTS["install_root"]) == {
            "closed_approval_ui_count": 1,
        }
        assert calls == ["authority", "busy", "authority", "busy", "notify"]
    else:
        with pytest.raises(support.UpdateCheckError):
            support.close_ui(PROCESS_ROOTS["config"], PROCESS_ROOTS["install_root"])
        assert ("notify" in calls) is (case == "timeout")
