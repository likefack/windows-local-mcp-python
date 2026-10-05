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

    monkeypatch.setattr(psutil, "Process", lambda: SimpleNamespace(username=lambda: "user"))
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
def test_smoke_scrubs_environment_and_requires_readback(
    tmp_path: Path, source: Path, monkeypatch: pytest.MonkeyPatch, wrong_content: bool
) -> None:
    import mcp
    import mcp.client.stdio

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

        async def list_tools(self) -> object:
            return SimpleNamespace(
                tools=[
                    SimpleNamespace(
                        model_dump=lambda **_: {
                            "name": "read_file",
                            "inputSchema": {"type": "object"},
                        }
                    )
                ]
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
    if wrong_content:
        with pytest.raises(support.UpdateCheckError, match="読み戻し"):
            support.smoke(scratch, source)
    else:
        result = support.smoke(scratch, source)
        assert result["tool_count"] == 1
        assert len(result["tool_schema_sha256"]) == 64
    assert str(source / "src") in captured["parameters"].args[5].replace("\\\\", "\\")
    assert list(scratch.iterdir()) == []
