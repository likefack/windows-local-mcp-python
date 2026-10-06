"""更新スクリプト専用の検証。既存の設定、監査、復旧状態は変更しない。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import itertools
import json
import ntpath
import os
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

MANIFEST_NAME = "update-manifest.json"
ROOT_FILES = frozenset({"pyproject.toml", "README.md", "config.example.toml"})
HELPER_PATH = "scripts/runtime_update_support.py"
# 現在の wheel に必要な非 Python リソースはない。追加時はここも明示更新する。
PACKAGE_RESOURCES: frozenset[str] = frozenset()
TERMINAL_STATUSES = frozenset(
    {
        "succeeded",
        "failed",
        "cancelled",
        "timed_out",
        "rejected",
        "expired",
        "interrupted",
        "conflict",
    }
)


class UpdateCheckError(RuntimeError):
    """パス、コマンドライン、設定値を含めずに表示できる診断。"""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _assert_no_reparse(path: Path) -> None:
    """resolve 前の各構成要素を検査し、junction を含めて traversal を拒否する。"""
    absolute = path.absolute()
    for part in reversed((absolute, *absolute.parents)):
        try:
            details = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode) or int(getattr(details, "st_file_attributes", 0)) & 0x400:
            raise UpdateCheckError("reparse point またはシンボリックリンクは使用できません。")


def _file_hash(path: Path) -> str:
    _assert_no_reparse(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise UpdateCheckError("通常ファイル以外の更新入力を検出しました。")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        held = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (held.st_dev, held.st_ino):
            raise UpdateCheckError("更新入力が読み取り中に変化しました。")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
        after_handle = os.fstat(stream.fileno())
    _assert_no_reparse(path)
    after = path.stat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after) or identity(before) != identity(after_handle):
        raise UpdateCheckError("更新入力が読み取り中に変化しました。")
    return hasher.hexdigest()


def _allowed(relative: str) -> bool:
    path = Path(relative)
    return (
        relative in ROOT_FILES
        or (len(path.parts) == 1 and path.suffix.lower() in {".ps1", ".bat"})
        or relative == HELPER_PATH
        or (
            relative.startswith("src/windows_local_mcp/")
            and (path.suffix == ".py" or relative in PACKAGE_RESOURCES)
            and not any(part.startswith(".") or part == "__pycache__" for part in path.parts)
        )
    )


def _walk_error(error: OSError) -> None:
    raise UpdateCheckError("更新検証対象のディレクトリを読み取れません。") from error


def _source_files(root: Path, *, strict: bool = False) -> dict[str, str]:
    _assert_no_reparse(root)
    if not root.is_dir():
        raise UpdateCheckError("更新元ディレクトリが存在しません。")
    candidates: list[Path] = []
    if strict:
        # snapshot は許可リスト外の追加ファイルも拒否する。
        for directory, children, names in os.walk(root, followlinks=False, onerror=_walk_error):
            for name in children:
                _assert_no_reparse(Path(directory) / name)
            for name in names:
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                if relative == MANIFEST_NAME:
                    continue
                if not _allowed(relative):
                    raise UpdateCheckError(
                        "snapshot に許可されていないファイルが追加されています。"
                    )
                candidates.append(path)
    else:
        candidates.extend(root / name for name in ROOT_FILES)
        candidates.extend(
            path for path in root.iterdir() if path.suffix.lower() in {".ps1", ".bat"}
        )
        candidates.append(root / HELPER_PATH)
        package = root / "src" / "windows_local_mcp"
        _assert_no_reparse(package)
        if not package.is_dir():
            raise UpdateCheckError("更新元の Python package が存在しません。")
        for directory, children, names in os.walk(package, followlinks=False, onerror=_walk_error):
            children[:] = [
                name for name in children if name != "__pycache__" and not name.startswith(".")
            ]
            for name in children:
                _assert_no_reparse(Path(directory) / name)
            for name in names:
                path = Path(directory) / name
                if _allowed(path.relative_to(root).as_posix()):
                    candidates.append(path)
    result = {path.relative_to(root).as_posix(): _file_hash(path) for path in candidates}
    if not (ROOT_FILES | {HELPER_PATH, "src/windows_local_mcp/__init__.py"}).issubset(result):
        raise UpdateCheckError("snapshot の必須ファイルが不足しています。")
    return dict(sorted(result.items()))


def snapshot(source: Path, destination: Path) -> dict[str, Any]:
    source, destination = source.absolute(), destination.absolute()
    _assert_no_reparse(destination)
    package_root = source / "src" / "windows_local_mcp"
    if destination == source or destination == package_root or package_root in destination.parents:
        raise UpdateCheckError("snapshot は収集対象の package 外に作成してください。")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise UpdateCheckError("snapshot の保存先は空のディレクトリにしてください。")
    before = _source_files(source)
    destination.mkdir(parents=True, exist_ok=True)
    for relative in before:
        target = destination / relative
        _assert_no_reparse(source / relative)
        _assert_no_reparse(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        # copyfile のみを使用し、更新元の ACL/owner を引き継がない。
        shutil.copyfile(source / relative, target)
    if _source_files(source) != before or _source_files(destination, strict=True) != before:
        raise UpdateCheckError("snapshot 作成中に更新入力が変化しました。")
    manifest = {"version": 1, "files": before}
    (destination / MANIFEST_NAME).write_bytes(canonical_json(manifest))
    return {"digest": _digest(manifest), "file_count": len(before)}


def verify(source: Path, digest: str) -> dict[str, Any]:
    source = source.absolute()
    manifest_path = source / MANIFEST_NAME
    _assert_no_reparse(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {"version", "files"}:
        raise UpdateCheckError("snapshot manifest の形式が不正です。")
    if manifest["version"] != 1 or not isinstance(manifest["files"], dict):
        raise UpdateCheckError("snapshot manifest の形式が不正です。")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", digest) or _digest(manifest) != digest.lower():
        raise UpdateCheckError("snapshot manifest の SHA-256 が一致しません。")
    if _source_files(source, strict=True) != manifest["files"]:
        raise UpdateCheckError("snapshot のファイル一覧または SHA-256 が一致しません。")
    return {"digest": _digest(manifest), "file_count": len(manifest["files"])}


def constraints(output: Path) -> dict[str, Any]:
    # pip 自身の vendored parser は追加依存を必要としない。
    from pip._vendor.packaging.version import InvalidVersion, Version

    pins: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name", "")
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
            raise UpdateCheckError("インストール済み依存パッケージ名が不正です。")
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized == "windows-local-mcp":
            continue
        if distribution.read_text("direct_url.json") is not None:
            raise UpdateCheckError("URL または editable 由来の依存パッケージは自動更新できません。")
        version = distribution.version
        try:
            parsed = Version(version)
        except (InvalidVersion, TypeError):
            raise UpdateCheckError(
                "インストール済み依存パッケージの version が不正です。"
            ) from None
        if not version or version != version.strip() or any(char.isspace() for char in version):
            raise UpdateCheckError("インストール済み依存パッケージの version が不正です。")
        normalized_version = str(parsed)
        if normalized in pins and pins[normalized] != normalized_version:
            raise UpdateCheckError("同じ依存パッケージに異なる version が記録されています。")
        pins[normalized] = normalized_version
    if "pip" not in pins:
        raise UpdateCheckError("既存 runtime の pip version を確認できません。")
    _assert_no_reparse(output)
    output.write_text(
        "".join(f"{name}=={version}\n" for name, version in sorted(pins.items())), encoding="utf-8"
    )
    return {"package_count": len(pins), "pip_version": pins["pip"]}


def _windows_path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value))


def _same_path(value: str, expected: Path | str) -> bool:
    return ntpath.isabs(value) and _windows_path(value) == _windows_path(str(expected))


def _under_root(value: str, root: Path | str) -> bool:
    if not value or not ntpath.isabs(value):
        return False
    try:
        return ntpath.commonpath([_windows_path(value), _windows_path(str(root))]) == _windows_path(
            str(root)
        )
    except ValueError:
        return False


def process_matches(
    executable: str,
    arguments: list[str],
    *,
    install_root: Path,
    launcher_root: Path,
    config: Path,
    profile: Path | None = None,
) -> bool:
    """引数単位の完全一致のみを使い、類似名の別環境を巻き込まない。"""
    if _under_root(executable, install_root):
        return True
    wrappers = [install_root / name for name in ("run-server.ps1", "run-approvals.ps1")]
    wrappers.append(launcher_root / "run-localmcp.ps1")
    if any(_same_path(argument, wrapper) for argument in arguments for wrapper in wrappers):
        return True
    modules = {
        "windows_local_mcp.cli",
        "windows_local_mcp.approval_ui",
        "windows_local_mcp.activity_monitor",
        "windows_local_mcp.worker",
    }
    if any(argument in modules for argument in arguments) and any(
        _same_path(argument, config) for argument in arguments
    ):
        return True
    if profile is not None and ntpath.basename(executable).casefold() in {
        "tunnel-client",
        "tunnel-client.exe",
    }:
        for index, argument in enumerate(arguments):
            if (
                argument == "--profile-file"
                and index + 1 < len(arguments)
                and _same_path(arguments[index + 1], profile)
            ):
                return True
            if argument.startswith("--profile-file=") and _same_path(
                argument.split("=", 1)[1], profile
            ):
                return True
    return False


def _authority_service_pid() -> int:
    """QUERY_STATUS のみを使う。service 停止後の再検査では除外 PID を返さない。"""
    import ctypes
    from ctypes import wintypes

    from windows_local_mcp import approved_host_authority as authority_api

    if os.name != "nt":
        raise UpdateCheckError("Approved Host service の確認には Windows が必要です。")
    api = authority_api._advapi32
    manager = api.OpenSCManagerW(None, None, authority_api._SC_MANAGER_CONNECT)
    if not manager:
        raise UpdateCheckError("Approved Host service の状態を確認できません。")
    service = None
    try:
        # psutil.win_service_get は内部で QUERY_CONFIG も要求するため使用しない。
        service = api.OpenServiceW(
            manager,
            authority_api.APPROVED_HOST_AUTHORITY_SERVICE_NAME,
            authority_api._SERVICE_QUERY_STATUS,
        )
        if not service:
            raise UpdateCheckError("Approved Host service の状態を確認できません。")
        status = authority_api._SERVICE_STATUS_PROCESS()
        needed = wintypes.DWORD()
        if not api.QueryServiceStatusEx(
            service,
            authority_api._SC_STATUS_PROCESS_INFO,
            ctypes.byref(status),
            ctypes.sizeof(status),
            ctypes.byref(needed),
        ):
            raise UpdateCheckError("Approved Host service の状態を確認できません。")
        if status.dwCurrentState == authority_api._SERVICE_RUNNING and status.dwProcessId > 0:
            return int(status.dwProcessId)
        if status.dwCurrentState == 1 and status.dwProcessId == 0:  # SERVICE_STOPPED
            return 0
        raise UpdateCheckError("Approved Host service が状態遷移中です。")
    finally:
        if service:
            api.CloseServiceHandle(service)
        api.CloseServiceHandle(manager)


def assert_no_runtime_processes(
    *,
    install_root: Path,
    launcher_root: Path,
    config: Path,
    profile: Path | None = None,
) -> int:
    import psutil

    current_process = psutil.Process()
    current_user = current_process.username().casefold()
    launcher_identity: tuple[int, float] | None = None
    base_executable = getattr(sys, "_base_executable", None)
    if (
        os.name == "nt"
        and isinstance(base_executable, str)
        and not _same_path(sys.executable, base_executable)
    ):
        try:
            # Windows venv は起動用 python.exe が即親として残る。実行ファイル、
            # 引数列、起動順を確認できたその一個だけを、自分の起動処理として扱う。
            parent = current_process.parent()
            if (
                parent is not None
                and _same_path(parent.exe(), sys.executable)
                and _same_path(current_process.exe(), base_executable)
            ):
                current_arguments = current_process.cmdline()
                parent_created = parent.create_time()
                if (
                    current_arguments
                    and current_arguments == parent.cmdline()
                    and 0 < parent_created <= current_process.create_time()
                    and current_process.ppid() == parent.pid
                    and parent.is_running()
                ):
                    launcher_identity = (parent.pid, parent_created)
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            # 証拠を取得できない親は除外せず、通常の対象プロセス検査へ回す。
            pass
    # service 本体は停止前検査でも常駐する。PS 側が service executable と
    # install_root の binding を別途確認する前提で、SCM が返す当該 PID を除外する。
    service_pid = _authority_service_pid()
    if not isinstance(service_pid, int) or service_pid < 0:
        raise UpdateCheckError("Approved Host service の PID を確認できません。")
    service_launcher_identity: tuple[int, float, float] | None = None
    if os.name == "nt" and service_pid > 0 and isinstance(base_executable, str):
        try:
            service_process = psutil.Process(service_pid)
            service_parent = service_process.parent()
            if (
                service_parent is not None
                and _same_path(service_process.exe(), base_executable)
                and _same_path(
                    service_parent.exe(), install_root / "runtime" / "Scripts" / "python.exe"
                )
            ):
                parent_created = service_parent.create_time()
                service_created = service_process.create_time()
                if (
                    0 < parent_created <= service_created
                    and service_process.ppid() == service_parent.pid
                    and service_process.is_running()
                    and service_parent.is_running()
                ):
                    # SYSTEM の引数列・username は通常ユーザーから取得できない。
                    # SCM が指定した本体の即親だけを実行ファイルと生成時刻に束縛する。
                    service_launcher_identity = (
                        service_parent.pid,
                        parent_created,
                        service_created,
                    )
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            # worker や未確認の ancestor をまとめて除外してはならない。
            pass
    checked = 0
    for process in psutil.process_iter(
        ["pid", "name", "exe", "cmdline", "username"], ad_value=None
    ):
        if process.pid == os.getpid() or (service_pid > 0 and process.pid == service_pid):
            continue
        try:
            if (
                launcher_identity is not None
                and process.pid == launcher_identity[0]
                and process.create_time() == launcher_identity[1]
                and process.is_running()
            ):
                # 列挙時にも作成時刻を照合し、再利用された同じ PID は除外しない。
                continue
            if (
                service_launcher_identity is not None
                and process.pid == service_launcher_identity[0]
                and process.create_time() == service_launcher_identity[1]
                and process.is_running()
            ):
                try:
                    # 本体側の PID 再利用・終了・親の変化も列挙時に検出する。
                    service_now = psutil.Process(service_pid)
                    if (
                        service_now.create_time() == service_launcher_identity[2]
                        and service_now.ppid() == process.pid
                        and service_now.is_running()
                    ):
                        continue
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    # 本体の消滅で、まだ生きている親の通常検査を飛ばさない。
                    pass
            info = process.info
            name = str(info.get("name") or "").casefold()
            executable = info.get("exe")
            arguments = info.get("cmdline")
            if process_matches(
                executable or "",
                arguments or [],
                install_root=install_root,
                launcher_root=launcher_root,
                config=config,
                profile=profile,
            ):
                raise UpdateCheckError(
                    "対象 runtime または launcher が起動中です。終了してから再実行してください。"
                )
            # 他ユーザーの SYSTEM process を一律に拒否しない。現在ユーザーの
            # 関連実行形式について所属を判定できなければ、安全に更新を中止する。
            relevant = name in {
                "python",
                "python.exe",
                "pythonw.exe",
                "powershell.exe",
                "pwsh.exe",
                "tunnel-client",
                "tunnel-client.exe",
            }
            owner = str(info.get("username") or "").casefold()
            if (
                relevant
                and (executable is None or arguments is None)
                and owner in {"", current_user}
            ):
                raise UpdateCheckError("対象となり得るプロセスの所属を確認できません。")
            checked += 1
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            raise UpdateCheckError("プロセスの所属を確認できません。") from None
    return checked


def audit_nonterminal_count(database: Path) -> int:
    _assert_no_reparse(database)
    if not database.exists():
        return 0
    # AuditStore は起動時に状態回復や prune を行うため、ここでは使用しない。
    with sqlite3.connect(
        database.absolute().as_uri() + "?mode=ro", uri=True, timeout=2
    ) as connection:
        placeholders = ",".join("?" for _ in TERMINAL_STATUSES)
        row = connection.execute(
            f"SELECT COUNT(*) FROM operations WHERE status IS NULL OR status NOT IN ({placeholders})",
            sorted(TERMINAL_STATUSES),
        ).fetchone()
    return int(row[0])


def idle(config: Path) -> dict[str, Any]:
    """サーバー終了前に処理・復旧状態だけを読み取り確認する。"""
    from windows_local_mcp.config import validate_configuration_candidate
    from windows_local_mcp.workspace_history import workspace_recovery_required

    _assert_no_reparse(config)
    settings = validate_configuration_candidate(config, final_config_path=config)
    _assert_no_reparse(settings.data_dir)
    for marker in ("tamper-detected.json", "approved-host-postflight-pending.json"):
        path = settings.data_dir / "control-plane" / marker
        _assert_no_reparse(path)
        if path.exists():
            raise UpdateCheckError("改変検出または Approved Host の事後検証待ちが残っています。")
    history = settings.data_dir / "workspace-history" / "transactions"
    _assert_no_reparse(history)
    if history.exists():
        for directory, children, files in os.walk(history, followlinks=False, onerror=_walk_error):
            for name in [*children, *files]:
                _assert_no_reparse(Path(directory) / name)
    if workspace_recovery_required(settings):
        raise UpdateCheckError("workspace の復旧待ちが残っています。")
    if audit_nonterminal_count(settings.data_dir / "audit.db"):
        raise UpdateCheckError("監査DBに未完了の処理が残っています。")
    return {
        "data_dir": str(settings.data_dir),
        "workspace_root": str(settings.workspace_root),
        "nonterminal_count": 0,
    }


def offline(
    config: Path, install_root: Path, launcher_root: Path, profile: Path | None = None
) -> dict[str, Any]:
    result = idle(config)
    checked = assert_no_runtime_processes(
        install_root=install_root, launcher_root=launcher_root, config=config, profile=profile
    )
    return {**result, "checked_process_count": checked}


def _approval_process_chain(process: Any, install_root: Path, config: Path) -> list[Any]:
    """設定が明示された専用 PowerShell と、直接起動した承認 UI だけを認める。"""
    import psutil

    try:
        executable = str(install_root / "runtime" / "Scripts" / "python.exe")
        expected = [executable, "-I", "-B", "-m", "windows_local_mcp.cli", "approvals"]
        # 他プロセスの引数読み取りは高コストになり得るため、実行ファイルで先に絞る。
        if not _same_path(process.exe(), executable):
            return []
        arguments = process.cmdline()
        if (
            not arguments
            or not _same_path(arguments[0], executable)
            or arguments[1:] != expected[1:]
        ):
            return []
        wrapper = process.parent()
        if wrapper is None:
            return []
        powershell = ntpath.join(
            os.environ.get("SystemRoot", "C:\\Windows"),
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe",
        )
        if not _same_path(wrapper.exe(), powershell):
            return []
        args = wrapper.cmdline()
        if (
            len(args) != 8
            or not _same_path(args[0], powershell)
            or [item.casefold() for item in args[1:5]]
            != ["-noprofile", "-executionpolicy", "bypass", "-file"]
            or not _same_path(args[5], install_root / "run-approvals.ps1")
            or args[6].casefold() != "-config"
            or not _same_path(args[7], config)
        ):
            return []
        chain = [wrapper, process]
        children = process.children()
        if len(children) != 1:
            return []
        child = children[0]
        base = getattr(sys, "_base_executable", "")
        if not base or not _same_path(child.exe(), base) or child.cmdline() != arguments:
            return []
        chain.append(child)
        user = psutil.Process().username().casefold()
        if any(item.username().casefold() != user or not item.is_running() for item in chain):
            return []
        for parent, descendant in itertools.pairwise(chain):
            if descendant.ppid() != parent.pid or not (
                0 < parent.create_time() <= descendant.create_time()
            ):
                return []
        return chain
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return []


def _interrupt_approval_console(chain: list[Any], recheck: Any) -> None:
    """専用コンソールに Ctrl+C を通知する。共有コンソールと強制終了は使わない。"""
    import ctypes
    from ctypes import wintypes

    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.FreeConsole.argtypes, api.FreeConsole.restype = [], wintypes.BOOL
    api.AttachConsole.argtypes, api.AttachConsole.restype = [wintypes.DWORD], wintypes.BOOL
    api.GetConsoleProcessList.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    api.GetConsoleProcessList.restype = wintypes.DWORD
    api.SetConsoleCtrlHandler.argtypes = [ctypes.c_void_p, wintypes.BOOL]
    api.SetConsoleCtrlHandler.restype = wintypes.BOOL
    api.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
    api.GenerateConsoleCtrlEvent.restype = wintypes.BOOL
    api.FreeConsole()
    if not api.AttachConsole(chain[0].pid):
        raise UpdateCheckError("承認UIの専用コンソールに接続できません。")
    try:
        # AttachConsole はハンドラを初期化するため、接続後に自身の無視を設定する。
        if not api.SetConsoleCtrlHandler(None, True):
            raise UpdateCheckError("承認UIの終了通知を準備できません。")
        recheck()
        pids = (wintypes.DWORD * 64)()
        count = api.GetConsoleProcessList(pids, len(pids))
        expected = {item.pid for item in chain} | {os.getpid()}
        if not count or count > len(pids) or set(pids[:count]) != expected:
            raise UpdateCheckError("承認UIのコンソールを他の処理が共有しているため終了できません。")
        if not api.GenerateConsoleCtrlEvent(0, 0):
            raise UpdateCheckError("承認UIへ通常終了を通知できません。")
    finally:
        # 呼び出し元のパイプは保持するが、別コンソールへ通知が漏れないよう離脱する。
        api.FreeConsole()


def close_ui(config: Path, install_root: Path) -> dict[str, Any]:
    import psutil

    if os.name != "nt":
        raise UpdateCheckError("承認UIの通常終了には Windows が必要です。")
    authority()
    idle(config)
    notified = 0
    for process in psutil.process_iter():
        chain = _approval_process_chain(process, install_root, config)
        if not chain:
            continue
        identities = [(item.pid, item.create_time()) for item in chain]

        def recheck(process: Any = process, identities: list = identities) -> None:
            # 通知直前にも承認待ち・復旧状態と PID 再利用を再確認する。
            authority()
            idle(config)
            current = _approval_process_chain(process, install_root, config)
            if [(item.pid, item.create_time()) for item in current] != identities:
                raise UpdateCheckError("承認UIの所属が終了通知前に変化しました。")

        _interrupt_approval_console(chain, recheck)
        _, alive = psutil.wait_procs(chain, timeout=10)
        if alive:
            raise UpdateCheckError("承認UIの通常終了が完了しませんでした。強制終了は行いません。")
        notified += 1
    return {"closed_approval_ui_count": notified}


def smoke(scratch: Path, source: Path | None = None) -> dict[str, Any]:
    import anyio
    from mcp import Client, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from windows_local_mcp.approved_host_policy import (
        _authority_service_installed,
        assert_approved_host_authority_available,
    )

    # 一時設定でも導入済み監視サービスの健全性保証は維持する。
    # 停止中なら MCP の匿名化された tool error に埋もれる前に原因を案内する。
    if _authority_service_installed():
        try:
            assert_approved_host_authority_available()
        except Exception as error:
            raise UpdateCheckError(
                "Approved Host 監視サービスに接続できないか、正常な状態ではありません。"
                "WindowsLocalMCPApprovedHost の起動状態と復旧状態を確認してください。"
            ) from error

    _assert_no_reparse(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    if source is not None:
        source = source.absolute()
        _assert_no_reparse(source / "src" / "windows_local_mcp")
    # ログは本番設定を含めず、作成する一時領域も指定 SCRATCH 内に限定する。
    with tempfile.TemporaryDirectory(prefix="runtime-smoke-", dir=scratch) as directory:
        root = Path(directory)
        workspace = root / "workspace"
        workspace.mkdir()
        # read_file returns the requested lines without a trailing newline.
        expected = "Windows Local MCP update read-back: 日本語"
        (workspace / "readback.txt").write_text(expected, encoding="utf-8")
        config = root / "config.toml"
        config.write_text(
            "\n".join(
                [
                    f"workspace_root = {json.dumps(str(workspace), ensure_ascii=False)}",
                    f"data_dir = {json.dumps(str(root / 'data'), ensure_ascii=False)}",
                    f"sandbox_scratch_dir = {json.dumps(str(root / 'sandbox'), ensure_ascii=False)}",
                    "protect_data_dir_acl = false",
                    "git_enabled = false",
                    "approved_host_enabled = false",
                    "approved_sandbox_enabled = false",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith(("LOCAL_MCP_", "PYTHON"))
        }
        environment.update(LOCAL_MCP_CONFIG=str(config), LOCAL_MCP_TRANSPORT="stdio")
        bootstrap = "from windows_local_mcp.cli import main; main()"
        if source is not None:
            bootstrap = f"import sys; sys.path.insert(0, {str(source / 'src')!r}); " + bootstrap
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-I", "-B", "-X", "utf8", "-c", bootstrap, "server"],
            env=environment,
            cwd=str(root),
        )

        async def exercise() -> dict[str, Any]:
            with anyio.fail_after(60):
                async with Client(stdio_client(parameters, errlog=errors)) as client:
                    listing = await client.list_tools()
                    tools = list(listing.tools)
                    cursors: set[str] = set()
                    while getattr(listing, "next_cursor", None):
                        cursor = listing.next_cursor
                        if cursor in cursors:
                            raise UpdateCheckError("MCP tool 一覧のページ送りが循環しています。")
                        cursors.add(cursor)
                        listing = await client.list_tools(cursor=cursor)
                        tools.extend(listing.tools)
                    schemas = sorted(
                        (tool.model_dump(mode="json", by_alias=True) for tool in tools),
                        key=lambda tool: tool["name"],
                    )
                    if not any(tool["name"] == "read_file" for tool in schemas):
                        raise UpdateCheckError("MCP tool 一覧に read_file がありません。")
                    result = await client.call_tool("read_file", {"path": "readback.txt"})
                    if (
                        result.is_error
                        or not isinstance(result.structured_content, dict)
                        or result.structured_content.get("content") != expected
                    ):
                        raise UpdateCheckError("MCP read_file の読み戻しが一致しません。")
                    return {"tool_count": len(schemas), "tool_schema_sha256": _digest(schemas)}

        with open(os.devnull, "w", encoding="utf-8") as errors:
            return anyio.run(exercise)


def authority() -> dict[str, Any]:
    from windows_local_mcp.approved_host_policy import (
        assert_approved_host_authority_available,
        verify_approved_host_runtime_immutability_only,
    )
    from windows_local_mcp.approved_host_service import _process_token_details

    if os.name != "nt" or _process_token_details(os.getpid())[1]:
        raise UpdateCheckError(
            "Approved Host の事前検証は通常の非昇格 Windows ユーザーで実行してください。"
        )
    verify_approved_host_runtime_immutability_only()
    assert_approved_host_authority_available()
    return {"runtime_immutable": True, "authority_available": True, "preflight_only": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot_parser = commands.add_parser("snapshot")
    snapshot_parser.add_argument("--source", type=Path, required=True)
    snapshot_parser.add_argument("--destination", type=Path, required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--source", type=Path, required=True)
    verify_parser.add_argument("--digest", required=True)
    constraints_parser = commands.add_parser("constraints")
    constraints_parser.add_argument("--output", type=Path, required=True)
    offline_parser = commands.add_parser("offline")
    for option in ("config", "install-root", "launcher-root"):
        offline_parser.add_argument(f"--{option}", type=Path, required=True)
    offline_parser.add_argument("--profile", type=Path)
    idle_parser = commands.add_parser("idle")
    idle_parser.add_argument("--config", type=Path, required=True)
    close_ui_parser = commands.add_parser("close-ui")
    close_ui_parser.add_argument("--config", type=Path, required=True)
    close_ui_parser.add_argument("--install-root", type=Path, required=True)
    smoke_parser = commands.add_parser("smoke")
    smoke_parser.add_argument("--scratch", type=Path, required=True)
    smoke_parser.add_argument("--source", type=Path)
    commands.add_parser("authority")
    arguments = vars(parser.parse_args(argv))
    command = arguments.pop("command")
    try:
        result = globals()[command.replace("-", "_")](**arguments)
    except UpdateCheckError as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except Exception as error:  # noqa: BLE001 -- CLI 境界で例外内の秘密情報を出力しない。
        # ライブラリ例外は入力や秘密情報を含み得るため型名だけを返す。
        details: dict[str, Any] = {}
        if isinstance(error, BaseExceptionGroup):
            # TaskGroup は検査自身の安全な診断も包むため、有限個の末端を取り出す。
            pending: list[BaseException] = [error]
            leaves: list[BaseException] = []
            for _ in range(64):
                if not pending or len(leaves) >= 8:
                    break
                item = pending.pop()
                if isinstance(item, BaseExceptionGroup):
                    pending.extend(item.exceptions[:8])
                else:
                    leaves.append(item)
            details["cause_types"] = sorted({type(item).__name__ for item in leaves})
            checks = [str(item) for item in leaves if isinstance(item, UpdateCheckError)]
            if checks:
                details["check_errors"] = checks
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "更新検証を完了できませんでした。",
                    "error_type": type(error).__name__,
                    **details,
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
