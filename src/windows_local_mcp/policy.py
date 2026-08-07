from __future__ import annotations

import shutil
from pathlib import Path
from typing import Sequence

from pydantic import BaseModel

from .config import Settings
from .paths import Workspace
from .util import canonical_json, sha256_text


class NormalizedCommand(BaseModel):
    executable: str
    args: list[str]
    cwd: str
    display_command: list[str]
    program_key: str
    network_expected: bool = False


class CommandPolicy:
    GIT_ALLOWED = {"status", "diff", "log", "show", "rev-parse", "ls-files", "grep"}
    FLUTTER_ALLOWED = {"analyze", "test", "build", "doctor", "devices"}
    DART_ALLOWED = {"analyze", "format", "test"}
    ADB_ALLOWED = {"devices", "get-state", "shell", "exec-out"}
    ADB_SHELL_ALLOWED = {"input", "am", "pm", "wm", "dumpsys", "screencap"}

    def __init__(self, settings: Settings, workspace: Workspace) -> None:
        self.settings = settings
        self.workspace = workspace
        self.safe_scripts = {
            self.workspace.resolve_existing(item, allow_directory=False)
            for item in settings.safe_powershell_scripts
        }

    @staticmethod
    def _reject_nul(values: Sequence[str]) -> None:
        for value in values:
            if "\x00" in value:
                raise ValueError("NUL文字を含む引数を拒否しました")

    @staticmethod
    def _resolve_executable(candidates: Sequence[str]) -> str:
        for candidate in candidates:
            resolved = shutil.which(candidate)
            if resolved:
                return str(Path(resolved).resolve())
        raise FileNotFoundError(f"実行ファイルがPATHに見つかりません: {', '.join(candidates)}")

    def normalize_safe(
        self,
        *,
        program: str,
        args: list[str],
        cwd: str,
    ) -> NormalizedCommand:
        if not args:
            raise ValueError("サブコマンドまたは引数が必要です")
        self._reject_nul([program, *args])
        cwd_path = self.workspace.resolve_directory(cwd)
        key = program.casefold()
        for suffix in (".exe", ".bat", ".cmd"):
            if key.endswith(suffix):
                key = key[: -len(suffix)]

        if key == "git":
            if args[0].casefold() not in self.GIT_ALLOWED:
                raise PermissionError(f"git {args[0]} は通常実行で許可されていません")
            executable = self._resolve_executable(("git.exe", "git"))
            return self._result(executable, args, cwd_path, "git")

        if key == "flutter":
            if args[0].casefold() not in self.FLUTTER_ALLOWED:
                raise PermissionError(f"flutter {args[0]} は通常実行で許可されていません")
            executable = self._resolve_executable(("flutter.bat", "flutter.cmd", "flutter"))
            return self._result(executable, args, cwd_path, "flutter")

        if key == "dart":
            if args[0].casefold() not in self.DART_ALLOWED:
                raise PermissionError(f"dart {args[0]} は通常実行で許可されていません")
            executable = self._resolve_executable(("dart.exe", "dart"))
            return self._result(executable, args, cwd_path, "dart")

        if key == "adb":
            self._validate_adb(args)
            executable = self._resolve_executable(("adb.exe", "adb"))
            return self._result(executable, args, cwd_path, "adb")

        if key in {"powershell", "powershell_script", "pwsh"}:
            return self._normalize_safe_powershell(args, cwd_path)

        raise PermissionError(
            f"{program} は通常実行の許可リストにありません。"
            "request_host_commandを使用してください"
        )

    def normalize_host(
        self,
        *,
        command: list[str],
        cwd: str,
        network_expected: bool,
    ) -> NormalizedCommand:
        if not command:
            raise ValueError("commandは1要素以上必要です")
        self._reject_nul(command)
        cwd_path = self.workspace.resolve_directory(cwd)
        executable = shutil.which(command[0])
        if executable is None:
            candidate = Path(command[0]).expanduser()
            if candidate.exists():
                executable = str(candidate.resolve())
            else:
                raise FileNotFoundError(f"実行ファイルが見つかりません: {command[0]}")
        return NormalizedCommand(
            executable=str(Path(executable).resolve()),
            args=list(command[1:]),
            cwd=str(cwd_path),
            display_command=list(command),
            program_key=Path(executable).stem.casefold(),
            network_expected=network_expected,
        )

    def _validate_adb(self, args: list[str]) -> None:
        first = args[0].casefold()
        if first not in self.ADB_ALLOWED:
            raise PermissionError(f"adb {args[0]} は通常実行で許可されていません")
        if first == "exec-out":
            if [part.casefold() for part in args[1:]] != ["screencap", "-p"]:
                raise PermissionError("adb exec-outは screencap -p のみ許可しています")
        if first == "shell":
            if len(args) < 2 or args[1].casefold() not in self.ADB_SHELL_ALLOWED:
                raise PermissionError(
                    "adb shellは input/am/pm/wm/dumpsys/screencap のみ許可しています"
                )

    def _normalize_safe_powershell(
        self,
        args: list[str],
        cwd_path: Path,
    ) -> NormalizedCommand:
        folded = [item.casefold() for item in args]
        if "-command" in folded or "-c" in folded or "-encodedcommand" in folded:
            raise PermissionError("任意PowerShellコードは承認付き経路を使用してください")

        try:
            file_index = folded.index("-file")
        except ValueError as error:
            raise PermissionError(
                "通常PowerShellは -File で明示済みスクリプトを呼ぶ場合だけ許可します"
            ) from error

        if file_index + 1 >= len(args):
            raise ValueError("-Fileの後にスクリプトパスが必要です")

        script = self.workspace.resolve_existing(args[file_index + 1], allow_directory=False)
        if script not in self.safe_scripts:
            raise PermissionError(
                f"安全スクリプトとして登録されていません: {self.workspace.relative(script)}"
            )

        normalized_args = list(args)
        normalized_args[file_index + 1] = str(script)
        executable = self._resolve_executable(("powershell.exe", "pwsh.exe", "pwsh"))
        return self._result(executable, normalized_args, cwd_path, "powershell_script")

    @staticmethod
    def _result(
        executable: str,
        args: list[str],
        cwd: Path,
        program_key: str,
    ) -> NormalizedCommand:
        return NormalizedCommand(
            executable=executable,
            args=args,
            cwd=str(cwd),
            display_command=[executable, *args],
            program_key=program_key,
            network_expected=False,
        )


def approval_hash(
    *,
    normalized: NormalizedCommand,
    reason: str,
    risk_summary: str,
) -> str:
    payload = {
        "executable": normalized.executable,
        "args": normalized.args,
        "cwd": normalized.cwd,
        "network_expected": normalized.network_expected,
        "reason": reason,
        "risk_summary": risk_summary,
    }
    return sha256_text(canonical_json(payload))
