from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import CommandPolicy


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
    settings = Settings(
        workspace_root=root,
        data_dir=data,
        protect_data_dir_acl=False,
        **overrides,
    )
    settings.ensure_directories()
    return settings


@pytest.fixture
def fake_tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"MZ fake")
    monkeypatch.setattr(
        CommandPolicy,
        "_resolve_executable",
        staticmethod(lambda _candidates: str(executable)),
    )
    return executable


def test_rejects_unknown_program(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError):
        policy.normalize_safe(program="python", args=["-c", "print(1)"], cwd=".")


def test_rejects_git_push_before_executable_lookup(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError):
        policy.normalize_safe(program="git", args=["push"], cwd=".")


@pytest.mark.parametrize(
    "args",
    [
        ["diff", "--output=../outside.txt"],
        ["diff", "--ext-diff"],
        ["status", "--work-tree=.."],
        ["log", "--config-env=x=y"],
        ["rev-parse", "--git-path", "config"],
    ],
)
def test_rejects_dangerous_git_options(
    tmp_path: Path, fake_tools: Path, args: list[str]
) -> None:
    settings = make_settings(tmp_path)
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError):
        policy.normalize_safe(program="git", args=args, cwd=".")


def test_git_status_and_workspace_pathspec_remain_automatic(
    tmp_path: Path, fake_tools: Path
) -> None:
    settings = make_settings(tmp_path)
    (settings.workspace_root / ".git").mkdir()
    source = settings.workspace_root / "src"
    source.mkdir()
    policy = CommandPolicy(settings, Workspace(settings))
    status = policy.normalize_safe(program="git", args=["status", "--short"], cwd=".")
    diff = policy.normalize_safe(
        program="git", args=["diff", "--name-only", "--", "src"], cwd="."
    )
    log = policy.normalize_safe(program="git", args=["log", "-10", "--patch"], cwd=".")
    assert status.args[:2] == ["--no-pager", "status"]
    assert "--no-ext-diff" in diff.args
    assert "--no-textconv" in diff.args
    assert "--no-ext-diff" in log.args
    assert "--no-textconv" in log.args
    assert str(source.resolve()) in diff.args


def test_automatic_git_requires_workspace_root_marker(
    tmp_path: Path, fake_tools: Path
) -> None:
    settings = make_settings(tmp_path)
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError, match="workspace_root itself"):
        policy.normalize_safe(program="git", args=["status", "--short"], cwd=".")


def test_automatic_tool_cannot_be_loaded_from_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = make_settings(tmp_path, dart_enabled=True)
    executable = settings.workspace_root / "dart.exe"
    executable.write_bytes(b"MZ fake")
    monkeypatch.setattr(
        CommandPolicy,
        "_resolve_executable",
        staticmethod(lambda _candidates: str(executable)),
    )
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError, match="must not be loaded from the workspace"):
        policy.normalize_safe(program="dart", args=["analyze"], cwd=".")


def test_git_pathspec_cannot_escape_workspace(tmp_path: Path, fake_tools: Path) -> None:
    settings = make_settings(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError):
        policy.normalize_safe(
            program="git", args=["diff", "--", "../outside.txt"], cwd="."
        )


@pytest.mark.parametrize("subcommand", ["test", "build", "run"])
def test_flutter_code_loading_requires_approval(
    tmp_path: Path, fake_tools: Path, subcommand: str
) -> None:
    settings = make_settings(tmp_path, flutter_enabled=True)
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError, match="requires approval"):
        policy.normalize_safe(program="flutter", args=[subcommand], cwd=".")


def test_flutter_analyze_forces_no_pub_and_validates_path(
    tmp_path: Path, fake_tools: Path
) -> None:
    settings = make_settings(tmp_path, flutter_enabled=True)
    app = settings.workspace_root / "app"
    app.mkdir()
    policy = CommandPolicy(settings, Workspace(settings))
    command = policy.normalize_safe(program="flutter", args=["analyze", "app"], cwd=".")
    assert command.args[:2] == ["analyze", "--no-pub"]
    with pytest.raises(PermissionError):
        policy.normalize_safe(program="flutter", args=["analyze", ".."], cwd=".")


def test_dart_test_and_external_format_are_rejected(
    tmp_path: Path, fake_tools: Path
) -> None:
    settings = make_settings(tmp_path, dart_enabled=True)
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError, match="requires human approval"):
        policy.normalize_safe(program="dart", args=["test"], cwd=".")
    with pytest.raises(PermissionError):
        policy.normalize_safe(program="dart", args=["format", ".."], cwd=".")


def test_dart_format_inside_workspace_remains_automatic(
    tmp_path: Path, fake_tools: Path
) -> None:
    settings = make_settings(tmp_path, dart_enabled=True)
    source = settings.workspace_root / "lib"
    source.mkdir()
    policy = CommandPolicy(settings, Workspace(settings))
    command = policy.normalize_safe(program="dart", args=["format", "lib"], cwd=".")
    assert command.args == ["format", str(source.resolve())]


@pytest.mark.parametrize(
    "args",
    [
        ["-s", "emulator-5554", "shell", "input", "tap", "1", "2"],
        ["-s", "emulator-5554", "shell", "pm", "clear", "example.app"],
        ["-s", "emulator-5554", "install", "app.apk"],
        ["shell", "dumpsys", "battery"],
    ],
)
def test_rejects_generic_or_destructive_adb(
    tmp_path: Path, fake_tools: Path, args: list[str]
) -> None:
    settings = make_settings(tmp_path, adb_enabled=True)
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError):
        policy.normalize_safe(program="adb", args=args, cwd=".")


def test_adb_emulator_read_and_screenshot_remain_automatic(
    tmp_path: Path, fake_tools: Path
) -> None:
    settings = make_settings(
        tmp_path,
        adb_enabled=True,
        adb_allowed_serials=["emulator-5554"],
    )
    policy = CommandPolicy(settings, Workspace(settings))
    battery = policy.normalize_safe(
        program="adb",
        args=["-s", "emulator-5554", "shell", "dumpsys", "battery"],
        cwd=".",
    )
    screenshot = policy.normalize_safe(
        program="adb",
        args=["-s", "emulator-5554", "exec-out", "screencap", "-p"],
        cwd=".",
    )
    assert battery.args[-3:] == ["shell", "dumpsys", "battery"]
    assert screenshot.args[-3:] == ["exec-out", "screencap", "-p"]


def test_adb_physical_and_unlisted_serial_are_rejected(
    tmp_path: Path, fake_tools: Path
) -> None:
    settings = make_settings(
        tmp_path,
        adb_enabled=True,
        adb_allowed_serials=["emulator-5554"],
    )
    policy = CommandPolicy(settings, Workspace(settings))
    with pytest.raises(PermissionError):
        policy.normalize_safe(
            program="adb", args=["-s", "R58M123", "get-state"], cwd="."
        )
    with pytest.raises(PermissionError):
        policy.normalize_safe(
            program="adb", args=["-s", "emulator-5556", "get-state"], cwd="."
        )
