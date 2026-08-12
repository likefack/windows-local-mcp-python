from pathlib import Path

import pytest

import windows_local_mcp.policy as policy_module
from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import CommandPolicy


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
    values: dict[str, object] = {
        "workspace_root": root,
        "data_dir": data,
        "protect_data_dir_acl": False,
        "git_enabled": False,
        "flutter_enabled": False,
        "dart_enabled": False,
        "adb_enabled": False,
        "powershell_enabled": False,
    }
    values.update(overrides)
    settings = Settings(**values)
    settings.ensure_directories()
    return settings


def fake_which(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def resolve(program: str) -> str:
        executable = tmp_path / f"{Path(program).stem}.exe"
        executable.write_bytes(b"MZ fake")
        return str(executable)

    monkeypatch.setattr(policy_module.shutil, "which", resolve)


@pytest.mark.parametrize(
    ("program", "message"),
    [
        ("git", "git capability is disabled"),
        ("flutter", "flutter capability is disabled"),
        ("dart", "dart capability is disabled"),
        ("adb", "adb capability is disabled"),
        ("powershell", "PowerShell capability is disabled"),
        ("pwsh", "PowerShell capability is disabled"),
    ],
)
def test_disabled_capability_is_rejected_on_host_approval_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    program: str,
    message: str,
) -> None:
    settings = make_settings(tmp_path)
    fake_which(monkeypatch, tmp_path)
    policy = CommandPolicy(settings, Workspace(settings))

    with pytest.raises(PermissionError, match=message):
        policy.normalize_host(
            command=[program, "--version"],
            cwd=".",
            network_expected=False,
        )


@pytest.mark.parametrize(
    ("program", "setting_name", "expected_key"),
    [
        ("git", "git_enabled", "git"),
        ("flutter", "flutter_enabled", "flutter"),
        ("dart", "dart_enabled", "dart"),
        ("adb", "adb_enabled", "adb"),
        ("powershell", "powershell_enabled", "powershell"),
        ("pwsh", "powershell_enabled", "pwsh"),
    ],
)
def test_enabled_capability_remains_available_through_host_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    program: str,
    setting_name: str,
    expected_key: str,
) -> None:
    settings = make_settings(tmp_path, **{setting_name: True})
    fake_which(monkeypatch, tmp_path)
    policy = CommandPolicy(settings, Workspace(settings))

    normalized = policy.normalize_host(
        command=[program, "--version"],
        cwd=".",
        network_expected=False,
    )

    assert normalized.program_key == expected_key
    assert normalized.executable_identity is not None
    assert normalized.executable_identity["sha256"]


def test_unrelated_approved_program_is_not_blocked_by_disabled_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = make_settings(tmp_path)
    fake_which(monkeypatch, tmp_path)
    policy = CommandPolicy(settings, Workspace(settings))

    normalized = policy.normalize_host(
        command=["python", "-c", "print('ok')"],
        cwd=".",
        network_expected=False,
    )

    assert normalized.program_key == "python"
    assert normalized.executable_identity is not None
