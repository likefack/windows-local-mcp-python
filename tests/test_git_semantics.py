import shutil
import subprocess
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.git_broker_sandbox import (
    GitBrokerUnavailable,
    _safe_repository_config,
    stage_git_repository,
)
from windows_local_mcp.git_semantics import (
    GitSemanticConfigUnavailable,
    normalize_core_autocrlf,
    resolve_trusted_core_autocrlf,
)


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
    )
    settings.ensure_directories()
    return settings


def _identity(tmp_path: Path) -> tuple[dict[str, object], Path]:
    install_root = tmp_path / "Git"
    executable = install_root / "mingw64" / "bin" / "git.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"git")
    return {"path": str(executable.resolve())}, install_root


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("true", "true"),
        ("YES", "true"),
        ("1", "true"),
        ("false", "false"),
        ("off", "false"),
        ("0", "false"),
        ("input", "input"),
    ],
)
def test_core_autocrlf_normalization(value: str, expected: str) -> None:
    assert normalize_core_autocrlf(value) == expected


def test_invalid_core_autocrlf_fails_closed() -> None:
    with pytest.raises(GitSemanticConfigUnavailable, match="invalid core.autocrlf"):
        normalize_core_autocrlf("project-controlled-value")


def test_trusted_core_autocrlf_uses_git_scope_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    identity, install_root = _identity(tmp_path)
    home = tmp_path / "home"
    xdg = tmp_path / "xdg"
    program_data = tmp_path / "program-data"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))

    _write(install_root / "etc" / "gitconfig", "[core]\n\tautocrlf = true\n")
    _write(xdg / "git" / "config", "[core]\n\tautocrlf = false\n")
    _write(home / ".gitconfig", "[core]\n\tautocrlf = input\n")

    assert resolve_trusted_core_autocrlf(settings, identity) == "input"


def test_conflicting_windows_system_autocrlf_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    identity, install_root = _identity(tmp_path)
    home = tmp_path / "home"
    program_data = tmp_path / "program-data"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("PROGRAMDATA", str(program_data))

    _write(install_root / "etc" / "gitconfig", "[core]\n\tautocrlf = true\n")
    _write(program_data / "Git" / "config", "[core]\n\tautocrlf = false\n")

    with pytest.raises(GitSemanticConfigUnavailable, match="conflicting core.autocrlf"):
        resolve_trusted_core_autocrlf(settings, identity)


def test_trusted_config_include_semantics_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    identity, install_root = _identity(tmp_path)
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("PROGRAMDATA", raising=False)

    _write(
        install_root / "etc" / "gitconfig",
        "[include]\n\tpath = C:/outside/semantic-config\n[core]\n\tautocrlf = true\n",
    )

    with pytest.raises(GitSemanticConfigUnavailable, match="include semantics"):
        resolve_trusted_core_autocrlf(settings, identity)


def test_trusted_config_path_cannot_be_rebased_into_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    identity, install_root = _identity(tmp_path)
    monkeypatch.setenv("HOME", str(settings.workspace_root))
    monkeypatch.setenv("USERPROFILE", str(settings.workspace_root))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("PROGRAMDATA", raising=False)
    _write(install_root / "etc" / "gitconfig", "[core]\n\tautocrlf = true\n")

    with pytest.raises(GitSemanticConfigUnavailable, match="overlaps"):
        resolve_trusted_core_autocrlf(settings, identity)


def test_sanitized_repository_config_inherits_trusted_autocrlf(tmp_path: Path) -> None:
    source = tmp_path / "config"
    _write(
        source,
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n",
    )

    sanitized = _safe_repository_config(
        source,
        byte_limit=1024 * 1024,
        inherited_core_autocrlf="true",
    )

    assert b"\tautocrlf = true\n" in sanitized


def test_local_direct_autocrlf_overrides_trusted_default(tmp_path: Path) -> None:
    source = tmp_path / "config"
    _write(
        source,
        "[core]\n\trepositoryformatversion = 0\n\tautocrlf = false\n",
    )

    sanitized = _safe_repository_config(
        source,
        byte_limit=1024 * 1024,
        inherited_core_autocrlf="input",
    )

    assert b"\tautocrlf = false\n" in sanitized
    assert b"\tautocrlf = input\n" not in sanitized


def test_repository_config_include_semantics_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "config"
    _write(
        source,
        "[include]\n\tpath = ../outside\n[core]\n\trepositoryformatversion = 0\n",
    )

    with pytest.raises(GitBrokerUnavailable, match="include semantics"):
        _safe_repository_config(
            source,
            byte_limit=1024 * 1024,
            inherited_core_autocrlf="true",
        )


def test_projection_preserves_clean_crlf_worktree_semantics(tmp_path: Path) -> None:
    git = shutil.which("git.exe") or shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")
    settings = _settings(tmp_path)
    subprocess.run(
        [git, "init", str(settings.workspace_root)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    tracked = settings.workspace_root / "tracked.txt"
    tracked.write_bytes(b"tracked\n")
    subprocess.run(
        [
            git,
            "-c",
            "core.autocrlf=true",
            "-C",
            str(settings.workspace_root),
            "add",
            "tracked.txt",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    subprocess.run(
        [
            git,
            "-C",
            str(settings.workspace_root),
            "-c",
            "user.name=Automatic Git EOL Regression",
            "-c",
            "user.email=regression@example.invalid",
            "commit",
            "-m",
            "initial",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )

    # Re-materialize the worktree with Git itself so this fixture models a normal Windows
    # checkout under core.autocrlf=true instead of guessing at Git's stat/EOL semantics.
    tracked.unlink()
    subprocess.run(
        [
            git,
            "-c",
            "core.autocrlf=true",
            "-C",
            str(settings.workspace_root),
            "checkout",
            "--",
            "tracked.txt",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    assert tracked.read_bytes() == b"tracked\r\n"

    source_status = subprocess.run(
        [
            git,
            "-c",
            "core.autocrlf=true",
            "-C",
            str(settings.workspace_root),
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    ).stdout
    assert source_status == b""

    stage = stage_git_repository(
        settings,
        "crlf-clean",
        commands=((git, "status", "--porcelain=v1", "--untracked-files=no"),),
        inherited_core_autocrlf="true",
    )
    try:
        projected_status = subprocess.run(
            [
                git,
                "-C",
                str(stage.repository),
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            shell=False,
        ).stdout
        assert projected_status == b""
    finally:
        shutil.rmtree(stage.root, ignore_errors=True)

    control = stage_git_repository(
        settings,
        "crlf-false-control",
        commands=((git, "status", "--porcelain=v1", "--untracked-files=no"),),
        inherited_core_autocrlf="false",
    )
    try:
        false_status = subprocess.run(
            [
                git,
                "-C",
                str(control.repository),
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            shell=False,
        ).stdout
        assert b"tracked.txt" in false_status
    finally:
        shutil.rmtree(control.root, ignore_errors=True)
