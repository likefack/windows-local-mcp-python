import hashlib
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.git_broker_sandbox import (
    GitBrokerUnavailable,
    _rebase_index_stat_cache_for_projection,
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


def test_projection_keeps_status_and_diff_consistent_for_sanitized_attributes(
    tmp_path: Path,
) -> None:
    git = shutil.which("git.exe") or shutil.which("git")
    if git is None:
        pytest.skip("Git is not installed")
    settings = _settings(tmp_path)
    lfs_version = subprocess.run(
        [git, "lfs", "version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        shell=False,
    )
    if lfs_version.returncode != 0:
        pytest.skip("Git LFS is not installed")
    subprocess.run(
        [git, "init", str(settings.workspace_root)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    subprocess.run(
        [git, "-C", str(settings.workspace_root), "lfs", "install", "--local"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    attributes = settings.workspace_root / ".gitattributes"
    tracked = settings.workspace_root / "tracked.bin"
    attributes.write_bytes(b"*.bin filter=lfs diff=lfs merge=lfs -text\n")
    tracked.write_bytes(b"Automatic Git LFS consistency regression fixture.\n")
    subprocess.run(
        [
            git,
            "-C",
            str(settings.workspace_root),
            "add",
            ".gitattributes",
            "tracked.bin",
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
            "user.name=Automatic Git Attribute Regression",
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

    git_base = [
        git,
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "diff.autoRefreshIndex=false",
    ]
    commands = (
        [*git_base, "status", "--porcelain=v1", "--untracked-files=all"],
        [*git_base, "diff", "--stat", "--name-status", "--no-ext-diff", "--no-textconv"],
    )
    source_status = subprocess.run(
        commands[0],
        cwd=settings.workspace_root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    ).stdout
    assert source_status == b""
    indexed = subprocess.run(
        [git, "-C", str(settings.workspace_root), "show", ":tracked.bin"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    ).stdout
    assert indexed.startswith(b"version https://git-lfs.github.com/spec/v1\n")
    assert indexed != tracked.read_bytes()

    index_data = (settings.workspace_root / ".git" / "index").read_bytes()
    assert struct.unpack(">I", index_data[4:8])[0] == 2
    flags_offset = 12 + 60

    v2_extended = bytearray(index_data)
    flags = struct.unpack(">H", v2_extended[flags_offset : flags_offset + 2])[0]
    struct.pack_into(">H", v2_extended, flags_offset, flags | 0x4000)
    v2_extended[-20:] = hashlib.sha1(v2_extended[:-20]).digest()
    with pytest.raises(GitBrokerUnavailable, match="extended flags in a v2 index"):
        _rebase_index_stat_cache_for_projection(
            bytes(v2_extended),
            source_root=settings.workspace_root,
            destination_root=settings.workspace_root,
        )

    v3_unknown_extended = bytearray(index_data)
    struct.pack_into(">I", v3_unknown_extended, 4, 3)
    struct.pack_into(">H", v3_unknown_extended, flags_offset, flags | 0x4000)
    path_offset = flags_offset + 2
    terminator = v3_unknown_extended.find(b"\0", path_offset, len(v3_unknown_extended) - 20)
    first_path = bytes(v3_unknown_extended[path_offset:terminator])
    v3_unknown_extended[path_offset + 2 : terminator + 3] = first_path + b"\0"
    struct.pack_into(">H", v3_unknown_extended, path_offset, 0x0001)
    v3_unknown_extended[-20:] = hashlib.sha1(v3_unknown_extended[:-20]).digest()
    with pytest.raises(GitBrokerUnavailable, match="unsupported extended flags"):
        _rebase_index_stat_cache_for_projection(
            bytes(v3_unknown_extended),
            source_root=settings.workspace_root,
            destination_root=settings.workspace_root,
        )

    ads_path = bytearray(index_data)
    replacement = b"x:" + b"a" * (len(first_path) - 2)
    ads_path[path_offset:terminator] = replacement
    ads_path[-20:] = hashlib.sha1(ads_path[:-20]).digest()
    with pytest.raises(GitBrokerUnavailable, match="unsafe index path"):
        _rebase_index_stat_cache_for_projection(
            bytes(ads_path),
            source_root=settings.workspace_root,
            destination_root=settings.workspace_root,
        )

    stage = stage_git_repository(
        settings,
        "attribute-consistency",
        commands=commands,
        inherited_core_autocrlf="true",
    )
    try:
        projected_outputs = [
            subprocess.run(
                [command[0], "-C", str(stage.repository), *command[1:]],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=True,
                shell=False,
            ).stdout
            for command in commands
        ]
        assert projected_outputs == [b"", b""]
        projected_attributes = (stage.repository / ".gitattributes").read_bytes()
        assert len(projected_attributes) == len(attributes.read_bytes())
        assert projected_attributes != attributes.read_bytes()
        assert set(projected_attributes) <= {ord("#"), ord("\n"), ord("\r")}
    finally:
        shutil.rmtree(stage.root, ignore_errors=True)

    tracked.unlink()
    deletion_stage = stage_git_repository(
        settings,
        "attribute-tracked-deletion",
        commands=commands,
        inherited_core_autocrlf="true",
    )
    try:
        deletion_outputs = [
            subprocess.run(
                [command[0], "-C", str(deletion_stage.repository), *command[1:]],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=True,
                shell=False,
            ).stdout
            for command in commands
        ]
        assert b"tracked.bin" in deletion_outputs[0]
        assert b"tracked.bin" in deletion_outputs[1]
        assert b".gitattributes" not in deletion_outputs[0]
        assert b".gitattributes" not in deletion_outputs[1]
    finally:
        shutil.rmtree(deletion_stage.root, ignore_errors=True)

    # If source stat evidence is stale, the Broker cannot safely emulate a project-controlled
    # clean filter. It must reject the snapshot rather than reintroduce status/diff disagreement.
    tracked.write_bytes(b"Automatic Git LFS consistency regression fixture changed and larger.\n")
    with pytest.raises(GitBrokerUnavailable, match="current source index stat metadata"):
        stage_git_repository(
            settings,
            "attribute-stale-index",
            commands=commands,
            inherited_core_autocrlf="true",
        )
