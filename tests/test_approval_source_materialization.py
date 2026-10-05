from __future__ import annotations

import json
from pathlib import Path

import pytest

from windows_local_mcp.approval import (
    materialize_execution_copy,
    prepare_approval_bundle,
    verify_approval_bundle,
)
from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import CommandPolicy, NormalizedCommand
from windows_local_mcp.risk import command_risk_facts


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        **overrides,
    )
    settings.ensure_directories()
    return settings


def _non_loader_command(
    tmp_path: Path,
    *,
    cwd: Path,
    args: list[str] | None = None,
    program_key: str = "whoami",
) -> NormalizedCommand:
    executable = tmp_path / "trusted-whoami.exe"
    executable.write_bytes(b"approved non-code-loader executable")
    command_args = args if args is not None else ["/user"]
    return NormalizedCommand(
        executable=str(executable),
        args=command_args,
        cwd=str(cwd),
        display_command=[str(executable), *command_args],
        program_key=program_key,
    )


@pytest.mark.parametrize("relative_cwd", [Path("."), Path("nested")])
@pytest.mark.parametrize("workspace_write", [False, True])
def test_source_workspace_materialization_preserves_verified_command(
    tmp_path: Path,
    relative_cwd: Path,
    workspace_write: bool,
) -> None:
    settings = _settings(tmp_path)
    workspace = settings.workspace_root
    nested = workspace / "nested"
    nested.mkdir()
    (workspace / "input.txt").write_text("approved", encoding="utf-8")
    cwd = (workspace / relative_cwd).resolve()
    command = _non_loader_command(tmp_path, cwd=cwd)

    execution, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=f"source-{relative_cwd.name or 'root'}-{workspace_write}",
        normalized=command,
        workspace_write=workspace_write,
    )

    assert manifest["mode"] == "source-workspace"
    assert "staged_cwd" not in manifest
    assert Path(str(manifest["staged_workspace"])).is_dir()

    verified = verify_approval_bundle(
        settings=settings,
        operation_id=f"source-{relative_cwd.name or 'root'}-{workspace_write}",
        expected_digest=digest,
    )
    materialized = materialize_execution_copy(
        settings=settings,
        operation_id=f"source-{relative_cwd.name or 'root'}-{workspace_write}",
        normalized=verified,
    )

    # Source-workspace mode executes the already verified source meaning. It does not
    # reinterpret the command as a staged cwd/run projection merely because a worker
    # requested materialization.
    assert execution.model_dump() == command.model_dump()
    assert verified.model_dump() == command.model_dump()
    assert materialized.model_dump() == verified.model_dump()
    assert Path(materialized.cwd).resolve() == cwd
    assert not (settings.sandbox_scratch_dir / "runs" / f"source-{relative_cwd.name or 'root'}-{workspace_write}").exists()


def test_git_source_workspace_materialization_preserves_git_mode(tmp_path: Path) -> None:
    settings = _settings(tmp_path, git_enabled=True)
    workspace = settings.workspace_root
    metadata = workspace / ".git"
    metadata.mkdir()
    (metadata / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"approved git executable")

    normalized = CommandPolicy(settings, Workspace(settings)).normalize_host(
        command=[str(executable), "status", "--short"],
        cwd=".",
        network_expected=False,
    )
    operation_id = "git-source-materialization"
    _execution, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=normalized,
    )

    assert manifest["mode"] == "git-state-source-workspace"
    verified = verify_approval_bundle(
        settings=settings,
        operation_id=operation_id,
        expected_digest=digest,
    )
    materialized = materialize_execution_copy(
        settings=settings,
        operation_id=operation_id,
        normalized=verified,
    )

    assert materialized.model_dump() == verified.model_dump()
    assert Path(materialized.cwd).resolve() == workspace.resolve()
    assert not (settings.sandbox_scratch_dir / "runs" / operation_id).exists()


@pytest.mark.parametrize(
    ("tamper_kind", "expected_error"),
    [
        ("workspace", "workspace files changed after approval"),
        ("executable", "approved executable changed after approval"),
        ("external", "external approved input changed after approval"),
    ],
)
def test_source_workspace_approval_rejects_bound_input_changes(
    tmp_path: Path,
    tamper_kind: str,
    expected_error: str,
) -> None:
    settings = _settings(tmp_path)
    workspace = settings.workspace_root
    workspace_file = workspace / "input.txt"
    workspace_file.write_text("approved", encoding="utf-8")
    external = tmp_path / "external.txt"
    external.write_text("approved external", encoding="utf-8")
    command = _non_loader_command(
        tmp_path,
        cwd=workspace,
        args=["/user", str(external)],
    )
    operation_id = f"source-tamper-{tamper_kind}"
    _execution, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=command,
    )
    assert manifest["mode"] == "source-workspace"

    if tamper_kind == "workspace":
        workspace_file.write_text("changed", encoding="utf-8")
    elif tamper_kind == "executable":
        Path(command.executable).write_bytes(b"replacement executable")
    else:
        external.write_text("changed external", encoding="utf-8")

    with pytest.raises(RuntimeError, match=expected_error):
        verify_approval_bundle(
            settings=settings,
            operation_id=operation_id,
            expected_digest=digest,
        )


def test_source_workspace_manifest_without_staged_cwd_is_not_reinterpreted(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    workspace = settings.workspace_root
    command = _non_loader_command(tmp_path, cwd=workspace)
    operation_id = "source-no-staged-cwd"
    _execution, _manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=command,
    )
    manifest_path = settings.data_dir / "approval-staging" / operation_id / "manifest.json"
    stored = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert stored["mode"] == "source-workspace"
    assert "staged_cwd" not in stored

    verified = verify_approval_bundle(
        settings=settings,
        operation_id=operation_id,
        expected_digest=digest,
    )
    assert materialize_execution_copy(
        settings=settings,
        operation_id=operation_id,
        normalized=verified,
    ).model_dump() == verified.model_dump()


def test_source_workspace_preserves_relative_absolute_and_external_operands(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    workspace = settings.workspace_root
    nested = workspace / "nested"
    nested.mkdir()
    relative_file = nested / "relative.txt"
    absolute_file = nested / "absolute.txt"
    relative_file.write_text("relative", encoding="utf-8")
    absolute_file.write_text("absolute", encoding="utf-8")
    external = tmp_path / "external.txt"
    external.write_text("external", encoding="utf-8")
    args = [
        "/user",
        "nested/relative.txt",
        f"--absolute={absolute_file.resolve()}",
        str(external.resolve()),
    ]
    command = _non_loader_command(tmp_path, cwd=workspace, args=args)
    operation_id = "source-workspace-operands"

    _execution, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=command,
    )
    assert manifest["mode"] == "source-workspace"
    assert [record["path"] for record in manifest["external_inputs"]] == [
        str(external.resolve())
    ]

    verified = verify_approval_bundle(
        settings=settings,
        operation_id=operation_id,
        expected_digest=digest,
    )
    materialized = materialize_execution_copy(
        settings=settings,
        operation_id=operation_id,
        normalized=verified,
    )

    assert verified.args == args
    assert materialized.args == args
    assert (Path(materialized.cwd) / materialized.args[1]).resolve() == relative_file.resolve()
    assert Path(materialized.args[2].split("=", 1)[1]).resolve() == absolute_file.resolve()
    assert Path(materialized.args[3]).resolve() == external.resolve()


def test_source_workspace_manifest_tamper_is_rejected_before_materialization(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    command = _non_loader_command(tmp_path, cwd=settings.workspace_root)
    operation_id = "source-manifest-tamper"
    _execution, _manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=command,
    )
    manifest_path = settings.data_dir / "approval-staging" / operation_id / "manifest.json"
    manifest_path.chmod(0o644)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["execution"]["args"] = ["/tampered"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(RuntimeError, match="approval manifest digest mismatch"):
        verify_approval_bundle(
            settings=settings,
            operation_id=operation_id,
            expected_digest=digest,
        )


def test_source_workspace_settings_change_is_rejected_before_materialization(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    command = _non_loader_command(tmp_path, cwd=settings.workspace_root)
    operation_id = "source-settings-change"
    _execution, _manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=command,
    )
    settings.approval_execution_ttl_seconds += 1

    with pytest.raises(RuntimeError, match="effective MCP settings changed"):
        verify_approval_bundle(
            settings=settings,
            operation_id=operation_id,
            expected_digest=digest,
        )


def test_source_workspace_environment_change_is_rejected_before_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    command = _non_loader_command(tmp_path, cwd=settings.workspace_root)
    operation_id = "source-environment-change"
    _execution, _manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=command,
    )
    monkeypatch.setenv("JAVA_HOME", str(tmp_path / "changed-java"))

    with pytest.raises(RuntimeError, match="command-affecting environment changed"):
        verify_approval_bundle(
            settings=settings,
            operation_id=operation_id,
            expected_digest=digest,
        )


@pytest.mark.parametrize("tampered_field", ["args", "cwd", "executable"])
def test_source_materialization_rejects_unapproved_execution_command_changes(
    tmp_path: Path,
    tampered_field: str,
) -> None:
    settings = _settings(tmp_path)
    workspace = settings.workspace_root
    alternate_cwd = workspace / "alternate"
    alternate_cwd.mkdir()
    command = _non_loader_command(tmp_path, cwd=workspace)
    operation_id = f"source-materialization-tamper-{tampered_field}"
    _execution, _manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id=operation_id,
        normalized=command,
    )
    verified = verify_approval_bundle(
        settings=settings,
        operation_id=operation_id,
        expected_digest=digest,
    )
    tampered = verified.model_copy(deep=True)
    if tampered_field == "args":
        tampered.args = ["/tampered"]
    elif tampered_field == "cwd":
        tampered.cwd = str(alternate_cwd)
    else:
        replacement = tmp_path / "replacement.exe"
        replacement.write_bytes(b"unapproved executable")
        tampered.executable = str(replacement)

    with pytest.raises(RuntimeError, match="source execution command differs"):
        materialize_execution_copy(
            settings=settings,
            operation_id=operation_id,
            normalized=tampered,
        )


@pytest.mark.parametrize(
    ("execution_tier", "mode", "expected_impact"),
    [
        (
            "approved_host",
            "source-workspace",
            "承認時に固定・検証した元の作業ディレクトリと入力を使用し、通常のWindowsユーザー権限で実行",
        ),
        (
            "approved_host",
            "git-state-source-workspace",
            "承認時に固定・検証した元の作業ディレクトリと入力を使用し、通常のWindowsユーザー権限で実行",
        ),
        (
            "approved_host",
            "staged-cwd",
            "staged execution copy; process still runs with the local account token",
        ),
        (
            "codex_sandbox",
            "staged-sandbox-workspace",
            "sandboxed execution; workspace writes only when explicitly requested",
        ),
    ],
)
def test_risk_display_preserves_source_git_staged_and_sandbox_modes(
    execution_tier: str,
    mode: str,
    expected_impact: str,
) -> None:
    command = NormalizedCommand(
        executable="C:/trusted/tool.exe",
        args=["/user"],
        cwd="C:/workspace",
        display_command=["C:/trusted/tool.exe", "/user"],
        program_key="whoami",
    )

    facts = command_risk_facts(
        command,
        workspace_write=False,
        manifest={"mode": mode},
        execution_tier=execution_tier,
    )

    assert facts["impact_scope"] == expected_impact
