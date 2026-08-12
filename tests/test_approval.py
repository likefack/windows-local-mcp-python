import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from windows_local_mcp.approval import (
    collect_staged_workspace_changes,
    materialize_execution_copy,
    prepare_approval_bundle,
    verify_approval_bundle,
)
from windows_local_mcp.approval_ui import _terminal_safe
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import NormalizedCommand


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(
        workspace_root=root,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        **overrides,
    )
    settings.ensure_directories()
    return settings


def make_executable(tmp_path: Path) -> Path:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"approved executable")
    return executable


def make_command(executable: Path, cwd: Path, args: list[str]) -> NormalizedCommand:
    return NormalizedCommand(
        executable=str(executable),
        args=args,
        cwd=str(cwd),
        display_command=[str(executable), *args],
        program_key="python",
    )


def test_code_loader_runs_immutable_cwd_copy_and_ignores_unrelated_changes(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    project = settings.workspace_root / "project"
    project.mkdir()
    script = project / "main.py"
    script.write_text("print('approved')", encoding="utf-8")
    unrelated = settings.workspace_root / "notes.txt"
    unrelated.write_text("one", encoding="utf-8")
    command = make_command(make_executable(tmp_path), project, ["main.py"])

    _, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="immutable",
        normalized=command,
    )
    script.write_text("print('replaced')", encoding="utf-8")
    unrelated.write_text("two", encoding="utf-8")

    verified = verify_approval_bundle(
        settings=settings, operation_id="immutable", expected_digest=digest
    )
    staged_script = Path(verified.cwd) / "main.py"
    assert staged_script.read_text(encoding="utf-8") == "print('approved')"
    assert manifest["mode"] == "staged-cwd"
    assert len(manifest["inputs"]) == 1


def test_staging_excludes_protected_files_and_generated_dependency_trees(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    project = settings.workspace_root / "project"
    project.mkdir()
    (project / "main.py").write_text("print('ok')", encoding="utf-8")
    (project / ".env").write_text("TOKEN=secret", encoding="utf-8")
    for directory in (".venv", "node_modules", "build", "__pycache__"):
        generated = project / directory
        generated.mkdir()
        (generated / "payload.bin").write_bytes(b"generated")
    command = make_command(make_executable(tmp_path), project, ["main.py"])

    _, manifest, _digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="bounded-staging",
        normalized=command,
    )

    staged = Path(str(manifest["staged_cwd"]))
    assert (staged / "main.py").is_file()
    assert not (staged / ".env").exists()
    assert not (staged / ".venv").exists()
    assert not (staged / "node_modules").exists()
    assert not (staged / "build").exists()
    assert not (staged / "__pycache__").exists()
    assert [Path(record["source_path"]).name for record in manifest["inputs"]] == [
        "main.py"
    ]


def test_tampering_with_immutable_approved_copy_is_rejected(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    script = settings.workspace_root / "main.py"
    script.write_text("safe", encoding="utf-8")
    command = make_command(make_executable(tmp_path), settings.workspace_root, ["main.py"])
    _, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="tamper",
        normalized=command,
    )
    staged = Path(manifest["inputs"][0]["staged_path"])
    staged.chmod(0o666)
    staged.write_text("evil", encoding="utf-8")
    with pytest.raises(RuntimeError, match="approved input changed"):
        verify_approval_bundle(
            settings=settings, operation_id="tamper", expected_digest=digest
        )


def test_executable_replacement_after_approval_is_rejected(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    script = settings.workspace_root / "main.py"
    script.write_text("safe", encoding="utf-8")
    executable = make_executable(tmp_path)
    command = make_command(executable, settings.workspace_root, ["main.py"])
    _, _, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="exe-swap",
        normalized=command,
    )
    executable.write_bytes(b"different executable")
    with pytest.raises(RuntimeError, match="executable changed"):
        verify_approval_bundle(
            settings=settings, operation_id="exe-swap", expected_digest=digest
        )


def test_workspace_write_approval_detects_any_workspace_change(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    target = settings.workspace_root / "target.txt"
    target.write_text("before", encoding="utf-8")
    command = make_command(make_executable(tmp_path), settings.workspace_root, ["target.txt"])
    _, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="source-write",
        normalized=command,
        workspace_write=True,
    )
    target.write_text("changed", encoding="utf-8")
    assert manifest["mode"] == "staged-workspace-write"
    with pytest.raises(RuntimeError, match="workspace files changed"):
        verify_approval_bundle(
            settings=settings, operation_id="source-write", expected_digest=digest
        )


def test_approval_terminal_text_escapes_controls_and_bidi() -> None:
    rendered = _terminal_safe("benign\x1b[2J\rforged\u202etxt")
    assert "\x1b" not in rendered
    assert "\r" not in rendered
    assert "\u202e" not in rendered
    assert rendered == r"benign\u001b[2J\u000dforged\u202etxt"


def test_staged_sandbox_write_returns_a_closed_world_workspace_delta(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    selected = settings.workspace_root / "selected.dart"
    other = settings.workspace_root / "other.dart"
    selected.write_text("void main(){}\n", encoding="utf-8")
    other.write_text("const other=1;\n", encoding="utf-8")
    executable = make_executable(tmp_path)
    command = NormalizedCommand(
        executable=str(executable),
        args=["format", str(selected)],
        cwd=str(settings.workspace_root),
        display_command=[str(executable), "format", str(selected)],
        program_key="dart",
    )
    _, _, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="staged-dart",
        normalized=command,
        workspace_write=True,
    )
    verified = verify_approval_bundle(
        settings=settings, operation_id="staged-dart", expected_digest=digest
    )
    run = materialize_execution_copy(
        settings=settings, operation_id="staged-dart", normalized=verified
    )
    run_cwd = Path(run.cwd)
    (run_cwd / "selected.dart").write_bytes(b"void main() {}\n")
    (run_cwd / "other.dart").write_bytes(b"malicious\n")
    changes, deletions = collect_staged_workspace_changes(
        settings=settings, operation_id="staged-dart", normalized=run
    )
    assert changes == {
        "other.dart": b"malicious\n",
        "selected.dart": b"void main() {}\n",
    }
    assert deletions == set()


def test_code_loader_external_input_is_rejected(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')", encoding="utf-8")
    command = make_command(
        make_executable(tmp_path), settings.workspace_root, [str(outside)]
    )
    with pytest.raises(PermissionError, match="outside workspace"):
        prepare_approval_bundle(
            settings=settings,
            workspace=Workspace(settings),
            operation_id="external",
            normalized=command,
        )


def test_approval_request_ttl_and_one_shot_claim_are_atomic(tmp_path: Path) -> None:
    settings = make_settings(
        tmp_path,
        approval_execution_ttl_seconds=5,
    )
    store = AuditStore(settings)
    future = (datetime.now(UTC) + timedelta(seconds=30)).isoformat()
    operation_id = store.create_operation(
        tool_name="request_host_command",
        tier="host_approval",
        status="pending_approval",
        cwd=str(settings.workspace_root),
        request={},
        approval_status="pending",
        request_expires_at=future,
    )
    store.decide_approval(operation_id, approved=True, approver="tester")
    store.claim_approved(operation_id)
    with pytest.raises(RuntimeError, match="already claimed"):
        store.claim_approved(operation_id)


def test_expired_request_cannot_be_approved(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    store = AuditStore(settings)
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    operation_id = store.create_operation(
        tool_name="request_host_command",
        tier="host_approval",
        status="pending_approval",
        cwd=str(settings.workspace_root),
        request={},
        approval_status="pending",
        request_expires_at=past,
    )
    with pytest.raises(RuntimeError, match="expired"):
        store.decide_approval(operation_id, approved=True, approver="tester")
    assert store.get_operation(operation_id)["status"] == "expired"


def test_expired_execution_grant_cannot_be_claimed(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    store = AuditStore(settings)
    future = (datetime.now(UTC) + timedelta(seconds=30)).isoformat()
    operation_id = store.create_operation(
        tool_name="request_host_command",
        tier="host_approval",
        status="pending_approval",
        cwd=str(settings.workspace_root),
        request={},
        approval_status="pending",
        request_expires_at=future,
    )
    store.decide_approval(operation_id, approved=True, approver="tester")
    store.update_operation(
        operation_id,
        approval_expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
    )
    with pytest.raises(RuntimeError, match="expired"):
        store.claim_approved(operation_id)
    assert store.get_operation(operation_id)["status"] == "expired"


def test_environment_change_invalidates_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = make_settings(tmp_path)
    script = settings.workspace_root / "main.py"
    script.write_text("safe", encoding="utf-8")
    command = make_command(make_executable(tmp_path), settings.workspace_root, ["main.py"])
    _, _, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="environment",
        normalized=command,
    )
    monkeypatch.setenv("JAVA_HOME", os.fspath(tmp_path / "different-java"))
    with pytest.raises(RuntimeError, match="environment changed"):
        verify_approval_bundle(
            settings=settings, operation_id="environment", expected_digest=digest
        )


def test_dart_path_dependency_outside_cwd_is_copied_and_rewritten(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    project = settings.workspace_root / "app"
    package_dir = project / ".dart_tool"
    package_dir.mkdir(parents=True)
    shared = settings.workspace_root / "shared_pkg"
    (shared / "lib").mkdir(parents=True)
    shared_source = shared / "lib" / "shared.dart"
    shared_source.write_text("const value = 'approved';", encoding="utf-8")
    (project / "pubspec.yaml").write_text("name: app", encoding="utf-8")
    package_dir.joinpath("package_config.json").write_text(
        '{"configVersion":2,"packages":[{"name":"shared","rootUri":"../../shared_pkg","packageUri":"lib/"}]}',
        encoding="utf-8",
    )
    executable = make_executable(tmp_path)
    command = NormalizedCommand(
        executable=str(executable),
        args=["test"],
        cwd=str(project),
        display_command=[str(executable), "test"],
        program_key="dart",
    )
    _, manifest, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="dart-path-dependency",
        normalized=command,
    )
    shared_source.write_text("const value = 'replaced';", encoding="utf-8")
    verified = verify_approval_bundle(
        settings=settings,
        operation_id="dart-path-dependency",
        expected_digest=digest,
    )
    staged_config = Path(verified.cwd) / ".dart_tool" / "package_config.json"
    assert "approval-inputs" in staged_config.read_text(encoding="utf-8")
    staged_shared = [
        Path(record["staged_path"])
        for record in manifest["inputs"]
        if record["source_path"].endswith("shared.dart")
    ]
    assert len(staged_shared) == 1
    assert "approved" in staged_shared[0].read_text(encoding="utf-8")
    runnable = materialize_execution_copy(
        settings=settings,
        operation_id="dart-path-dependency",
        normalized=verified,
    )
    runnable_config = Path(runnable.cwd) / ".dart_tool" / "package_config.json"
    runnable_text = runnable_config.read_text(encoding="utf-8")
    assert "approval-inputs" not in runnable_text
    assert settings.sandbox_scratch_dir is not None
    assert (
        settings.sandbox_scratch_dir / "runs" / "dart-path-dependency"
    ).as_uri() in runnable_text


def test_non_file_dart_dependency_fails_closed(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    project = settings.workspace_root / "app"
    package_dir = project / ".dart_tool"
    package_dir.mkdir(parents=True)
    package_dir.joinpath("package_config.json").write_text(
        '{"configVersion":2,"packages":[{"name":"remote","rootUri":"https://example.invalid/pkg"}]}',
        encoding="utf-8",
    )
    executable = make_executable(tmp_path)
    command = NormalizedCommand(
        executable=str(executable),
        args=["test"],
        cwd=str(project),
        display_command=[str(executable), "test"],
        program_key="dart",
    )
    with pytest.raises(PermissionError, match="non-file"):
        prepare_approval_bundle(
            settings=settings,
            workspace=Workspace(settings),
            operation_id="remote-dependency",
            normalized=command,
        )


def test_verified_snapshot_materializes_separate_writable_run_copy(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    script = settings.workspace_root / "main.py"
    script.write_text("approved", encoding="utf-8")
    command = make_command(make_executable(tmp_path), settings.workspace_root, ["main.py"])
    _, _, digest = prepare_approval_bundle(
        settings=settings,
        workspace=Workspace(settings),
        operation_id="run-copy",
        normalized=command,
    )
    immutable = verify_approval_bundle(
        settings=settings, operation_id="run-copy", expected_digest=digest
    )
    runnable = materialize_execution_copy(
        settings=settings, operation_id="run-copy", normalized=immutable
    )
    assert Path(runnable.cwd).name == "cwd"
    assert Path(runnable.cwd).parent.name == "run-copy"
    assert Path(runnable.cwd).parent.parent.name == "runs"
    assert settings.sandbox_scratch_dir in Path(runnable.cwd).parents
    Path(runnable.cwd, "main.py").write_text("runtime output", encoding="utf-8")
    assert Path(immutable.cwd, "main.py").read_text(encoding="utf-8") == "approved"


def test_external_dart_dependency_requires_configured_read_root(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    project = settings.workspace_root / "app"
    package_dir = project / ".dart_tool"
    package_dir.mkdir(parents=True)
    external = tmp_path / "private-package"
    external.mkdir()
    (external / "secret.dart").write_text("secret", encoding="utf-8")
    package_dir.joinpath("package_config.json").write_text(
        json.dumps(
            {
                "configVersion": 2,
                "packages": [
                    {"name": "external", "rootUri": external.as_uri(), "packageUri": ""}
                ],
            }
        ),
        encoding="utf-8",
    )
    executable = make_executable(tmp_path)
    command = NormalizedCommand(
        executable=str(executable),
        args=["analyze"],
        cwd=str(project),
        display_command=[str(executable), "analyze"],
        program_key="dart",
    )
    with pytest.raises(PermissionError, match="sandbox_dependency_readable_paths"):
        prepare_approval_bundle(
            settings=settings,
            workspace=Workspace(settings),
            operation_id="external-dart-dependency",
            normalized=command,
        )
