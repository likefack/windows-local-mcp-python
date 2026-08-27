from pathlib import Path
from types import SimpleNamespace

import pytest

from windows_local_mcp import git_broker_live_verify
from windows_local_mcp.git_broker_sandbox import (
    GitBrokerStage,
    _prepare_git_launch,
    _require_current_git_live_marker,
)

_BUILTINS = b"status diff log show rev-parse ls-files\n"


def test_ordinary_git_launch_rechecks_git_specific_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = object()
    identity = {"sha256": "a" * 64}
    calls: list[tuple[object, dict[str, str]]] = []

    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_live_verification",
        lambda actual_settings, actual_identity: calls.append(
            (actual_settings, actual_identity)
        ),
    )

    _require_current_git_live_marker(
        settings,  # type: ignore[arg-type]
        identity,
        live_verification_probe=False,
    )

    assert calls == [(settings, identity)]


def test_explicit_live_verification_probe_is_the_only_marker_bootstrap_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_live_verification",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bootstrap probe must not require a marker that it is creating")
        ),
    )

    _require_current_git_live_marker(
        object(),  # type: ignore[arg-type]
        {"sha256": "a" * 64},
        live_verification_probe=True,
    )


def test_prepare_git_launch_keeps_process_cwd_outside_projection(tmp_path: Path) -> None:
    source = tmp_path / "workspace"
    source_subdir = source / "sub"
    source_subdir.mkdir(parents=True)
    root = tmp_path / "scratch" / "git-broker" / "operation"
    repository = root / "repository"
    staged_subdir = repository / "sub"
    staged_subdir.mkdir(parents=True)
    runtime = root / "runtime"
    runtime.mkdir()
    executable = tmp_path / "trusted" / "mingw64" / "bin" / "git.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"git")
    stage = GitBrokerStage(
        root=root,
        repository=repository,
        runtime=runtime,
        source_root=source,
        snapshot_digest="a" * 64,
        file_count=0,
        total_bytes=0,
    )
    identity = {"path": str(executable.resolve())}

    command, process_cwd = _prepare_git_launch(
        [str(executable), "--no-pager", "status"],
        stage,
        identity,
        str(source_subdir),
    )

    assert process_cwd == executable.parent.resolve()
    assert process_cwd != repository
    assert process_cwd != staged_subdir
    assert command == [
        str(executable),
        "-C",
        str(staged_subdir),
        "--no-pager",
        "status",
    ]


def test_verify_git_broker_live_uses_bootstrap_probe_mode(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = git_broker_live_verify.Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
        git_enabled=True,
    )
    settings.ensure_directories()
    identity = {
        "path": str((tmp_path / "git.exe").resolve()),
        "sha256": "a" * 64,
        "size": 123,
        "mtime_ns": 456,
        "stable_file_identity": {"platform": "test", "id": 1},
        "provenance": "explicit-local-config",
    }
    properties = {
        name: {"status": "verified"}
        for name in git_broker_live_verify.SANDBOX_SECURITY_PROPERTIES
    }
    containment = SimpleNamespace(
        backend=SimpleNamespace(
            version="test-backend",
            as_dict=lambda: {"version": "test-backend", "identity": "bound"},
        ),
        live_evidence={"version": 5, "properties": properties, "checks": {}},
        policy_digest="containment-policy",
    )
    seen: dict[str, object] = {}
    snapshot_digest = "c" * 64

    monkeypatch.setattr(
        git_broker_live_verify,
        "configured_git_identity",
        lambda _settings: identity,
    )
    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_containment",
        lambda _settings, _identity: containment,
    )

    def fake_batch(**kwargs: object) -> list[SimpleNamespace]:
        seen.update(kwargs)
        return [
            SimpleNamespace(
                returncode=0,
                stdout=b"true\n",
                stderr=b"",
                snapshot_digest=snapshot_digest,
            ),
            SimpleNamespace(
                returncode=0,
                stdout=b"",
                stderr=b"",
                snapshot_digest=snapshot_digest,
            ),
            SimpleNamespace(
                returncode=0,
                stdout=_BUILTINS,
                stderr=b"",
                snapshot_digest=snapshot_digest,
            ),
        ]

    monkeypatch.setattr(git_broker_live_verify, "run_git_broker_batch", fake_batch)

    marker = git_broker_live_verify.verify_git_broker_live(settings)

    assert marker["route_eligible"] is True
    assert marker["checks"]["git_projection_snapshot_bound"] is True
    assert marker["checks"]["git_allowed_commands_builtin"] is True
    assert seen["live_verification_probe"] is True
