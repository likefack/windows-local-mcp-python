from __future__ import annotations

from pathlib import Path

import pytest

from windows_local_mcp import sandbox_source_acl
from windows_local_mcp.sandbox_source_acl import (
    SOURCE_WORKSPACE_READ_GUARD_VERSION,
    SourceWorkspaceAclError,
    _ReadDenyState,
    ensure_source_workspace_read_deny,
)


def test_source_workspace_acl_guard_applies_and_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sid = "S-1-5-21-100-200-300-1004"
    states = iter(
        [
            _ReadDenyState(False, False, False),
            _ReadDenyState(True, True, True),
        ]
    )
    applied: list[tuple[Path, str]] = []

    monkeypatch.setattr(
        sandbox_source_acl,
        "_inspect_source_workspace_read_deny",
        lambda _workspace, _sid: next(states),
    )
    monkeypatch.setattr(
        sandbox_source_acl,
        "_apply_source_workspace_read_deny",
        lambda path, target: applied.append((path, target)),
    )

    result = ensure_source_workspace_read_deny(workspace, sid)

    assert applied == [(workspace.resolve(), sid)]
    assert result == {
        "version": SOURCE_WORKSPACE_READ_GUARD_VERSION,
        "workspace_root": str(workspace.resolve()),
        "target_sid": sid,
        "explicit_deny_read": True,
        "inheritable_to_files": True,
        "inheritable_to_directories": True,
        "added": True,
    }


def test_source_workspace_acl_guard_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sid = "S-1-5-21-100-200-300-1004"
    monkeypatch.setattr(
        sandbox_source_acl,
        "_inspect_source_workspace_read_deny",
        lambda _workspace, _sid: _ReadDenyState(True, True, True),
    )

    def forbidden_apply(_workspace: Path, _sid: str) -> None:
        raise AssertionError("already-satisfied ACL must not be rewritten")

    monkeypatch.setattr(
        sandbox_source_acl,
        "_apply_source_workspace_read_deny",
        forbidden_apply,
    )

    result = ensure_source_workspace_read_deny(workspace, sid)

    assert result["added"] is False
    assert result["explicit_deny_read"] is True


def test_source_workspace_acl_guard_fails_closed_when_update_does_not_converge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sid = "S-1-5-21-100-200-300-1004"
    monkeypatch.setattr(
        sandbox_source_acl,
        "_inspect_source_workspace_read_deny",
        lambda _workspace, _sid: _ReadDenyState(False, False, False),
    )
    monkeypatch.setattr(
        sandbox_source_acl,
        "_apply_source_workspace_read_deny",
        lambda _workspace, _sid: None,
    )

    with pytest.raises(SourceWorkspaceAclError, match="did not converge"):
        ensure_source_workspace_read_deny(workspace, sid)


def test_source_workspace_acl_guard_rejects_invalid_sid(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(SourceWorkspaceAclError, match="SID is invalid"):
        ensure_source_workspace_read_deny(workspace, "not-a-sid")
