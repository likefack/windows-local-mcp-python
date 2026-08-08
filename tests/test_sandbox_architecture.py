from __future__ import annotations

import ctypes
import json
import sys
from ctypes import wintypes
from pathlib import Path

import pytest
from pydantic import ValidationError

from windows_local_mcp.appcontainer import (
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    _acl_write_ahead_ledger,
    _configure_kernel32,
    appcontainer_profile_name,
)
from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.policy import approved_request_hash
from windows_local_mcp.sandbox_backend import (
    ApprovedSandboxUnavailable,
    build_codex_sandbox_argv,
    codex_sandbox_effective_policy,
    resolve_codex_sandbox_backend,
)
from windows_local_mcp.windows_system import windows_system_executable
from windows_local_mcp.workspace_history import (
    capture_workspace_state,
    incomplete_workspace_transactions,
    mark_workspace_transaction_audit_reconciled,
    recover_incomplete_workspace_transaction,
    verify_checkpoint_integrity,
    workspace_recovery_required,
)


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
    )
    settings.ensure_directories()
    return settings


def test_codex_sandbox_adapter_binds_installed_launcher_without_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    codex = tmp_path / "trusted-tools" / "codex.exe"
    codex.parent.mkdir()
    codex.write_bytes(b"test codex launcher")
    (codex.parent / "codex-command-runner.exe").write_bytes(b"test command runner")
    (codex.parent / "codex-windows-sandbox-setup.exe").write_bytes(
        b"test sandbox setup"
    )
    settings.approved_sandbox_codex_path = codex
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend._openai_authenticode_identity",
        lambda _path: {
            "status": "Valid",
            "subject": 'CN="OpenAI OpCo, LLC"',
            "thumbprint": "A" * 40,
        },
    )

    backend = resolve_codex_sandbox_backend(settings)
    argv = build_codex_sandbox_argv(
        backend,
        command=[sys.executable, "-m", "pytest"],
        cwd=str(settings.workspace_root),
    )
    assert argv[0] == str(codex.resolve())
    assert argv[1] == "sandbox"
    assert "exec" not in argv[:8]
    assert backend.as_dict()["model_api_usage"].startswith("none")
    assert backend.as_dict()["authentication_required"] is False
    assert backend.permission_profile == ":workspace"
    assert backend.provenance == "explicit-trusted-local-config"
    assert backend.signature_status == "Valid"
    assert [helper.name for helper in backend.helpers] == [
        "codex-command-runner.exe",
        "codex-windows-sandbox-setup.exe",
    ]


def test_codex_sandbox_rejects_untrusted_launcher_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    codex = tmp_path / "trusted-tools" / "codex.exe"
    codex.parent.mkdir()
    codex.write_bytes(b"unsigned replacement")
    settings.approved_sandbox_codex_path = codex

    def reject(_path: Path) -> dict[str, str]:
        raise ApprovedSandboxUnavailable("not signed by OpenAI")

    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend._openai_authenticode_identity", reject
    )
    with pytest.raises(ApprovedSandboxUnavailable, match="not found or was not accessible"):
        resolve_codex_sandbox_backend(settings)


def test_codex_policy_is_offline_and_does_not_trust_target_stderr() -> None:
    policy = codex_sandbox_effective_policy(workspace_write=True)
    assert policy["network_policy"]["internet"] == "deny"
    assert policy["filesystem_policy"]["outside_workspace_write"].startswith("denied")


def test_approved_request_hash_binds_capability_fields() -> None:
    request: dict[str, object] = {
        "approval_binding_version": 2,
        "normalized_command": {"executable": "python.exe", "args": ["test.py"]},
        "workspace_write": False,
        "max_runtime_seconds": 30,
        "sandbox_backend": {"executable_sha256": "a" * 64},
    }
    expected = approved_request_hash(request)
    for key, value in (
        ("workspace_write", True),
        ("max_runtime_seconds", 300),
        ("sandbox_backend", {"executable_sha256": "b" * 64}),
    ):
        changed = dict(request)
        changed[key] = value
        assert approved_request_hash(changed) != expected


def test_safe_readable_path_cannot_overlap_security_roots(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(ValidationError, match="cannot overlap"):
        Settings(
            workspace_root=workspace,
            data_dir=tmp_path / "data",
            protect_data_dir_acl=False,
            safe_network_readable_paths=[tmp_path],
        )


def test_appcontainer_identity_binds_readable_path_policy_and_operation(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    sdk_a = tmp_path / "sdk-a"
    sdk_b = tmp_path / "sdk-b"
    sdk_a.mkdir()
    sdk_b.mkdir()
    settings.safe_network_readable_paths = [sdk_a]
    first = appcontainer_profile_name(settings, "dart", operation_id="operation-a")
    settings.safe_network_readable_paths = [sdk_b]
    changed_policy = appcontainer_profile_name(settings, "dart", operation_id="operation-a")
    changed_operation = appcontainer_profile_name(
        settings, "dart", operation_id="operation-b"
    )
    assert first != changed_policy
    assert changed_policy != changed_operation
    assert len(first) <= 64
    assert len(changed_policy) <= 64
    assert len(changed_operation) <= 64


def test_acl_write_ahead_keeps_displaced_sid_until_cleanup() -> None:
    ledger = _acl_write_ahead_ledger(
        {"old-sid": [r"C:\SDK-A"], "same-sid": [r"C:\Old"]},
        {"same-sid", "new-sid"},
        {r"C:\SDK-B"},
    )
    assert ledger["old-sid"] == [r"C:\SDK-A"]
    assert set(ledger["same-sid"]) == {r"C:\Old", r"C:\SDK-B"}
    assert ledger["new-sid"] == [r"C:\SDK-B"]


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 pointer-size contract")
def test_appcontainer_win32_signatures_keep_pointer_sized_handles() -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _configure_kernel32(kernel32)
    assert ctypes.sizeof(wintypes.HANDLE) == ctypes.sizeof(ctypes.c_void_p)
    assert kernel32.CloseHandle.argtypes == [wintypes.HANDLE]
    assert kernel32.AssignProcessToJobObject.argtypes == [
        wintypes.HANDLE,
        wintypes.HANDLE,
    ]
    assert PROC_THREAD_ATTRIBUTE_HANDLE_LIST == 0x00020002


@pytest.mark.skipif(sys.platform != "win32", reason="Windows system-directory contract")
def test_windows_policy_helpers_ignore_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(Path.cwd()))
    resolved = Path(windows_system_executable("icacls.exe"))
    assert resolved.is_file()
    assert resolved.name.casefold() == "icacls.exe"
    assert resolved.parent != Path.cwd()


def test_checkpoint_read_failure_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    target = settings.workspace_root / "locked.txt"
    target.write_text("important", encoding="utf-8")
    original = Path.read_bytes

    def fail_target(path: Path) -> bytes:
        if path == target:
            raise PermissionError("sharing violation")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", fail_target)
    with pytest.raises(RuntimeError, match="could not capture locked.txt"):
        capture_workspace_state(settings, "capture-failure", "before")


def test_checkpoint_without_complete_capture_marker_is_rejected(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    operation = settings.data_dir / "workspace-history" / "operations" / "legacy" / "before"
    operation.mkdir(parents=True)
    manifest = operation / "manifest.json"
    manifest.write_text(
        json.dumps({"version": 2, "operation_id": "legacy", "stage": "before", "files": []}),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="complete-capture marker"):
        verify_checkpoint_integrity(settings, str(manifest))


def test_preflight_and_staged_journals_become_terminal_without_recovery(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    (settings.workspace_root / "a.txt").write_text("safe", encoding="utf-8")
    before = capture_workspace_state(settings, "staged-journal", "before")
    transaction = settings.data_dir / "workspace-history" / "transactions" / "staged-journal"
    transaction.mkdir()
    journal_path = transaction / "journal.json"
    journal_path.write_text(
        json.dumps(
            {
                "version": 1,
                "operation_id": "staged-journal",
                "kind": "workspace_restore",
                "state": "staged",
                "before_manifest": before.manifest_path,
                "target_manifest": before.manifest_path,
                "applied_paths": [],
            }
        ),
        encoding="utf-8",
    )
    journal = incomplete_workspace_transactions(settings)[0]
    recovered = recover_incomplete_workspace_transaction(settings, journal)
    assert recovered["state"] == "failed_preflight"
    mark_workspace_transaction_audit_reconciled(settings, "staged-journal")
    assert incomplete_workspace_transactions(settings) == []
    assert workspace_recovery_required(settings) is False


def test_corrupt_journal_blocks_mutation_fail_closed(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    transaction = settings.data_dir / "workspace-history" / "transactions" / "corrupt-op"
    transaction.mkdir()
    (transaction / "journal.json").write_bytes(b"not-json")
    journals = incomplete_workspace_transactions(settings)
    assert journals[0]["state"] == "recovery_required"
    assert workspace_recovery_required(settings) is True


def test_applied_verified_journal_restores_audit_consistency(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    (settings.workspace_root / "a.txt").write_text("target", encoding="utf-8")
    target = capture_workspace_state(settings, "applied-op", "after")
    audit = AuditStore(settings)
    audit.create_operation(
        operation_id="applied-op",
        tool_name="request_workspace_rollback",
        tier="approved_host",
        status="running",
        cwd=str(settings.workspace_root),
        request={},
    )
    transaction = settings.data_dir / "workspace-history" / "transactions" / "applied-op"
    transaction.mkdir()
    journal_path = transaction / "journal.json"
    journal_path.write_text(
        json.dumps(
            {
                "version": 1,
                "operation_id": "applied-op",
                "kind": "workspace_restore",
                "state": "applied_verified",
                "before_manifest": target.manifest_path,
                "target_manifest": target.manifest_path,
                "changed_paths": [],
                "applied_paths": [],
            }
        ),
        encoding="utf-8",
    )
    reconciled = AuditStore(settings).get_operation("applied-op", include_events=False)
    assert reconciled["status"] == "succeeded"
    assert reconciled["post_workspace_path"] == target.manifest_path
    assert json.loads(journal_path.read_text(encoding="utf-8"))["state"] == "complete"


def test_applied_verified_terminal_error_records_owned_after_checkpoint(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    (settings.workspace_root / "a.txt").write_text("applied", encoding="utf-8")
    foreign_target = capture_workspace_state(settings, "old-target", "after")
    audit = AuditStore(settings)
    audit.create_operation(
        operation_id="failed-rollback",
        tool_name="request_workspace_rollback",
        tier="approved_host",
        status="failed",
        cwd=str(settings.workspace_root),
        request={},
    )
    transaction = (
        settings.data_dir
        / "workspace-history"
        / "transactions"
        / "failed-rollback"
    )
    transaction.mkdir()
    journal_path = transaction / "journal.json"
    journal_path.write_text(
        json.dumps(
            {
                "version": 1,
                "operation_id": "failed-rollback",
                "kind": "workspace_restore",
                "state": "applied_verified",
                "before_manifest": foreign_target.manifest_path,
                "target_manifest": foreign_target.manifest_path,
                "changed_paths": [],
                "applied_paths": [],
            }
        ),
        encoding="utf-8",
    )

    reconciled = AuditStore(settings).get_operation(
        "failed-rollback", include_events=False
    )
    owned_after = (
        settings.data_dir
        / "workspace-history"
        / "operations"
        / "failed-rollback"
        / "after"
        / "manifest.json"
    )
    assert reconciled["status"] == "succeeded"
    assert reconciled["post_workspace_path"] == str(owned_after.resolve(strict=True))
    verify_checkpoint_integrity(settings, str(owned_after))
    assert json.loads(owned_after.read_text(encoding="utf-8"))["capture_complete"] is True
    assert json.loads(journal_path.read_text(encoding="utf-8"))["state"] == "complete"


def test_legacy_complete_journal_repairs_audit_before_marking_reconciled(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    (settings.workspace_root / "a.txt").write_text("applied", encoding="utf-8")
    foreign_target = capture_workspace_state(settings, "legacy-target", "after")
    audit = AuditStore(settings)
    audit.create_operation(
        operation_id="legacy-complete",
        tool_name="request_workspace_rollback",
        tier="approved_host",
        status="running",
        cwd=str(settings.workspace_root),
        request={},
    )
    transaction = (
        settings.data_dir
        / "workspace-history"
        / "transactions"
        / "legacy-complete"
    )
    transaction.mkdir()
    journal_path = transaction / "journal.json"
    journal_path.write_text(
        json.dumps(
            {
                "version": 1,
                "operation_id": "legacy-complete",
                "kind": "workspace_restore",
                "state": "complete",
                "before_manifest": foreign_target.manifest_path,
                "target_manifest": foreign_target.manifest_path,
                "changed_paths": [],
                "applied_paths": [],
            }
        ),
        encoding="utf-8",
    )

    reconciled = AuditStore(settings).get_operation(
        "legacy-complete", include_events=False
    )
    owned_after = (
        settings.data_dir
        / "workspace-history"
        / "operations"
        / "legacy-complete"
        / "after"
        / "manifest.json"
    )
    assert reconciled["status"] == "succeeded"
    assert reconciled["post_workspace_path"] == str(owned_after.resolve(strict=True))
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert journal["state"] == "complete"
    assert journal["audit_reconciled"] is True
    assert incomplete_workspace_transactions(settings) == []
