from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.policy import approved_request_hash
from windows_local_mcp.sandbox_backend import (
    SANDBOX_SECURITY_PROPERTIES,
    ApprovedSandboxUnavailable,
    CodexSandboxBackend,
    build_codex_sandbox_argv,
    codex_sandbox_effective_policy,
    require_codex_sandbox_live_verification,
    resolve_codex_sandbox_backend,
)
from windows_local_mcp.sandbox_live_verify import (
    _host_endpoint_reachable,
    _property_results,
    _protected_information_canary_path,
)
from windows_local_mcp.sandbox_live_verify import _run as run_live_probe
from windows_local_mcp.util import canonical_json, sha256_text
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


def test_live_verification_properties_distinguish_failed_from_unverified() -> None:
    properties = _property_results(
        {
            "source_read": True,
            "outside_user_read_denied": False,
            "control_plane_read_denied": True,
            "scratch_write": True,
            "source_workspace_write_denied": True,
            "outside_user_write_denied": True,
            "control_plane_write_denied": True,
        }
    )

    assert properties["filesystem_read"]["status"] == "failed"
    assert properties["filesystem_read"]["failed"] == ["outside_user_read_denied"]
    assert properties["filesystem_write"]["status"] == "verified"
    assert properties["resource_bound"]["status"] == "unverified"
    assert properties["resource_bound"]["failed"] == []
    assert "process_limit_enforced" in properties["resource_bound"]["unverified"]
    assert properties["internet"]["status"] == "unverified"
    assert properties["internet"]["unverified"] == ["internet_denied"]
    assert properties["lan"]["status"] == "unverified"
    assert properties["lan"]["unverified"] == ["lan_denied"]

    failed_network = _property_results(
        {"internet_denied": False, "lan_denied": False}
    )
    assert failed_network["internet"]["status"] == "failed"
    assert failed_network["lan"]["status"] == "failed"


def test_protected_information_canary_uses_exact_blocked_filename(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    first = _protected_information_canary_path(workspace)
    second = _protected_information_canary_path(workspace)

    assert first.name == ".env"
    assert first.parent.parent == workspace
    assert first.parent.name.startswith(".wlmcp-live-protected-")
    assert second.parent != first.parent


def test_host_endpoint_control_distinguishes_reachable_from_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, int], float]] = []

    class Connection:
        def close(self) -> None:
            return None

    def connect(endpoint: tuple[str, int], *, timeout: float) -> Connection:
        calls.append((endpoint, timeout))
        return Connection()

    monkeypatch.setattr("socket.create_connection", connect)
    assert _host_endpoint_reachable("1.1.1.1", 443, timeout=3) is True
    assert calls == [(("1.1.1.1", 443), 3)]

    def unavailable(_endpoint: tuple[str, int], *, timeout: float) -> Connection:
        raise OSError(f"unreachable after {timeout}")

    monkeypatch.setattr("socket.create_connection", unavailable)
    assert _host_endpoint_reachable("1.1.1.1", 443) is False


def test_sandbox_live_verification_is_property_scoped_and_fails_closed(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    backend = CodexSandboxBackend(
        executable=str(tmp_path / "codex.exe"),
        executable_sha256="a" * 64,
        executable_size=1,
        executable_mtime_ns=1,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )
    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    backend_digest = sha256_text(canonical_json(backend.as_dict()))
    marker.write_text(
        canonical_json(
            {
                "version": 1,
                "passed": True,
                "backend_digest": backend_digest,
                "checks": {"network_denied": True},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ApprovedSandboxUnavailable, match="missing, failed, or stale"):
        require_codex_sandbox_live_verification(settings, backend)

    properties = {
        name: {"status": "verified"} for name in SANDBOX_SECURITY_PROPERTIES
    }
    properties["resource_bound"] = {"status": "unverified"}
    marker.write_text(
        canonical_json(
            {
                "version": 2,
                "passed": True,
                "backend_digest": backend_digest,
                "properties": properties,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ApprovedSandboxUnavailable, match="missing, failed, or stale"):
        require_codex_sandbox_live_verification(settings, backend)

    properties["resource_bound"] = {"status": "verified"}
    marker.write_text(
        canonical_json(
            {
                "version": 2,
                "passed": True,
                "backend_digest": backend_digest,
                "properties": properties,
            }
        ),
        encoding="utf-8",
    )
    assert require_codex_sandbox_live_verification(settings, backend)["version"] == 2

    settings.approved_sandbox_require_live_verification = False
    with pytest.raises(ApprovedSandboxUnavailable, match="cannot be disabled"):
        require_codex_sandbox_live_verification(settings, backend)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process-tree live check")
def test_live_probe_timeout_terminates_descendant_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    python = str((Path(sys.base_prefix) / "python.exe").resolve(strict=True))
    backend = CodexSandboxBackend(
        executable=python,
        executable_sha256="a" * 64,
        executable_size=Path(python).stat().st_size,
        executable_mtime_ns=Path(python).stat().st_mtime_ns,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )
    heartbeat = settings.sandbox_scratch_dir / "timeout-heartbeat.bin"
    child_code = (
        "from pathlib import Path\n"
        "import time\n"
        f"path=Path({str(heartbeat)!r})\n"
        "while True:\n"
        " with path.open('ab') as output: output.write(b'x')\n"
        " time.sleep(.05)\n"
    )
    parent_code = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable,'-I','-c',{child_code!r}]);"
        "time.sleep(60)"
    )
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_live_verify.build_codex_sandbox_argv",
        lambda _backend, *, command, cwd: command,
    )

    probe_diagnostics: list[dict[str, object]] = []
    with pytest.raises(subprocess.TimeoutExpired):
        run_live_probe(
            settings,
            backend,
            settings.sandbox_scratch_dir,
            [python, "-I", "-c", parent_code],
            timeout=1,
            probe_name="timeout-regression",
            probe_diagnostics=probe_diagnostics,
        )

    size_after_stop = heartbeat.stat().st_size
    time.sleep(0.3)
    assert heartbeat.stat().st_size == size_after_stop
    assert probe_diagnostics[0]["probe"] == "timeout-regression"
    assert probe_diagnostics[0]["pid"]
    assert probe_diagnostics[0]["timed_out"] is True
    assert probe_diagnostics[0]["child_process_state"] == "terminated_and_drained"


def test_approved_request_hash_binds_capability_fields() -> None:
    request: dict[str, object] = {
        "approval_binding_version": 3,
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
            sandbox_dependency_readable_paths=[tmp_path],
        )


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
