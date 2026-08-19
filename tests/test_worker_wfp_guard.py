from __future__ import annotations

import io
import subprocess
import sys
import time
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.policy import NormalizedCommand
from windows_local_mcp.process_utils import ProcessIdentity
from windows_local_mcp.sandbox_backend import ApprovedSandboxUnavailable, CodexSandboxBackend
from windows_local_mcp.worker import run_operation


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


def _backend() -> CodexSandboxBackend:
    executable = str(Path(sys.executable).resolve(strict=True))
    return CodexSandboxBackend(
        executable=executable,
        executable_sha256="a" * 64,
        executable_size=Path(executable).stat().st_size,
        executable_mtime_ns=Path(executable).stat().st_mtime_ns,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )


def _guard_payload() -> dict[str, object]:
    return {
        "guard_version": "wlmcp-wfp-loopback-guard-v1",
        "policy_generation": 1,
        "target_account": "CodexSandboxOffline",
        "target_sid": "S-1-5-21-100-200-300-1004",
        "app_isolation_sublayer_key": "ffe221c3-92a8-4564-a59f-dafb70756020",
        "app_isolation_weight": 7,
        "guard_sublayer_key": "7019c9c2-acc9-5a02-97cb-d9ccdca1b9ab",
        "guard_sublayer_weight": 10,
        "v4_filter_key": "0acea791-e272-5a9c-ae2f-5bf41970dd41",
        "v4_filter_id": 501,
        "v4_effective_weight": 100,
        "v6_filter_key": "cb98391f-1773-5060-bfb6-3de2306f8baa",
        "v6_filter_id": 502,
        "v6_effective_weight": 100,
        "static_nonpersistent": True,
        "dynamic_session": False,
        "persistent": False,
    }


class FakeChild:
    def __init__(self, *, exit_code: int = 0, timeout: bool = False) -> None:
        self.pid = 4242
        self.returncode: int | None = None
        self.stdout = io.BytesIO(b"worker output")
        self.stderr = io.BytesIO(b"")
        self.exit_code = exit_code
        self.timeout = timeout
        self.terminated = False

    def wait(self, timeout: float | None = None) -> int:
        if self.timeout and not self.terminated:
            time.sleep(min(float(timeout or 0), 0.05))
            raise subprocess.TimeoutExpired(["codex"], timeout)
        self.returncode = -1 if self.terminated else self.exit_code
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def close(self) -> None:
        pass


@dataclass
class FakeJob:
    violation: str | None = None
    calls: list[str] = field(default_factory=list)

    def terminate(self) -> None:
        self.calls.append("terminate")

    def wait_empty(self, *, timeout: float) -> bool:
        assert timeout == 10
        self.calls.append("wait_empty")
        return True

    def close(self) -> None:
        self.calls.append("close")


def _prepare_operation(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    *,
    max_runtime: int = 5,
) -> tuple[str, CodexSandboxBackend]:
    backend = _backend()
    normalized = NormalizedCommand(
        executable=str(Path(sys.executable).resolve(strict=True)),
        args=["-c", "pass"],
        cwd=str(settings.workspace_root),
        display_command=["python", "-c", "pass"],
        program_key="python",
        executable_identity={"test": True},
    )
    request: dict[str, Any] = {
        "normalized_command": normalized.model_dump(),
        "workspace_write": False,
        "max_runtime_seconds": max_runtime,
        "sandbox_backend": backend.as_dict(),
        "approval_manifest_digest": "manifest",
        "approval_manifest_summary": {"mode": "staged-cwd"},
    }
    audit = AuditStore(settings)
    operation_id = audit.create_operation(
        tool_name="request_sandbox_command",
        tier="codex_sandbox",
        status="queued",
        cwd=str(settings.workspace_root),
        request=request,
        request_hash="approved-hash",
        approval_status="claimed",
    )
    audit.update_operation(operation_id, process_nonce="nonce")

    monkeypatch.setattr("windows_local_mcp.worker.verify_control_plane_generation", lambda *_: None)
    monkeypatch.setattr("windows_local_mcp.worker.approved_request_hash", lambda _: "approved-hash")
    monkeypatch.setattr("windows_local_mcp.worker.verify_approval_bundle", lambda **_: normalized)
    monkeypatch.setattr(
        "windows_local_mcp.worker.materialize_execution_copy", lambda **_: normalized
    )
    monkeypatch.setattr("windows_local_mcp.worker.verify_codex_sandbox_backend", lambda *_: backend)
    monkeypatch.setattr(
        "windows_local_mcp.worker.require_codex_sandbox_live_verification", lambda *_: {}
    )
    monkeypatch.setattr(
        "windows_local_mcp.worker._ensure_approval_execution_fresh", lambda *_: None
    )
    monkeypatch.setattr(
        "windows_local_mcp.worker.hold_executable_identity",
        lambda *_: nullcontext(Path(sys.executable).resolve(strict=True)),
    )
    monkeypatch.setattr(
        "windows_local_mcp.worker.hold_codex_sandbox_backend", lambda value: nullcontext(value)
    )
    monkeypatch.setattr("windows_local_mcp.worker.probe_codex_version", lambda *_: "test")
    monkeypatch.setattr(
        "windows_local_mcp.worker.capture_process_identity",
        lambda pid, nonce: ProcessIdentity(
            pid=pid,
            create_time=1.0,
            executable=str(Path(sys.executable).resolve(strict=True)),
            nonce=nonce,
        ),
    )
    monkeypatch.setattr("windows_local_mcp.worker.process_tree_write_bytes", lambda *_: 0)
    return operation_id, backend


@pytest.mark.parametrize(
    ("scenario", "exit_code", "timeout", "violation", "expected_status", "failure_class"),
    [
        ("normal", 0, False, None, "succeeded", None),
        ("command_failure", 7, False, None, "failed", "command_failure"),
        ("timeout", 0, True, None, "timed_out", "runtime_limit"),
        (
            "resource_violation",
            0,
            False,
            "process_count_limit",
            "failed",
            "sandbox_resource_policy",
        ),
    ],
)
def test_worker_guarded_sandbox_outcomes_keep_job_cleanup_and_never_remove_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    exit_code: int,
    timeout: bool,
    violation: str | None,
    expected_status: str,
    failure_class: str | None,
) -> None:
    settings = _settings(tmp_path)
    operation_id, _backend_value = _prepare_operation(
        settings, monkeypatch, max_runtime=1 if timeout else 5
    )
    child = FakeChild(exit_code=exit_code, timeout=timeout)
    job = FakeJob(violation=violation)
    calls: list[str] = []

    def guarded_launch(
        *_args: object, **kwargs: object
    ) -> tuple[object, object, list[str], dict[str, object]]:
        calls.append("guard_ensure")
        callback = kwargs["on_guard_verified"]
        callback(_guard_payload())
        calls.append("codex_launch")
        return child, job, ["codex", "sandbox"], _guard_payload()

    def forbidden_remove(*_args: object, **_kwargs: object) -> None:
        calls.append("guard_remove")
        raise AssertionError("worker must never remove the always-on WFP block")

    monkeypatch.setattr("windows_local_mcp.worker.guard_and_launch_codex_sandbox", guarded_launch)
    monkeypatch.setattr(
        "windows_local_mcp.wfp_guard.maintenance_remove_codex_loopback_block",
        forbidden_remove,
    )
    monkeypatch.setattr(
        "windows_local_mcp.worker._terminate_launched_child",
        lambda launched, _identity: launched.terminate(),
    )
    assert run_operation(operation_id, settings) == (0 if expected_status == "succeeded" else 1)

    record = AuditStore(settings).get_operation(operation_id, include_events=True)
    assert record["status"] == expected_status, scenario
    assert record["result"]["failure_class"] == failure_class
    assert record["result"]["host_fallback_performed"] is False
    assert record["result"]["wfp_guard_verification"]["target_sid"].startswith("S-1-")
    event_types = [event["event_type"] for event in record["events"]]
    assert event_types.index("wfp_guard_verified") < event_types.index("child_started")
    assert calls == ["guard_ensure", "codex_launch"]
    expected_cleanup = (
        ["terminate", "terminate", "wait_empty", "close"]
        if violation is not None
        else ["terminate", "wait_empty", "close"]
    )
    assert job.calls == expected_cleanup


def test_worker_launcher_failure_after_guard_is_fail_closed_without_host_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    operation_id, _backend_value = _prepare_operation(settings, monkeypatch)
    calls: list[str] = []

    def launcher_failure(*_args: object, **kwargs: object) -> object:
        kwargs["on_guard_verified"](_guard_payload())
        calls.extend(("guard_ensure", "launcher_failure"))
        raise OSError("launcher failed")

    monkeypatch.setattr("windows_local_mcp.worker.guard_and_launch_codex_sandbox", launcher_failure)
    assert run_operation(operation_id, settings) == 1
    record = AuditStore(settings).get_operation(operation_id, include_events=True)
    assert record["result"]["failure_class"] == "launcher_failure"
    assert record["result"]["host_fallback_performed"] is False
    assert calls == ["guard_ensure", "launcher_failure"]


def test_worker_guard_failure_prevents_launch_and_has_no_host_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    operation_id, _backend_value = _prepare_operation(settings, monkeypatch)
    launches: list[str] = []

    def guard_failure(*_args: object, **_kwargs: object) -> object:
        raises = ApprovedSandboxUnavailable("Codex Sandbox WFP Guard verification failed")
        raise raises

    def forbidden_popen(*_args: object, **_kwargs: object) -> object:
        launches.append("popen")
        raise AssertionError("Guard failure must prevent every child launch")

    monkeypatch.setattr("windows_local_mcp.worker.guard_and_launch_codex_sandbox", guard_failure)
    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)
    assert run_operation(operation_id, settings) == 1
    record = AuditStore(settings).get_operation(operation_id, include_events=True)
    assert record["result"]["failure_class"] == "sandbox_backend_failure"
    assert record["result"]["host_fallback_performed"] is False
    assert record["network_policy"]["wfp_guard_status"] == "verification_failed"
    assert record["network_policy"]["enforcement_status"] == "prepared"
    assert "wfp_guard" not in record["network_policy"]
    event_types = [event["event_type"] for event in record["events"]]
    assert "wfp_guard_verification_failed" in event_types
    assert "child_started" not in event_types
    assert launches == []
