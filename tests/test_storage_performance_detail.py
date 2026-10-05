from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from windows_local_mcp import performance_trace, resources
from windows_local_mcp import workspace_history as history
from windows_local_mcp.config import Settings
from windows_local_mcp.performance_trace import operation_trace
from windows_local_mcp.resources import NamedControlPlaneLock, WorkspaceExecutionLock
from windows_local_mcp.util import sha256_bytes


def settings_for(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
    )
    settings.ensure_directories()
    return settings


def phase_names(trace) -> set[str]:
    return {item["name"] for item in trace.to_payload()["phases"]}


@pytest.mark.parametrize("scoped", [False, True])
def test_checkpoint_capture_reuse_and_verification_have_separate_timings(
    tmp_path: Path, scoped: bool
) -> None:
    settings = settings_for(tmp_path)
    data = b"checkpoint test payload"
    (settings.workspace_root / "fixture.txt").write_bytes(data)
    paths = {"fixture.txt"} if scoped else None
    with operation_trace() as first_trace:
        first = history.capture_workspace_state(settings, "first", "before", paths=paths)
    assert {
        "control_plane_lock_wait",
        "checkpoint_capture",
        "checkpoint_scan",
        "checkpoint_hash",
        "checkpoint_blob_store",
        "checkpoint_manifest_write",
        "data_directory_scan",
        "quota_validation",
    } <= phase_names(first_trace)

    with operation_trace() as reused_trace:
        second = history.capture_workspace_state(settings, "second", "before", paths=paths)
        verified = history.verify_checkpoint_integrity(settings, second.manifest_path)
    assert verified == {"fixture.txt": sha256_bytes(data)}
    assert {
        "checkpoint_blob_verify", "checkpoint_manifest_load", "checkpoint_hash"
    } <= phase_names(reused_trace)
    assert first.file_count == second.file_count == 1
    assert len(list((settings.data_dir / "workspace-history" / "blobs").glob("*.blob"))) == 1
    # Diagnostic records contain no paths, file contents, or digests.
    timing_json = json.dumps(reused_trace.to_payload())
    assert "fixture.txt" not in timing_json
    assert data.decode() not in timing_json
    assert sha256_bytes(data) not in timing_json


def test_corrupt_reused_blob_preserves_failure_and_checkpoint_cleanup(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    data = b"original"
    (settings.workspace_root / "fixture.txt").write_bytes(data)
    history.capture_workspace_state(settings, "original", "before")
    blob = settings.data_dir / "workspace-history" / "blobs" / f"{sha256_bytes(data)}.blob"
    blob.write_bytes(b"corrupt")
    with (
        pytest.raises(RuntimeError, match="checkpoint blob is corrupt"),
        operation_trace() as trace,
    ):
        history.capture_workspace_state(settings, "failed", "before")
    assert trace.to_payload()["failed_phase"] == "checkpoint_blob_verify"
    assert blob.read_bytes() == b"corrupt"
    assert not (settings.data_dir / "workspace-history" / "operations" / "failed" / "before").exists()


def test_storage_without_trace_does_not_read_diagnostic_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(tmp_path)
    (settings.workspace_root / "fixture.txt").write_bytes(b"unchanged")

    def unexpected_clock_read() -> int:
        pytest.fail("inactive storage instrumentation read the diagnostic clock")

    monkeypatch.setattr(performance_trace.time, "perf_counter_ns", unexpected_clock_read)
    with WorkspaceExecutionLock(settings, target=settings.workspace_root / "fixture.txt"):
        state = history.capture_workspace_state(settings, "untraced", "before")
        assert history.verify_checkpoint_integrity(settings, state.manifest_path)
        resources.prune_artifacts(settings, protected_ids={"untraced"})


def test_quota_failure_and_artifact_pruning_are_separate_phases(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    expired = settings.data_dir / "outputs" / "old-output.log"
    expired.write_bytes(b"output")
    os.utime(expired, (0, 0))
    with operation_trace() as pruning_trace:
        removed = resources.prune_artifacts(settings)
    assert removed >= 1
    assert not expired.exists()
    assert {"artifact_pruning", "data_directory_scan"} <= phase_names(pruning_trace)

    with (
        pytest.raises(RuntimeError, match="data_dir quota exceeded"),
        operation_trace() as quota_trace,
    ):
        resources.enforce_data_quota(settings, incoming_bytes=settings.max_data_dir_bytes + 1)
    assert phase_names(quota_trace) == {"quota_validation", "data_directory_scan"}
    assert quota_trace.to_payload()["failed_phase"] == "quota_validation"


class ControlledClock:
    def __init__(self) -> None:
        self.now_ns = 0

    def perf_counter_ns(self) -> int:
        return self.now_ns

    def monotonic(self) -> float:
        return self.now_ns / 1_000_000_000

    def sleep(self, seconds: float) -> None:
        self.now_ns += round(seconds * 1_000_000_000)


class ControlledLock:
    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.held = False
        self.releases = 0

    def acquire(self, *, blocking: bool) -> bool:
        assert not blocking
        if self.failures:
            self.failures -= 1
            return False
        assert not self.held
        self.held = True
        return True

    def release(self) -> None:
        assert self.held
        self.held = False
        self.releases += 1


def controlled_lock(monkeypatch: pytest.MonkeyPatch, failures: int):
    clock = ControlledClock()
    lock = ControlledLock(failures)
    monkeypatch.setattr(performance_trace.time, "perf_counter_ns", clock.perf_counter_ns)
    monkeypatch.setattr(resources.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(resources.time, "sleep", clock.sleep)
    monkeypatch.setattr(resources, "_local_lock_for", lambda _path: lock)
    return clock, lock


def storage_lock(settings: Settings, kind: str, timeout: float = 1.0):
    if kind == "workspace_lock_wait":
        return WorkspaceExecutionLock(settings, timeout, target=settings.workspace_root / "a.txt")
    return NamedControlPlaneLock(settings, "test-storage-detail", timeout)


@pytest.mark.parametrize("kind", ["workspace_lock_wait", "control_plane_lock_wait"])
def test_lock_wait_duration_excludes_protected_body_and_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    settings = settings_for(tmp_path)
    clock, lock = controlled_lock(monkeypatch, failures=1)
    with operation_trace() as trace, storage_lock(settings, kind):
        assert lock.held
        clock.sleep(3.0)
    payload = trace.to_payload()
    assert len(payload["phases"]) == 1
    assert payload["phases"][0]["name"] == kind
    assert payload["phases"][0]["duration_ns"] == 50_000_000
    assert payload["total_ns"] == 3_050_000_000
    assert not lock.held
    assert lock.releases == 1
    # Reacquisition also exercises OS lock release, independently of the diagnostic clock.
    with storage_lock(settings, kind):
        assert lock.held
    assert lock.releases == 2


@pytest.mark.parametrize("kind", ["workspace_lock_wait", "control_plane_lock_wait"])
def test_lock_timeout_is_measured_without_holding_lock_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    settings = settings_for(tmp_path)
    _clock, lock = controlled_lock(monkeypatch, failures=100)
    with (
        pytest.raises(TimeoutError),
        operation_trace() as trace,
        storage_lock(settings, kind, timeout=0.1),
    ):
        pytest.fail("timed-out lock entered protected body")
    payload = trace.to_payload()
    assert payload["failed_phase"] == kind
    assert payload["phases"][0]["duration_ns"] == 100_000_000
    assert not lock.held
    assert lock.releases == 0
    lock.failures = 0
    with storage_lock(settings, kind):
        pass
    assert lock.releases == 1


def test_nested_control_plane_lock_keeps_outer_lock_until_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(tmp_path)
    clock, lock = controlled_lock(monkeypatch, failures=1)
    with operation_trace() as trace, NamedControlPlaneLock(settings, "nested-timing"):
        clock.sleep(2.0)
        with NamedControlPlaneLock(settings, "nested-timing"):
            clock.sleep(1.0)
        assert lock.held
        assert lock.releases == 0
    assert lock.releases == 1
    phases = trace.to_payload()["phases"]
    assert [item["duration_ns"] for item in phases] == [50_000_000, 0]
    assert all(item["name"] == "control_plane_lock_wait" for item in phases)


def test_scoped_restore_measures_manifest_scan_and_durable_journal(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    target = settings.workspace_root / "target.txt"
    unrelated = settings.workspace_root / "unrelated.txt"
    target.write_bytes(b"before")
    before = history.capture_workspace_state(settings, "before", "before", paths={"target.txt"})
    target.write_bytes(b"after")
    after = history.capture_workspace_state(settings, "after", "after", paths={"target.txt"})
    unrelated.write_bytes(b"keep")
    with operation_trace() as trace:
        result = history.restore_workspace_state(
            settings, after.manifest_path, before.manifest_path, operation_id="restore"
        )
    assert target.read_bytes() == b"before"
    assert unrelated.read_bytes() == b"keep"
    assert result["rollback_scope"] == {"kind": "paths", "paths": ["target.txt"]}
    assert {"checkpoint_manifest_load", "checkpoint_scan", "journal_write"} <= phase_names(trace)
    journal = json.loads(Path(result["transaction_journal"]).read_text(encoding="utf-8"))
    # Audit reconciliation owns completion; restore must retain the pending finalization state.
    assert journal["state"] == "applied_verified"


def test_recovery_keeps_starting_contents_and_records_journal_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(tmp_path)
    target = settings.workspace_root / "target.txt"
    target.write_bytes(b"before")
    before = history.capture_workspace_state(settings, "before", "before")
    target.write_bytes(b"current")
    current = history.capture_workspace_state(settings, "current", "before")
    apply_manifest = history._apply_manifest
    calls = 0

    def fail_after_first_apply(*args, **kwargs):
        nonlocal calls
        calls += 1
        apply_manifest(*args, **kwargs)
        if calls == 1:
            raise OSError("injected apply failure")

    monkeypatch.setattr(history, "_apply_manifest", fail_after_first_apply)
    with pytest.raises(history.WorkspaceMutationError) as caught, operation_trace() as trace:
        history.restore_workspace_state(
            settings, current.manifest_path, before.manifest_path, operation_id="recover"
        )
    assert caught.value.recovery_state == "failed_recovered"
    assert target.read_bytes() == b"current"
    journal = json.loads(Path(caught.value.journal_path).read_text(encoding="utf-8"))
    assert journal["state"] == "failed_recovered"
    assert "journal_write" in phase_names(trace)
