from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from windows_local_mcp.approved_host_authority import (
    ApprovedHostRecoveryRequired,
    AuthorityWorkerIdentity,
    authority_completion_path,
)
from windows_local_mcp.approved_host_security import HardenedAuthorityStateStore
from windows_local_mcp.approved_host_worker_lease import HardenedAuthorityWorkerLease


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _arm(
    store: HardenedAuthorityStateStore,
    operation_id: str = "op-1",
) -> tuple[str, Path]:
    nonce = "authority-nonce"
    proof = authority_completion_path(store.root, operation_id, nonce)
    store.arm(
        operation_id=operation_id,
        authority_nonce=nonce,
        requester_pid=123,
        requester_create_time=456.0,
        requester_sid="test-runtime-user",
        context_sha256="a" * 64,
        proof_path=proof,
    )
    return nonce, proof


def test_running_and_recovery_updates_never_replace_immutable_active_latch(
    tmp_path: Path,
) -> None:
    store = HardenedAuthorityStateStore(tmp_path / "authority", "epoch-1")
    _arm(store)
    before = _sha256(store.active_path)

    store.mark_running(
        AuthorityWorkerIdentity(pid=10, create_time=20.0, executable="worker.exe")
    )
    assert _sha256(store.active_path) == before
    assert store.status_path.is_file()
    assert store.read_active()["state"] == "running"  # type: ignore[index]

    store.mark_recovery_required("worker lost", worker_exit_code=9)
    assert _sha256(store.active_path) == before
    active = store.read_active()
    assert active is not None
    assert active["state"] == "recovery_required"
    assert active["recovery_reason"] == "worker lost"
    assert active["worker_exit_code"] == 9


def test_status_without_active_latch_is_recovery_required(tmp_path: Path) -> None:
    store = HardenedAuthorityStateStore(tmp_path / "authority", "epoch-1")
    _arm(store)
    store.mark_recovery_required("test")
    store.active_path.unlink()

    with pytest.raises(ApprovedHostRecoveryRequired, match="status exists without"):
        store.read_active()


def test_normal_return_and_verified_postflight_clear_latch(tmp_path: Path) -> None:
    store = HardenedAuthorityStateStore(tmp_path / "authority", "epoch-1")
    nonce, proof = _arm(store)
    lease = HardenedAuthorityWorkerLease("op-1", "epoch-1", nonce, proof)
    lease.mark_child_started()
    lease.mark_postflight_verified()
    lease.finalize_normal_return(0)

    record = store.consume_completion(proof)

    assert record["state"] == "completed"
    assert record["proof"]["worker_returned_normally"] is True
    assert record["proof"]["postflight_verified"] is True
    assert store.read_active() is None
    assert not store.status_path.exists()


def test_child_without_verified_postflight_cannot_create_completion_proof(
    tmp_path: Path,
) -> None:
    store = HardenedAuthorityStateStore(tmp_path / "authority", "epoch-1")
    nonce, proof = _arm(store)
    lease = HardenedAuthorityWorkerLease("op-1", "epoch-1", nonce, proof)
    lease.mark_child_started()

    lease.finalize_normal_return(1)

    assert not proof.exists()
    assert store.read_active() is not None


def test_forged_legacy_proof_without_normal_return_does_not_clear_latch(
    tmp_path: Path,
) -> None:
    store = HardenedAuthorityStateStore(tmp_path / "authority", "epoch-1")
    nonce, proof = _arm(store)
    proof.write_text(
        '{"version":1,"operation_id":"op-1","service_epoch":"epoch-1",'
        f'"authority_nonce":"{nonce}","child_started":false,'
        '"postflight_verified":false,"worker_exit_code":1}',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="normal return"):
        store.consume_completion(proof)

    assert store.read_active() is not None


def test_service_epoch_change_stays_latched(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    first = HardenedAuthorityStateStore(root, "epoch-1")
    _arm(first)
    restarted = HardenedAuthorityStateStore(root, "epoch-2")

    with pytest.raises(ApprovedHostRecoveryRequired, match="earlier service epoch"):
        restarted.require_current_active()

    assert restarted.active_path.is_file()
