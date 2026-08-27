from __future__ import annotations

from pathlib import Path

import pytest

from windows_local_mcp.approved_host_authority import (
    ApprovedHostRecoveryRequired,
    AuthorityStateStore,
    AuthorityWorkerLease,
    authority_completion_path,
)


def _arm(store: AuthorityStateStore, operation_id: str = "op-1") -> tuple[str, Path]:
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


def test_authority_state_is_one_operation_at_a_time(tmp_path: Path) -> None:
    store = AuthorityStateStore(tmp_path / "authority", "epoch-1")
    _arm(store)

    with pytest.raises(ApprovedHostRecoveryRequired, match="previous Approved Host"):
        _arm(store, "op-2")

    active = store.read_active()
    assert active is not None
    assert active["operation_id"] == "op-1"


def test_child_without_verified_postflight_keeps_active_state(tmp_path: Path) -> None:
    store = AuthorityStateStore(tmp_path / "authority", "epoch-1")
    nonce, proof = _arm(store)
    lease = AuthorityWorkerLease("op-1", "epoch-1", nonce, proof)
    lease.mark_child_started()

    lease.finalize(1)

    assert not proof.exists()
    assert store.read_active() is not None


def test_verified_postflight_clears_matching_active_state(tmp_path: Path) -> None:
    store = AuthorityStateStore(tmp_path / "authority", "epoch-1")
    nonce, proof = _arm(store)
    lease = AuthorityWorkerLease("op-1", "epoch-1", nonce, proof)
    lease.mark_child_started()
    lease.mark_postflight_verified()
    lease.finalize(0)

    record = store.consume_completion(proof)

    assert record["state"] == "completed"
    assert record["proof"]["postflight_verified"] is True
    assert store.read_active() is None


def test_prelaunch_failure_can_clear_without_child_postflight(tmp_path: Path) -> None:
    store = AuthorityStateStore(tmp_path / "authority", "epoch-1")
    nonce, proof = _arm(store)
    lease = AuthorityWorkerLease("op-1", "epoch-1", nonce, proof)

    lease.finalize(1)
    record = store.consume_completion(proof)

    assert record["proof"]["child_started"] is False
    assert record["proof"]["postflight_verified"] is False
    assert store.read_active() is None


def test_service_epoch_change_requires_recovery(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    first = AuthorityStateStore(root, "epoch-1")
    _arm(first)
    restarted = AuthorityStateStore(root, "epoch-2")

    with pytest.raises(ApprovedHostRecoveryRequired, match="earlier service epoch"):
        restarted.require_current_active()

    assert restarted.read_active() is not None
