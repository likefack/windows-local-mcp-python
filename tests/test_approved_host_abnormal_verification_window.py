from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from windows_local_mcp import approved_host_abnormal_verification as abnormal


def test_abnormal_wait_keeps_requester_alive_through_slow_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]

    def monotonic() -> float:
        return clock[0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    class _Audit:
        def get_operation(
            self,
            _operation_id: str,
            *,
            include_events: bool,
        ) -> dict[str, object]:
            assert include_events is False
            started = clock[0] >= 55.0
            return {
                "status": "running",
                "worker_pid": 4242 if started else None,
                "child_pid": 4343 if started else None,
            }

    monkeypatch.setattr(abnormal.time, "monotonic", monotonic)
    monkeypatch.setattr(abnormal.time, "sleep", sleep)

    result = abnormal._wait_worker_and_child(SimpleNamespace(audit=_Audit()), "op-abnormal")

    assert result["worker_pid"] == 4242
    assert result["child_pid"] == 4343
    assert clock[0] >= 55.0
    assert abnormal._ABNORMAL_CHILD_START_TIMEOUT_SECONDS >= 60.0


def test_abnormal_arm_waits_for_authenticated_recovery_after_service_epoch_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    probes: list[object] = [
        {
            "healthy": False,
            "active_operation_id": "op-abnormal",
            "recovery_reason": None,
            "service_epoch": "epoch-before",
        },
        abnormal.ApprovedHostAuthorityUnavailable("service restarting"),
        {
            "healthy": False,
            "active_operation_id": "op-abnormal",
            "recovery_reason": "SYSTEM worker exited without an authority completion proof",
            "service_epoch": "epoch-before",
        },
        {
            "healthy": False,
            "active_operation_id": "op-abnormal",
            "recovery_reason": "authority service restarted while an operation was active",
            "service_epoch": "epoch-after",
        },
    ]

    class _Client:
        def probe(self) -> dict[str, object]:
            value = probes.pop(0)
            if isinstance(value, Exception):
                raise value
            assert isinstance(value, dict)
            return value

    class _Audit:
        def get_operation(
            self,
            _operation_id: str,
            *,
            include_events: bool,
        ) -> dict[str, object]:
            assert include_events is False
            return {"status": "running"}

    monkeypatch.setattr(abnormal, "ApprovedHostAuthorityClient", lambda: _Client())
    monkeypatch.setattr(abnormal.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(abnormal.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    result = abnormal._wait_for_fault_injection_recovery(
        SimpleNamespace(audit=_Audit()),
        "op-abnormal",
        initial_service_epoch="epoch-before",
        timeout=10.0,
    )

    assert result["service_epoch"] == "epoch-after"
    assert result["recovery_reason"]
    assert not probes


def test_abnormal_arm_rejects_normal_completion_before_fault_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]

    class _Client:
        def probe(self) -> dict[str, object]:
            return {
                "healthy": False,
                "active_operation_id": "op-abnormal",
                "recovery_reason": None,
                "service_epoch": "epoch-before",
            }

    class _Audit:
        def get_operation(
            self,
            _operation_id: str,
            *,
            include_events: bool,
        ) -> dict[str, object]:
            assert include_events is False
            return {"status": "succeeded"}

    monkeypatch.setattr(abnormal, "ApprovedHostAuthorityClient", lambda: _Client())
    monkeypatch.setattr(abnormal.time, "monotonic", lambda: clock[0])

    with pytest.raises(AssertionError, match="became terminal"):
        abnormal._wait_for_fault_injection_recovery(
            SimpleNamespace(audit=_Audit()),
            "op-abnormal",
            initial_service_epoch="epoch-before",
            timeout=10.0,
        )


def test_abnormal_wmi_helper_is_indefinite_but_worker_deadline_remains_product_bounded() -> None:
    source = inspect.getsource(abnormal.arm_abnormal)

    assert 'helper_command = f\'"{ping}" -t 127.0.0.1\'' in source
    assert "server.runtime.settings.default_max_runtime_seconds" in source
    assert "_wait_for_fault_injection_recovery" in source


def test_abnormal_admin_phase_rechecks_wmi_helper_across_worker_loss_and_restart() -> None:
    script = (
        Path(__file__).resolve().parents[1] / "verify-approved-host-authority-abnormal.ps1"
    ).read_text(encoding="utf-8")

    assert 'Assert-WmiHelperIdentities -Handoff $handoff -Stage "before worker loss"' in script
    assert (
        'Assert-WmiHelperIdentities -Handoff $handoff -Stage "after SYSTEM worker loss"'
        in script
    )
    assert (
        'Assert-WmiHelperIdentities -Handoff $handoff -Stage "after authority service restart"'
        in script
    )
    assert "ABNORMAL_ARM_READY" in script
