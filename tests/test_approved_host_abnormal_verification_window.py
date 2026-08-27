from __future__ import annotations

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


def test_abnormal_wmi_helper_outlives_fault_injection_budget() -> None:
    assert abnormal._ABNORMAL_OPERATION_RUNTIME_SECONDS >= 300
    # Loopback ping sends its first request immediately; N requests live for roughly N-1 seconds.
    assert (
        abnormal._ABNORMAL_WMI_HELPER_PING_COUNT - 1
        > abnormal._ABNORMAL_OPERATION_RUNTIME_SECONDS
    )
