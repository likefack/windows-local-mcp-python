from __future__ import annotations

from types import SimpleNamespace

import pytest

from windows_local_mcp import approved_host_live_verification as live


def test_live_verifier_keeps_requester_alive_through_slow_preflight(
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
            return {
                "status": "running",
                "child_pid": 4242 if clock[0] >= 55.0 else None,
            }

    monkeypatch.setattr(live.time, "monotonic", monotonic)
    monkeypatch.setattr(live.time, "sleep", sleep)

    result = live._wait_for_child(SimpleNamespace(audit=_Audit()), "op-live")

    assert result["child_pid"] == 4242
    assert clock[0] >= 55.0
    assert live._LIVE_CHILD_START_TIMEOUT_SECONDS >= 60.0
