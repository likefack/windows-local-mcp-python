"""転送の終了・期限切れを、監査のbegin成功と区別して表示する回帰検査。"""
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from test_live_activity import _FakeAudit, _operation

import windows_local_mcp.live_activity as activity
from windows_local_mcp.transfer_activity import TransferActivityState


def tracker_with_state(monkeypatch, state, *, full=False):
    operation = _operation(
        "begin", "artifact_upload_begin",
        result={"transfer_id": "transfer", "path": "sample.bin", "total_bytes": 4},
        events=[{"event_type": "artifact_upload_chunk", "payload": {"result": {"received": 4, "complete": True}}}] if full else [],
    )
    audit = _FakeAudit([operation])
    audit.settings = SimpleNamespace()
    current = [state]
    moment = [0.0]
    monkeypatch.setattr(activity, "read_transfer_activity_state", lambda *args: current[0])
    tracker = activity.LiveActivityTracker(
        audit, clock=lambda: moment[0], now=lambda: datetime(2026, 8, 31, 12, tzinfo=UTC),
    )
    return tracker, current, moment, audit


@pytest.mark.parametrize("state", ["cancelled", "expired", "failed", "committed"])
@pytest.mark.parametrize("full", [False, True])
def test_terminal_transfer_is_not_replayed_or_polled(monkeypatch, state, full):
    tracker, _, moment, _ = tracker_with_state(monkeypatch, TransferActivityState(state), full=full)
    assert tracker.poll_once() == []
    moment[0] = 3600.0
    assert tracker.poll_once() == []


@pytest.mark.parametrize("state,label", [("cancelled", "Cancelled"), ("expired", "Expired"), ("failed", "Failed"), ("committed", "Uploaded")])
def test_live_transfer_terminal_transition_is_shown_once(monkeypatch, state, label):
    tracker, current, moment, _ = tracker_with_state(monkeypatch, TransferActivityState("open"))
    assert "Waiting" in tracker.poll_once()[0]
    current[0] = TransferActivityState(state, "2026-08-31T11:01:00+00:00")
    lines = tracker.poll_once()
    assert len(lines) == 1 and label in lines[0] and "Running" not in lines[0]
    assert "60.000秒" in lines[0]
    moment[0] = 10.0
    assert tracker.poll_once() == []


def test_unknown_transfer_is_not_claimed_running_and_can_recover(monkeypatch):
    tracker, current, moment, _ = tracker_with_state(monkeypatch, TransferActivityState("unavailable"))
    lines = tracker.poll_once()
    assert len(lines) == 1 and "Unknown" in lines[0] and "Running" not in lines[0]
    moment[0] = 10.0
    assert tracker.poll_once() == []
    current[0] = TransferActivityState("open")
    assert "Waiting" in tracker.poll_once()[0]
    moment[0] = 20.0
    assert tracker.poll_once() == []


def test_unknown_old_transfer_is_rechecked_beyond_history_limit(monkeypatch):
    tracker, current, _, audit = tracker_with_state(monkeypatch, TransferActivityState("open"))
    tracker.limit = 1
    assert "Waiting" in tracker.poll_once()[0]
    audit.add(_operation("new", "read_file", path="new.txt"))
    current[0] = TransferActivityState("unavailable")
    assert any("Unknown" in line for line in tracker.poll_once())
    current[0] = TransferActivityState("cancelled")
    assert any("Cancelled" in line for line in tracker.poll_once())
    assert tracker.poll_once() == []


def test_complete_bytes_still_wait_for_upload_commit(monkeypatch):
    tracker, _, moment, _ = tracker_with_state(monkeypatch, TransferActivityState("open"), full=True)
    line = tracker.poll_once()[0]
    assert "Waiting" in line and "4/4バイト" in line and "保存確定待ち" in line
    moment[0] = 10.0
    assert tracker.poll_once() == []


@pytest.mark.parametrize("full", [False, True])
def test_open_transfer_does_not_repeat_without_new_progress(monkeypatch, full):
    tracker, _, moment, audit = tracker_with_state(monkeypatch, TransferActivityState("open"), full=full)
    line = tracker.poll_once()[0]
    assert "Waiting" in line and "Running" not in line and "経過" not in line
    assert ("保存確定待ち" if full else "データ待ち") in line
    # 期限切れを待たなくても、監視を再開しただけでは実行中にならない。
    for moment[0] in (5.5, 11.0, 30.0, 3600.0):
        assert tracker.poll_once() == []
    if not full:
        audit.operations["begin"]["events"].append({
            "event_type": "artifact_upload_chunk",
            "occurred_at": "2026-08-31T11:00:30+00:00",
            "payload": {"result": {"received": 2}},
        })
        changed = tracker.poll_once()
        assert len(changed) == 1 and "2/4バイト" in changed[0] and "Waiting" in changed[0]
        moment[0] += 5.5
        assert tracker.poll_once() == []


def test_waiting_transfer_beyond_history_limit_still_observes_progress_and_expiry(monkeypatch):
    tracker, current, moment, audit = tracker_with_state(monkeypatch, TransferActivityState("open"))
    tracker.limit = 1
    assert "Waiting" in tracker.poll_once()[0]
    audit.add(_operation("new", "read_file", path="new.txt"))
    tracker.poll_once()
    moment[0] = 6
    assert tracker.poll_once() == []
    current[0] = TransferActivityState("expired")
    lines = tracker.poll_once()
    assert len(lines) == 1 and "Expired" in lines[0]
    moment[0] = 12
    assert tracker.poll_once() == []


def test_audit_failure_is_not_overridden_by_transfer_success(monkeypatch):
    tracker, _, _, audit = tracker_with_state(monkeypatch, TransferActivityState("committed"))
    assert "Uploaded" not in "\n".join(tracker.poll_once())
    audit.operations["begin"]["status"] = "failed"
    assert "Failed" in tracker.poll_once()[0]
