from __future__ import annotations

from windows_local_mcp import wfp_guard_runtime as runtime


def test_c6_4_crash_window_waits_only_when_marker_exists(tmp_path, monkeypatch) -> None:
    marker = tmp_path / ".c6-4-wfp-helper-pause"
    waits: list[float] = []

    class FakeEvent:
        def wait(self, timeout: float) -> None:
            waits.append(timeout)

    monkeypatch.setattr(runtime, "_C6_4_CRASH_MARKER", marker)
    monkeypatch.setattr(runtime.threading, "Event", lambda: FakeEvent())

    runtime._wait_for_c6_4_crash_window()
    assert waits == []

    marker.write_text("c6.4\n", encoding="utf-8")
    runtime._wait_for_c6_4_crash_window()
    assert waits == [runtime._C6_4_CRASH_PAUSE_SECONDS]
