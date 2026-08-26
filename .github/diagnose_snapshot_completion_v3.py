from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "tests/test_approval_execution_integration.py"
text = path.read_text(encoding="utf-8")
old = '''    result = executor.launch("snapshot-bound-workspace", 30)\n\n    assert result["status"] == "succeeded"\n    assert "SNAPSHOT RUNS INDEPENDENTLY" in result["stdout_preview"]\n'''
new = '''    result = executor.launch("snapshot-bound-workspace", 30)\n    if result["status"] != "succeeded":\n        diagnostic_deadline = time.monotonic() + 5\n        operation = store.get_operation("snapshot-bound-workspace")\n        while operation["status"] not in {\n            "succeeded", "failed", "timed_out", "cancelled", "interrupted", "expired", "conflict"\n        } and time.monotonic() < diagnostic_deadline:\n            time.sleep(0.1)\n            operation = store.get_operation("snapshot-bound-workspace")\n        raise AssertionError({"launch_result": result, "final_operation": operation})\n\n    assert result["status"] == "succeeded"\n    assert "SNAPSHOT RUNS INDEPENDENTLY" in result["stdout_preview"]\n'''
if text.count(old) != 1:
    raise RuntimeError(f"snapshot diagnostic target count={text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
