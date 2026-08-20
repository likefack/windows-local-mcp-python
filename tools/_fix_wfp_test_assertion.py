from pathlib import Path

path = Path("tests/test_wfp_guard_runtime.py")
text = path.read_text(encoding="utf-8")
old = "            assert reported_parent == child.pid\n"
new = "            assert reported_pid == child.pid\n"
if text.count(old) != 1:
    raise RuntimeError("expected named-pipe child PID assertion was not found exactly once")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
