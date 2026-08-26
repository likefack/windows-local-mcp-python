from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    with (ROOT / path).open("w", encoding="utf-8", newline="\n") as output:
        output.write(text)


def replace_once(path: str, old: str, new: str, label: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: {label}: expected one replacement target, found {count}")
    write(path, text.replace(old, new, 1))


# Persist a normal public result when the operation-wide deadline expires before
# an Approved Host child can start. The worker already fails closed here; this
# only makes the terminal contract as explicit as later runtime/finalization
# deadline paths.
replace_once(
    "src/windows_local_mcp/worker.py",
    '''        except TimeoutError as guard_error:\n            audit.transition_operation(\n                operation_id,\n                from_statuses={"running"},\n                status="timed_out",\n                finished_at=utc_now_iso(),\n                error=f"Approved Host control-plane preflight exceeded deadline: {guard_error}",\n            )\n            audit.add_event(\n                operation_id,\n                "operation_deadline_exceeded",\n                {"error": str(guard_error)[:1000], "phase": "approved_host_preflight"},\n            )\n''',
    '''        except TimeoutError as guard_error:\n            preflight_error = (\n                f"Approved Host control-plane preflight exceeded deadline: {guard_error}"\n            )\n            preflight_duration_ms = int((time.monotonic() - operation_started) * 1000)\n            preflight_result = {\n                "operation_id": operation_id,\n                "status": "timed_out",\n                "exit_code": None,\n                "duration_ms": preflight_duration_ms,\n                "stdout_preview": "",\n                "stderr_preview": "",\n                "stdout_total_bytes": 0,\n                "stderr_total_bytes": 0,\n                "stdout_truncated": False,\n                "stderr_truncated": False,\n                "stdout_path": str(stdout_path),\n                "stderr_path": str(stderr_path),\n                "execution_tier": operation["tier"],\n                "failure_class": "operation_deadline",\n                "postflight_error": None,\n                "host_fallback_performed": False,\n            }\n            audit.transition_operation(\n                operation_id,\n                from_statuses={"running"},\n                status="timed_out",\n                finished_at=utc_now_iso(),\n                result_json=canonical_json(preflight_result),\n                error=preflight_error,\n                duration_ms=preflight_duration_ms,\n            )\n            audit.add_event(\n                operation_id,\n                "operation_deadline_exceeded",\n                {"error": str(guard_error)[:1000], "phase": "approved_host_preflight"},\n            )\n''',
    "persist preflight deadline result",
)

# A successful Approved Host execution now performs a complete runtime/control-
# plane capture before and after the child. Give this success regression an
# operation budget that actually includes those required security checks.
replace_once(
    "tests/test_approval_execution_integration.py",
    '''        operation_id="snapshot-bound-workspace",\n        script_text="print('SNAPSHOT RUNS INDEPENDENTLY')",\n    )\n    store.approve_and_claim("snapshot-bound-workspace", approver="integration-test")\n    result = executor.launch("snapshot-bound-workspace", 30)\n''',
    '''        operation_id="snapshot-bound-workspace",\n        script_text="print('SNAPSHOT RUNS INDEPENDENTLY')",\n        max_runtime_seconds=60,\n    )\n    store.approve_and_claim("snapshot-bound-workspace", approver="integration-test")\n    result = executor.launch("snapshot-bound-workspace", 70)\n''',
    "budget successful snapshot security finalization",
)

# Make prelaunch operation-deadline behavior explicit. This is distinct from a
# child runtime limit and must never start the approved payload.
replace_once(
    "tests/test_approval_execution_integration.py",
    '''\n\n@pytest.mark.skipif(os.name != "nt", reason="Approved Host descendant Job Object is Windows-only")\ndef test_approved_host_terminates_descendants_at_runtime_limit(tmp_path: Path, monkeypatch) -> None:\n''',
    '''\n\n@pytest.mark.skipif(os.name != "nt", reason="Approved Host preflight deadline is Windows-only")\ndef test_approved_host_preflight_deadline_is_terminal(tmp_path: Path, monkeypatch) -> None:\n    workspace = tmp_path / "workspace"\n    workspace.mkdir()\n    data = tmp_path / "data"\n    config = tmp_path / "config.toml"\n    _write_config(workspace, data, config)\n    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))\n    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)\n    marker = data / "control-plane" / "preflight-deadline-child-started.txt"\n\n    _, store, executor = _prepare_operation(\n        workspace=workspace,\n        data=data,\n        operation_id="approved-host-preflight-deadline",\n        script_text=(\n            "from pathlib import Path\\n"\n            f"Path({str(marker)!r}).write_text('started', encoding='utf-8')\\n"\n        ),\n        max_runtime_seconds=1,\n    )\n    store.approve_and_claim("approved-host-preflight-deadline", approver="integration-test")\n    result = executor.launch("approved-host-preflight-deadline", 10)\n    operation = store.get_operation("approved-host-preflight-deadline")\n\n    assert result["status"] == "timed_out"\n    assert result["failure_class"] == "operation_deadline"\n    assert operation["child_pid"] is None\n    assert not marker.exists()\n\n\n@pytest.mark.skipif(os.name != "nt", reason="Approved Host descendant Job Object is Windows-only")\ndef test_approved_host_terminates_descendants_at_runtime_limit(tmp_path: Path, monkeypatch) -> None:\n''',
    "separate preflight deadline regression",
)

# Keep an actual descendant runtime-limit integration. The operation budget must
# be long enough for the mandatory preflight to arm the guard before the child
# starts; the descendant then deliberately outlives the remaining budget.
replace_once(
    "tests/test_approval_execution_integration.py",
    '''        "time.sleep(2.0)\\n"\n''',
    '''        "time.sleep(90.0)\\n"\n''',
    "long-lived descendant",
)
replace_once(
    "tests/test_approval_execution_integration.py",
    '''        script_text=script,\n        max_runtime_seconds=1,\n    )\n    store.approve_and_claim("approved-host-descendant-timeout", approver="integration-test")\n    result = executor.launch("approved-host-descendant-timeout", 10)\n    time.sleep(1.5)\n''',
    '''        script_text=script,\n        max_runtime_seconds=35,\n    )\n    store.approve_and_claim("approved-host-descendant-timeout", approver="integration-test")\n    result = executor.launch("approved-host-descendant-timeout", 75)\n    time.sleep(1.0)\n''',
    "budget descendant runtime-limit integration",
)
