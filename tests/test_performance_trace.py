import gc
import json
import weakref
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from contextvars import copy_context

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.performance_trace import (
    MAX_PHASES,
    decode_timing_payload,
    encode_timing_payload,
    operation_trace,
    phase,
    traced_operation,
)


def store_for(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(workspace_root=root, data_dir=tmp_path / "data", protect_data_dir_acl=False)
    settings.ensure_directories()
    return AuditStore(settings)


def test_nested_order_and_overflow_keep_failure(monkeypatch):
    # Changing the wall clock must not affect elapsed time.
    monkeypatch.setattr("time.time", lambda: -123456.0)
    with pytest.raises(RuntimeError), operation_trace() as trace, phase("operation_body"):
        for _ in range(MAX_PHASES + 20):
            with phase("source_read"):
                pass
        with phase("cas_recheck"):
            raise RuntimeError("original")
    value = trace.to_payload()
    assert len(value["phases"]) == MAX_PHASES
    assert value["dropped_phase_count"] == 22
    assert value["failed_phase"] == "cas_recheck"
    assert value["status"] == "failed"
    assert value["phases"][0]["name"] == "operation_body"
    assert all(p["offset_ns"] + p["duration_ns"] <= value["total_ns"] for p in value["phases"])
    assert decode_timing_payload(encode_timing_payload(value)) == value


def test_deeply_nested_count_is_bounded():
    with operation_trace() as trace, ExitStack() as stack:
        for _ in range(MAX_PHASES + 10):
            stack.enter_context(phase("source_read"))
    value = trace.to_payload()
    assert len(value["phases"]) == MAX_PHASES
    assert value["dropped_phase_count"] == 10
    assert [p["sequence"] for p in value["phases"]] == list(range(1, MAX_PHASES + 1))


def test_context_isolation():
    def run(name):
        with operation_trace() as trace, phase(name):
            pass
        return trace.to_payload()["phases"][0]["name"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(run, ["source_read", "source_hash"])) == ["source_read", "source_hash"]


def test_handled_exception_does_not_retain_frame_resources():
    class Resource:
        pass

    references = []

    def probe():
        resource = Resource()
        references.append(weakref.ref(resource))
        with phase("path_validation"):
            raise FileNotFoundError("normal missing-target probe")

    with operation_trace() as trace:
        try:
            probe()
        except FileNotFoundError:
            pass
        gc.collect()
        assert references[0]() is None
    assert trace.to_payload()["failed_phase"] is None


@pytest.mark.parametrize(
    "change",
    [
        {"total_ns": -1},
        {"total_ns": True},
        {"total_ms": float("nan")},
        {"total_ms": 100},
        {"schema_version": 3},
        {"secret": "no"},
        {"phases": [{"name": "credential", "offset_ns": 0, "duration_ns": 0, "status": "failed"}]},
        {
            "phases": [
                {"name": "source_read", "offset_ns": 0, "duration_ns": 101, "status": "succeeded"}
            ]
        },
        {"phases": [None] * (MAX_PHASES + 1)},
    ],
)
def test_reject_malformed(change):
    with pytest.raises(ValueError):
        encode_timing_payload({"total_ns": 100, **change})


def test_fresh_database_migration_and_no_activity_update(tmp_path):
    store = store_for(tmp_path)
    oid = store.create_operation(
        tool_name="read_file", tier="broker", status="succeeded", cwd=None, request={}
    )
    original = store.get_operation(oid)
    assert original["timings"] is None
    # Reproduce the previous schema, including a retained operation and event.
    with store._connect() as db:
        db.execute("ALTER TABLE operations DROP COLUMN timing_json")
    store = AuditStore(store.settings)
    assert store.get_operation(oid)["timings"] is None
    with operation_trace(audit=store, operation_id=oid), phase("source_read"):
        pass
    saved = store.get_operation(oid)
    assert saved["duration_ms"] is not None
    assert saved["updated_at"] == original["updated_at"]
    assert saved["events"] == original["events"]
    assert "timings" not in store.list_operations()[0]
    with pytest.raises(ValueError):
        store.update_operation(oid, timing_json="{}")
    with pytest.raises(ValueError):
        store.persist_timings(oid, timing_json=json.dumps(saved["timings"]), duration_ms=-1)


def test_persistence_error_does_not_mask_original(tmp_path, monkeypatch):
    store = store_for(tmp_path)

    def fail(*args, **kwargs):
        raise OSError("diagnostic storage failure")

    monkeypatch.setattr(store, "persist_timings", fail)

    @traced_operation
    def operation(failure):
        store.create_operation(
            tool_name="test", tier="broker", status="failed", cwd=None, request={}
        )
        with phase("transform"):
            if failure:
                raise ValueError("original transform failure")
        return "original result"

    with pytest.raises(ValueError, match="original transform failure"):
        operation(True)
    assert operation(False) == "original result"


def test_phases_only_persist_once_at_scope_exit(tmp_path, monkeypatch):
    store = store_for(tmp_path)
    oid = store.create_operation(
        tool_name="test", tier="broker", status="succeeded", cwd=None, request={}
    )
    calls = []
    original = store.persist_timings

    def record(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "persist_timings", record)
    with operation_trace(audit=store, operation_id=oid):
        for _ in range(MAX_PHASES):
            with phase("source_hash"):
                pass
        assert calls == []
    assert calls == [oid]


def test_v2_exact_parent_self_and_uninstrumented_time(monkeypatch):
    ticks = iter([0, 10, 20, 50, 90, 100])
    monkeypatch.setattr("time.perf_counter_ns", lambda: next(ticks))
    with operation_trace() as trace, phase("operation_body"), phase("source_hash"):
        pass
    payload = trace.to_payload()
    outer, child = payload["phases"]
    assert payload["schema_version"] == 2
    assert outer["parent_sequence"] is None
    assert child["parent_sequence"] == outer["sequence"]
    assert (outer["duration_ns"], outer["self_ns"]) == (80, 50)
    assert (child["duration_ns"], child["self_ns"]) == (30, 30)
    assert payload["uninstrumented_ns"] == 20
    assert sum(p["self_ns"] for p in payload["phase_summary"]) + 20 == 100


def test_dropped_child_time_and_late_failure_remain_in_summary(monkeypatch):
    # Once details fill up, the parent's self time must still exclude its children.
    ticks = iter(range(10_000))
    monkeypatch.setattr("time.perf_counter_ns", lambda: next(ticks))
    with pytest.raises(ValueError), operation_trace() as trace, phase("operation_body"):
        for _ in range(MAX_PHASES + 2):
            with phase("source_hash"):
                pass
        with phase("audit_commit"):
            raise ValueError("must not enter diagnostics")
    payload = trace.to_payload()
    summary = {p["name"]: p for p in payload["phase_summary"]}
    assert summary["source_hash"]["count"] == MAX_PHASES + 2
    assert summary["audit_commit"]["failed_count"] == 1
    assert payload["failed_phase"] == "audit_commit"
    parent = payload["phases"][0]
    assert parent["self_ns"] == parent["duration_ns"] - (MAX_PHASES + 3)
    assert "must not enter diagnostics" not in encode_timing_payload(payload)


def test_legacy_v1_does_not_gain_invented_self_or_aggregates():
    value = {
        "schema_version": 1, "total_ns": 100, "phases": [
            {"name": "source_read", "offset_ns": 10, "duration_ns": 50, "status": "succeeded"}
        ],
    }
    normalized = decode_timing_payload(encode_timing_payload(value))
    assert normalized["schema_version"] == 1
    assert "phase_summary" not in normalized
    assert "self_ns" not in normalized["phases"][0]


def test_copied_thread_context_does_not_mix_synchronous_trace():
    def child():
        with phase("source_hash"):
            pass
        with operation_trace() as own, phase("source_read"):
            pass
        return own.to_payload()

    with (
        operation_trace() as trace,
        phase("operation_body"),
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        child_payload = pool.submit(copy_context().run, child).result()
    assert [p["name"] for p in trace.to_payload()["phases"]] == ["operation_body"]
    assert [p["name"] for p in child_payload["phases"]] == ["source_read"]


@pytest.mark.parametrize("field,value", [
    ("count", 0), ("failed_count", 100), ("self_ns", -1),
    ("max_ns", 2**63), ("name", "secret-content"),
])
def test_v2_rejects_corrupt_summary(field, value):
    with operation_trace() as trace, phase("source_read"):
        pass
    payload = trace.to_payload()
    payload["phase_summary"][0][field] = value
    with pytest.raises(ValueError):
        encode_timing_payload(payload)


def test_v2_rejects_invalid_parent_and_self():
    with operation_trace() as trace, phase("source_read"):
        pass
    payload = trace.to_payload()
    payload["phases"][0]["parent_sequence"] = 1
    with pytest.raises(ValueError, match="parent"):
        encode_timing_payload(payload)
    payload = trace.to_payload()
    payload["phases"][0]["self_ns"] = payload["total_ns"] + 1
    with pytest.raises(ValueError, match="self"):
        encode_timing_payload(payload)


def test_v2_rejects_corrupted_self_even_when_totals_still_match(monkeypatch):
    ticks = iter([0, 10, 20, 50, 90, 100])
    monkeypatch.setattr("time.perf_counter_ns", lambda: next(ticks))
    with operation_trace() as trace, phase("operation_body"), phase("source_hash"):
        pass
    payload = trace.to_payload()
    payload["phases"][0]["self_ns"] = 80
    payload["phases"][1]["self_ns"] = 0
    for item in payload["phase_summary"]:
        item["self_ns"] = 80 if item["name"] == "operation_body" else 0
    with pytest.raises(ValueError, match="child"):
        encode_timing_payload(payload)
