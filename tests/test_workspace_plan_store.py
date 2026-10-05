from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from windows_local_mcp.workspace_plan import WorkspacePlan, WorkspacePlanStore


def _plan(*, path: str = "fixture.txt", payload: bytes = b"value") -> WorkspacePlan:
    """Build a plan whose retained size is independent of filesystem fixtures."""

    return WorkspacePlan(tool_name="test", changes={path: payload})


def test_plan_id_is_opaque_bounded_and_one_shot() -> None:
    store = WorkspacePlanStore(max_bytes=1024)
    plan = _plan()

    plan_id = store.put(plan)

    assert len(plan_id) == 32
    assert store.take(plan_id) is plan
    with pytest.raises(ValueError, match="unknown, expired, consumed, or restarted"):
        store.take(plan_id)


def test_only_one_concurrent_take_consumes_plan() -> None:
    store = WorkspacePlanStore(max_bytes=1024)
    plan_id = store.put(_plan())

    def take() -> WorkspacePlan | None:
        try:
            return store.take(plan_id)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _index: take(), range(8)))

    assert sum(item is not None for item in results) == 1


def test_store_enforces_plan_count_and_retained_byte_capacity() -> None:
    count_store = WorkspacePlanStore(max_bytes=1024)
    for index in range(count_store.max_plans):
        count_store.put(_plan(path=f"{index}.txt"))
    with pytest.raises(ValueError, match="capacity exceeded"):
        count_store.put(_plan(path="overflow.txt"))

    byte_store = WorkspacePlanStore(max_bytes=7)
    first = byte_store.put(_plan(path="first.txt", payload=b"1234"))
    with pytest.raises(ValueError, match="capacity exceeded"):
        byte_store.put(_plan(path="second.txt", payload=b"5678"))

    # A rejected admission must not consume or invalidate an existing plan.
    assert byte_store.take(first).changes == {"first.txt": b"1234"}


def test_plan_expires_after_300_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1000.0
    monkeypatch.setattr("windows_local_mcp.workspace_plan.time.monotonic", lambda: now)
    store = WorkspacePlanStore(max_bytes=1024)
    assert store.ttl_seconds == 300
    plan_id = store.put(_plan())

    now = 1299.999
    assert store.take(plan_id).tool_name == "test"

    plan_id = store.put(_plan())
    now += store.ttl_seconds
    with pytest.raises(ValueError, match="unknown, expired, consumed, or restarted"):
        store.take(plan_id)


def test_restart_and_tampered_plan_ids_are_rejected() -> None:
    original_store = WorkspacePlanStore(max_bytes=1024)
    plan_id = original_store.put(_plan())

    restarted_store = WorkspacePlanStore(max_bytes=1024)
    with pytest.raises(ValueError, match="unknown, expired, consumed, or restarted"):
        restarted_store.take(plan_id)

    replacement = "A" if plan_id[-1] != "A" else "B"
    tampered = f"{plan_id[:-1]}{replacement}"
    with pytest.raises(ValueError, match="unknown, expired, consumed, or restarted"):
        original_store.take(tampered)

    # Guessing or modifying an id must not consume the actual plan.
    assert original_store.take(plan_id).changes == {"fixture.txt": b"value"}
