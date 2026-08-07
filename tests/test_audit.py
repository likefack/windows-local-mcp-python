from pathlib import Path

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings


def test_operation_round_trip(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(workspace_root=root, data_dir=tmp_path / "data")
    settings.ensure_directories()
    store = AuditStore(settings)

    operation_id = store.create_operation(
        tool_name="test",
        tier="read",
        status="running",
        cwd=str(root),
        request={"value": 1},
    )
    store.update_operation(operation_id, status="succeeded")
    store.add_event(operation_id, "done", {"ok": True})

    operation = store.get_operation(operation_id)
    assert operation["status"] == "succeeded"
    assert operation["request"] == {"value": 1}
    assert operation["events"][-1]["event_type"] == "done"
