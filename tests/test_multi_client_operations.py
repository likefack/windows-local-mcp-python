"""同じ runtime / Audit DB へ接続する複数クライアントの回帰試験。"""

import anyio
import pytest
from test_request_origin import connected_client
from test_server_operations import load_server


def test_parallel_clients_audit_writes_errors_and_history(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)

    async def exercise():
        with anyio.fail_after(30):
            async with connected_client(server.mcp, "editor-a") as a, connected_client(server.mcp, "editor-b") as b:
                outcomes = {}

                async def write(client, label):
                    response = await client.call_tool("write_file", {
                        "path": f"{label}.txt", "content": label, "task_id": label,
                    })
                    assert not response.is_error, response
                    outcomes[label] = response.structured_content

                async with anyio.create_task_group() as group:
                    group.start_soon(write, a, "alpha")
                    group.start_soon(write, b, "beta")
                rows = {
                    label: server.runtime.audit.get_operation(result["operation_id"])
                    for label, result in outcomes.items()
                }
                assert rows["alpha"]["session_id"] != rows["beta"]["session_id"]
                assert rows["alpha"]["client_name"] == "editor-a"
                assert rows["beta"]["client_name"] == "editor-b"
                for label, row in rows.items():
                    assert row["task_id"] == label
                    assert row["request_id"] is not None
                    assert row["events"][0]["origin"]["session_id"] == row["session_id"]
                bad = await b.call_tool("read_file", {"path": "missing.txt", "task_id": "missing"})
                assert bad.is_error
                denied = server.runtime.audit.list_operations(task_id="missing")
                assert len(denied) == 1
                assert denied[0]["status"] == "rejected"
                assert denied[0]["session_id"] == rows["beta"]["session_id"]
                history = await a.call_tool("audit_list", {
                    "session_id": rows["alpha"]["session_id"], "filter_task_id": "alpha", "limit": 1,
                })
                assert not history.is_error
                assert history.structured_content["result"][0]["id"] == outcomes["alpha"]["operation_id"]
                timeline = await a.call_tool("activity_timeline", {"filter_task_id": "beta"})
                assert not timeline.is_error
                assert timeline.structured_content["result"][0]["task_id"] == "beta"
                report = await a.call_tool("operation_report", {
                    "operation_id": outcomes["beta"]["operation_id"],
                })
                assert not report.is_error
                assert report.structured_content["session_id"] == rows["beta"]["session_id"]
                # 別クライアントの参照は許可を変えず、参照操作だけをその呼出元に記録する。
                inspected = server.runtime.audit.list_operations(limit=1)[0]
                assert inspected["session_id"] == rows["alpha"]["session_id"]
                assert inspected["task_id"] is None
    anyio.run(exercise)
    assert (root / "alpha.txt").read_text(encoding="utf-8") == "alpha"
    assert (root / "beta.txt").read_text(encoding="utf-8") == "beta"


def test_all_tools_accept_task_id_without_exposing_session_override(tmp_path, monkeypatch):
    server, _ = load_server(tmp_path, monkeypatch)
    for tool in server.mcp._tool_manager.list_tools():
        parameters = tool.parameters
        assert "task_id" in parameters["properties"], tool.name
        assert "task_id" not in parameters.get("required", []), tool.name
        if tool.name not in {"audit_list", "activity_timeline"}:
            assert "session_id" not in parameters["properties"], tool.name


def test_failed_launch_releases_queue_slot(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    server.runtime.settings.max_concurrent_jobs = 1

    def fail_launch(*_args):
        raise RuntimeError("test launch failure")

    monkeypatch.setattr(server.runtime.executor, "launch", fail_launch)
    for _ in range(2):
        with pytest.raises(RuntimeError, match="test launch failure"):
            server._queue_command(
                tool_name="test-command", tier="broker",
                normalized_command={"cwd": str(root)},
                foreground_timeout_seconds=0, max_runtime_seconds=10,
            )
        assert server.runtime.audit.list_active_operations() == []
    assert all(row["status"] == "failed" for row in server.runtime.audit.list_operations())


def test_transfer_event_keeps_actual_callers_and_session_info(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "data.bin").write_bytes(b"transfer-test")

    async def exercise():
        with anyio.fail_after(30):
            async with connected_client(server.mcp, "sender") as a, connected_client(server.mcp, "receiver") as b:
                info = await a.call_tool("session_info", {"task_id": "export"})
                assert not info.is_error
                first = await a.call_tool("artifact_download_begin", {
                    "path": "data.bin", "task_id": "export",
                })
                assert not first.is_error
                manifest = first.structured_content
                chunk = await b.call_tool("artifact_download_chunk", {
                    "transfer_id": manifest["transfer_id"], "offset": 0, "task_id": "resume",
                })
                assert not chunk.is_error
                operation = server.runtime.audit.get_operation(manifest["operation_id"])
                assert operation["session_id"] == info.structured_content["session_id"]
                assert operation["task_id"] == info.structured_content["task_id"] == "export"
                event = next(e for e in operation["events"] if e["event_type"] == "artifact_download_chunk")
                assert event["origin"]["session_id"] != operation["session_id"]
                assert event["origin"]["client_name"] == "receiver"
                assert event["origin"]["task_id"] == "resume"
    anyio.run(exercise)
