"""発行元の要求分離と、実 SDK の接続・スレッド引き継ぎを確認する。"""

import threading
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import anyio
import anyio.lowlevel
import pytest
from mcp import ClientSession
from mcp.shared.message import SessionMessage
from mcp.types import Implementation

from windows_local_mcp.request_origin import (
    OriginMCPServer,
    current_origin,
    origin_fields,
    origin_from_context,
)


@asynccontextmanager
async def connected_client(server, name):
    """同一サーバーへ独立した二重化ストリームを接続する。"""
    client_send, server_read = anyio.create_memory_object_stream[SessionMessage](20)
    server_send, client_read = anyio.create_memory_object_stream[SessionMessage](20)
    async with anyio.create_task_group() as group:
        group.start_soon(
            server._lowlevel_server.run,
            server_read, server_send, server._lowlevel_server.create_initialization_options(),
        )
        async with ClientSession(
            client_read, client_send, client_info=Implementation(name=name, version="1.0")
        ) as client:
            await client.initialize()
            yield client
        group.cancel_scope.cancel()


def test_same_connection_proxies_are_stable_and_reconnect_differs():
    connection = SimpleNamespace(state={}, client_params=None, session_id=None)
    a = origin_from_context(SimpleNamespace(
        session=SimpleNamespace(_connection=connection), request_id=1
    ))
    b = origin_from_context(SimpleNamespace(
        session=SimpleNamespace(_connection=connection), request_id=2
    ))
    assert a.session_id == b.session_id
    assert (a.request_id, b.request_id) == ("1", "2")
    other = origin_from_context(SimpleNamespace(
        session=SimpleNamespace(_connection=SimpleNamespace(state={}, client_params=None))
    ))
    assert other.session_id != a.session_id
    assert origin_from_context(SimpleNamespace()).origin_scope == "request"
    assert current_origin().origin_scope == "process"


def test_two_real_sdk_connections_keep_origin_through_parallel_threaded_calls():
    server = OriginMCPServer("origin-test")
    barrier = threading.Barrier(2, timeout=10)

    @server.tool()
    def observe(wait: bool = False) -> dict[str, Any]:
        if wait:
            barrier.wait()
        return origin_fields()

    async def exercise():
        with anyio.fail_after(20):
            async with connected_client(server, "client-a") as a, connected_client(server, "client-b") as b:
                listing = await a.list_tools()
                schema = listing.tools[0].input_schema
                assert "task_id" in schema["properties"]
                assert "task_id" not in schema.get("required", [])
                results = {}

                async def read(client, label):
                    result = await client.call_tool("observe", {"wait": True, "task_id": label})
                    assert not result.is_error
                    results[label] = result.structured_content

                async with anyio.create_task_group() as group:
                    group.start_soon(read, a, "task-a")
                    group.start_soon(read, b, "task-b")
                first, second = results["task-a"], results["task-b"]
                assert first["session_id"] != second["session_id"]
                assert first["server_instance_id"] == second["server_instance_id"]
                assert first["client_name"] == "client-a"
                assert second["client_name"] == "client-b"
                assert first["task_id"] == "task-a"
                assert second["task_id"] == "task-b"
                assert first["request_id"] is not None
                again = (await a.call_tool("observe", {})).structured_content
                assert again["session_id"] == first["session_id"]
                assert again["task_id"] is None  # 直前のタスクを共有状態に残さない。
                assert again["request_id"] != first["request_id"]
                rejected = await a.call_tool("observe", {"task_id": "invalid\nlabel"})
                assert rejected.is_error
                clean = (await b.call_tool("observe", {})).structured_content
                assert clean["task_id"] is None
    anyio.run(exercise)
    assert current_origin().origin_scope == "process"


def test_shared_connection_parallel_tasks_and_exception_cleanup():
    server = OriginMCPServer("shared-origin-test")

    @server.tool()
    async def observe(fail: bool = False) -> dict[str, Any]:
        await anyio.lowlevel.checkpoint()
        if fail:
            raise ValueError("intentional")
        return origin_fields()

    async def exercise():
        with anyio.fail_after(15):
            async with connected_client(server, "shared") as client:
                results = {}

                async def read(label):
                    response = await client.call_tool("observe", {"task_id": label})
                    results[label] = response.structured_content

                async with anyio.create_task_group() as group:
                    group.start_soon(read, "alpha")
                    group.start_soon(read, "beta")
                assert results["alpha"]["session_id"] == results["beta"]["session_id"]
                assert results["alpha"]["task_id"] == "alpha"
                assert results["beta"]["task_id"] == "beta"
                assert (await client.call_tool("observe", {"fail": True, "task_id": "bad"})).is_error
                assert (await client.call_tool("observe", {})).structured_content["task_id"] is None
    anyio.run(exercise)


@pytest.mark.parametrize("value", ["x\x1b[31m\ny", "password=very-secret", "x" * 3000])
def test_client_metadata_is_bounded_and_redacted(value):
    client = SimpleNamespace(name=value, version=value)
    connection = SimpleNamespace(state={}, client_params=SimpleNamespace(client_info=client))
    origin = origin_from_context(SimpleNamespace(session=SimpleNamespace(_connection=connection)))
    assert len(origin.client_name) <= 120
    assert "\x1b" not in origin.client_name and "\n" not in origin.client_name
    assert "very-secret" not in origin.client_name
