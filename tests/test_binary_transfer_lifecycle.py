from __future__ import annotations

import base64
import importlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from windows_local_mcp.util import sha256_bytes


def load_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    max_open_transfers: int = 2,
) -> tuple[Any, Path, Path]:
    """Load an isolated server while bypassing only the external Approved Host health state."""

    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    data_dir = tmp_path / "data"
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(workspace).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data_dir).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "max_structured_file_bytes = 1048576",
                "max_transfer_chunk_bytes = 4096",
                f"max_open_transfers = {max_open_transfers}",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    sys.modules.pop("windows_local_mcp.server", None)
    server = importlib.import_module("windows_local_mcp.server")
    monkeypatch.setattr(server, "assert_control_plane_healthy", lambda _settings: None)
    return server, workspace, config


def manifest_for(server: Any, transfer_id: str) -> tuple[Path, dict[str, Any]]:
    root = server.runtime.settings.data_dir / "binary-transfers" / transfer_id
    return root, json.loads((root / "manifest.json").read_text(encoding="utf-8"))


def complete_download(server: Any, transfer_id: str, total_bytes: int) -> list[dict[str, Any]]:
    chunks = []
    for offset in range(0, total_bytes, 4096):
        chunks.append(server.artifact_download_chunk(transfer_id, offset))
    return chunks


def test_completed_download_releases_slot_and_terminal_chunk_retry_is_stable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace, _config = load_server(tmp_path, monkeypatch, max_open_transfers=1)
    payload = b"a" * 8192
    (workspace / "source.bin").write_bytes(payload)

    transfer = server.artifact_download_begin("source.bin", chunk_bytes=4096)
    first = server.artifact_download_chunk(transfer["transfer_id"], 0)
    terminal = server.artifact_download_chunk(transfer["transfer_id"], 4096)

    assert first["complete"] is False
    assert terminal["complete"] is True
    assert manifest_for(server, transfer["transfer_id"])[1]["state"] == "completed"

    # A lost terminal response may be retried from the retained immutable snapshot.
    assert server.artifact_download_chunk(transfer["transfer_id"], 4096) == terminal
    replacement = server.artifact_download_begin("source.bin")
    assert replacement["transfer_id"] != transfer["transfer_id"]


def test_repeated_completed_downloads_do_not_exhaust_shared_pool_and_upload_commits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace, _config = load_server(tmp_path, monkeypatch, max_open_transfers=2)
    source = b"download-source"
    (workspace / "source.bin").write_bytes(source)

    for _ in range(6):
        transfer = server.artifact_download_begin("source.bin")
        chunk = server.artifact_download_chunk(transfer["transfer_id"], 0)
        assert chunk["complete"] is True

    uploaded = b"uploaded-result"
    upload = server.artifact_upload_begin(
        "result.bin",
        len(uploaded),
        sha256_bytes(uploaded),
        source_transfer_id=transfer["transfer_id"],
    )
    server.artifact_upload_chunk(
        upload["transfer_id"], 0, base64.b64encode(uploaded).decode("ascii")
    )
    committed = server.artifact_upload_commit(upload["transfer_id"])

    assert committed["after_sha256"] == sha256_bytes(uploaded)
    assert (workspace / "result.bin").read_bytes() == uploaded
    assert manifest_for(server, upload["transfer_id"])[1]["state"] == "committed"


def test_only_active_transfers_consume_the_shared_download_upload_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace, _config = load_server(tmp_path, monkeypatch, max_open_transfers=2)
    payload = b"active"
    (workspace / "source.bin").write_bytes(payload)

    download = server.artifact_download_begin("source.bin")
    upload = server.artifact_upload_begin("staged.bin", 1, sha256_bytes(b"x"))
    with pytest.raises(RuntimeError, match="admission limit"):
        server.artifact_download_begin("source.bin")

    server.artifact_download_chunk(download["transfer_id"], 0)
    admitted = server.artifact_download_begin("source.bin")
    with pytest.raises(RuntimeError, match="admission limit"):
        server.artifact_upload_begin("blocked.bin", 1, sha256_bytes(b"y"))

    server.artifact_transfer_cancel(upload["transfer_id"])
    server.artifact_transfer_cancel(admitted["transfer_id"])


def test_cancel_is_idempotent_and_does_not_rewrite_completed_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace, _config = load_server(tmp_path, monkeypatch, max_open_transfers=1)
    (workspace / "source.bin").write_bytes(b"source")

    upload = server.artifact_upload_begin("pending.bin", 1, sha256_bytes(b"x"))
    first = server.artifact_transfer_cancel(upload["transfer_id"], reason="abandoned")
    second = server.artifact_transfer_cancel(upload["transfer_id"], reason="ignored retry")
    assert first == second
    assert first["state"] == "cancelled"

    download = server.artifact_download_begin("source.bin")
    server.artifact_download_chunk(download["transfer_id"], 0)
    result = server.artifact_transfer_cancel(download["transfer_id"])
    assert result["state"] == "completed"
    assert result["cancelled"] is False
    assert manifest_for(server, download["transfer_id"])[1]["state"] == "completed"

    cancel_tool = next(
        tool
        for tool in server.mcp._tool_manager.list_tools()
        if tool.name == "artifact_transfer_cancel"
    )
    assert cancel_tool.annotations.idempotent_hint is True


def test_expired_and_failed_transfers_release_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace, _config = load_server(tmp_path, monkeypatch, max_open_transfers=1)
    (workspace / "source.bin").write_bytes(b"trusted snapshot")

    expired = server.artifact_download_begin("source.bin")
    expired_root, expired_manifest = manifest_for(server, expired["transfer_id"])
    expired_manifest["created_at"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    server._write_transfer_manifest(expired_root, expired_manifest)
    replacement = server.artifact_download_begin("source.bin")
    assert manifest_for(server, expired["transfer_id"])[1]["state"] == "expired"
    server.artifact_transfer_cancel(replacement["transfer_id"])

    failed = server.artifact_download_begin("source.bin")
    failed_root, _manifest = manifest_for(server, failed["transfer_id"])
    (failed_root / "payload.bin").write_bytes(b"tampered bytes!!")
    with pytest.raises(server.TransferIntegrityError, match="snapshot changed"):
        server.artifact_download_chunk(failed["transfer_id"], 0)
    assert manifest_for(server, failed["transfer_id"])[1]["state"] == "failed"
    server.artifact_download_begin("source.bin")


def test_client_chunk_error_keeps_transfer_open_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace, _config = load_server(tmp_path, monkeypatch)
    (workspace / "source.bin").write_bytes(b"source")
    transfer = server.artifact_download_begin("source.bin")

    with pytest.raises(ValueError, match="chunk boundary"):
        server.artifact_download_chunk(transfer["transfer_id"], 1)

    assert manifest_for(server, transfer["transfer_id"])[1]["state"] == "open"
    assert server.artifact_download_chunk(transfer["transfer_id"], 0)["complete"] is True


def test_completed_manifest_survives_restart_and_remains_outside_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace, config = load_server(tmp_path, monkeypatch, max_open_transfers=1)
    (workspace / "source.bin").write_bytes(b"restart-safe")
    transfer = server.artifact_download_begin("source.bin")
    terminal = server.artifact_download_chunk(transfer["transfer_id"], 0)

    sys.modules.pop("windows_local_mcp.server", None)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    restarted = importlib.import_module("windows_local_mcp.server")
    monkeypatch.setattr(restarted, "assert_control_plane_healthy", lambda _settings: None)

    assert manifest_for(restarted, transfer["transfer_id"])[1]["state"] == "completed"
    assert restarted.artifact_download_chunk(transfer["transfer_id"], 0) == terminal
    restarted.artifact_download_begin("source.bin")


def test_zero_byte_download_is_terminal_without_a_chunk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace, _config = load_server(tmp_path, monkeypatch, max_open_transfers=1)
    (workspace / "empty.bin").write_bytes(b"")

    empty = server.artifact_download_begin("empty.bin")
    assert empty["chunk_count"] == 0
    assert manifest_for(server, empty["transfer_id"])[1]["state"] == "completed"
    server.artifact_download_begin("empty.bin")


def test_begin_audit_failure_is_terminal_instead_of_leaking_an_unreachable_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace, _config = load_server(tmp_path, monkeypatch, max_open_transfers=1)
    (workspace / "source.bin").write_bytes(b"source")
    real_log = server._log_simple
    monkeypatch.setattr(
        server,
        "_log_simple",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("forced audit failure")),
    )

    with pytest.raises(RuntimeError, match="forced audit failure"):
        server.artifact_download_begin("source.bin")

    manifests = list(
        (server.runtime.settings.data_dir / "binary-transfers").glob("*/manifest.json")
    )
    assert len(manifests) == 1
    assert json.loads(manifests[0].read_text(encoding="utf-8"))["state"] == "failed"
    monkeypatch.setattr(server, "_log_simple", real_log)
    server.artifact_download_begin("source.bin")


def test_concurrent_begin_completion_and_cancel_never_exceed_open_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace, _config = load_server(tmp_path, monkeypatch, max_open_transfers=2)
    (workspace / "source.bin").write_bytes(b"concurrent")

    def begin() -> str | None:
        try:
            return str(server.artifact_download_begin("source.bin")["transfer_id"])
        except RuntimeError as error:
            assert "admission limit" in str(error)
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        initial = list(pool.map(lambda _index: begin(), range(8)))
    active = [item for item in initial if item is not None]
    assert len(active) == 2

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(server.artifact_download_chunk, active[0], 0)]
        futures.append(pool.submit(server.artifact_transfer_cancel, active[1]))
        futures.extend(pool.submit(begin) for _index in range(6))
        results = [future.result() for future in futures]

    for result in results[2:]:
        if isinstance(result, str):
            server.artifact_transfer_cancel(result)
    open_count = 0
    for path in (server.runtime.settings.data_dir / "binary-transfers").glob("*/manifest.json"):
        state = json.loads(path.read_text(encoding="utf-8"))["state"]
        open_count += state in {"preparing", "open"}
    assert open_count <= server.runtime.settings.max_open_transfers


def test_real_mcp_stdio_repeated_download_then_upload_round_trip(tmp_path: Path) -> None:
    """Exercise the public MCP surface without claiming Secure Tunnel or ChatGPT E2E."""

    if os.name == "nt":
        service_probe = subprocess.run(
            ["sc.exe", "query", "WindowsLocalMCPApprovedHost"],
            capture_output=True,
            check=False,
            shell=False,
        )
        if service_probe.returncode not in {0, 1060}:
            pytest.skip(
                "current Windows context cannot query Approved Host SCM state; "
                f"sc.exe exited with {service_probe.returncode}"
            )

    workspace = tmp_path / "stdio-workspace"
    workspace.mkdir()
    data_dir = tmp_path / "stdio-data"
    config = tmp_path / "stdio-config.toml"
    source = b"stdio-transfer" * 500
    (workspace / "source.bin").write_bytes(source)
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(workspace).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data_dir).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "approved_sandbox_enabled = false",
                "approved_host_enabled = false",
                "max_transfer_chunk_bytes = 4096",
                "max_open_transfers = 1",
            ]
        ),
        encoding="utf-8",
    )

    async def exercise() -> None:
        environment = os.environ.copy()
        environment["LOCAL_MCP_CONFIG"] = str(config)
        environment.pop("LOCAL_MCP_ROOT", None)
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "windows_local_mcp.cli", "server"],
            env=environment,
            cwd=str(Path(__file__).parents[1]),
        )
        with anyio.fail_after(60):
            async with (
                stdio_client(parameters) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                await session.initialize()
                tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                assert tools["artifact_transfer_cancel"].annotations.idempotent_hint is True

                for _ in range(3):
                    begun = await session.call_tool(
                        "artifact_download_begin", {"path": "source.bin"}
                    )
                    assert not begun.is_error
                    assert begun.structured_content is not None
                    transfer_id = begun.structured_content["transfer_id"]
                    offset = 0
                    assembled = bytearray()
                    while offset < len(source):
                        chunk = await session.call_tool(
                            "artifact_download_chunk",
                            {"transfer_id": transfer_id, "offset": offset},
                        )
                        assert not chunk.is_error
                        assert chunk.structured_content is not None
                        assembled.extend(base64.b64decode(chunk.structured_content["base64"]))
                        offset = chunk.structured_content["next_offset"]
                    assert bytes(assembled) == source

                uploaded = b"stdio-upload-result"
                upload = await session.call_tool(
                    "artifact_upload_begin",
                    {
                        "path": "result.bin",
                        "total_bytes": len(uploaded),
                        "sha256": sha256_bytes(uploaded),
                    },
                )
                assert not upload.is_error
                assert upload.structured_content is not None
                upload_id = upload.structured_content["transfer_id"]
                chunk = await session.call_tool(
                    "artifact_upload_chunk",
                    {
                        "transfer_id": upload_id,
                        "offset": 0,
                        "base64_chunk": base64.b64encode(uploaded).decode("ascii"),
                    },
                )
                assert not chunk.is_error
                committed = await session.call_tool(
                    "artifact_upload_commit", {"transfer_id": upload_id}
                )
                assert not committed.is_error

    anyio.run(exercise)
    assert (workspace / "result.bin").read_bytes() == b"stdio-upload-result"
