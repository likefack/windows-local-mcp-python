from __future__ import annotations

import base64
import importlib
import json
import os
import random
import sys
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from windows_local_mcp.util import sha256_bytes


def _load_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    max_transfer_chunk_bytes: int = 512 * 1024,
) -> tuple[Any, Path]:
    """Load an isolated server with an explicit transfer limit."""

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data_dir = tmp_path / "data"
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(workspace).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data_dir).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "approved_sandbox_enabled = false",
                "approved_host_enabled = false",
                "max_structured_file_bytes = 2097152",
                f"max_transfer_chunk_bytes = {max_transfer_chunk_bytes}",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    sys.modules.pop("windows_local_mcp.server", None)
    server = importlib.import_module("windows_local_mcp.server")
    monkeypatch.setattr(server, "assert_control_plane_healthy", lambda _settings: None)
    return server, workspace


def _tool_result_text(result: Any) -> str:
    return "\n".join(
        str(block.text) for block in result.content if getattr(block, "type", None) == "text"
    )


def test_exact_512_kib_chunk_round_trip_remains_byte_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace = _load_server(tmp_path, monkeypatch)
    # A seeded pseudo-random payload catches accidental text, compression, or repeated-data paths.
    payload = random.Random(0x512_000).randbytes(512 * 1024)
    digest = sha256_bytes(payload)

    upload = server.artifact_upload_begin("received.bin", len(payload), digest)
    uploaded = server.artifact_upload_chunk(
        upload["transfer_id"], 0, base64.b64encode(payload).decode("ascii")
    )
    committed = server.artifact_upload_commit(upload["transfer_id"])

    assert uploaded["complete"] is True
    assert uploaded["chunk_sha256"] == digest
    assert committed["after_sha256"] == digest
    assert (workspace / "received.bin").read_bytes() == payload

    download = server.artifact_download_begin("received.bin")
    chunk = server.artifact_download_chunk(download["transfer_id"], 0)
    downloaded = base64.b64decode(chunk["base64"], validate=True)
    assert chunk["bytes"] == 512 * 1024
    assert chunk["sha256"] == digest
    assert downloaded == payload


def test_oversized_base64_is_rejected_before_decode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _workspace = _load_server(
        tmp_path, monkeypatch, max_transfer_chunk_bytes=4096
    )
    upload = server.artifact_upload_begin("bounded.bin", 4096, sha256_bytes(b"x" * 4096))
    decode_called = False

    def unexpected_decode(*_args: Any, **_kwargs: Any) -> bytes:
        nonlocal decode_called
        decode_called = True
        raise AssertionError("oversized base64 reached the decoder")

    monkeypatch.setattr(server.base64, "b64decode", unexpected_decode)
    encoded_limit = ((4096 + 2) // 3) * 4
    with pytest.raises(server.ArtifactTransferError) as raised:
        server.artifact_upload_chunk(
            upload["transfer_id"], 0, "A" * (encoded_limit + 4)
        )

    assert raised.value.code == "TRANSFER_BASE64_LIMIT"
    assert decode_called is False


def test_offset_and_incomplete_errors_are_classified_without_auditing_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _workspace = _load_server(
        tmp_path, monkeypatch, max_transfer_chunk_bytes=4096
    )
    payload = b"sensitive-binary-body-that-must-not-enter-audit"
    encoded = base64.b64encode(payload).decode("ascii")
    upload = server.artifact_upload_begin(
        "incomplete.bin", len(payload), sha256_bytes(payload)
    )

    with pytest.raises(server.ArtifactTransferStateError) as offset_error:
        server.artifact_upload_chunk(upload["transfer_id"], 1, encoded)
    assert offset_error.value.code == "TRANSFER_OFFSET_INVALID"

    with pytest.raises(server.ArtifactTransferStateError) as incomplete_error:
        server.artifact_upload_commit(upload["transfer_id"])
    assert incomplete_error.value.code == "TRANSFER_INCOMPLETE"

    operation_summaries = [
        item
        for item in server.runtime.audit.list_operations(limit=100)
        if item["tool_name"] in {"artifact_upload_chunk", "artifact_upload_commit"}
    ]
    assert {item["tool_name"] for item in operation_summaries} == {
        "artifact_upload_chunk",
        "artifact_upload_commit",
    }
    audit_records = [
        server.runtime.audit.get_operation(item["id"], include_events=True)
        for item in operation_summaries
    ]
    serialized_audit = json.dumps(audit_records, ensure_ascii=False)
    assert encoded not in serialized_audit
    assert payload.decode("ascii") not in serialized_audit
    assert "base64_chunk" not in serialized_audit
    assert "TRANSFER_OFFSET_INVALID" in serialized_audit
    assert "TRANSFER_INCOMPLETE" in serialized_audit


def test_commit_sha256_mismatch_fails_without_creating_workspace_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, workspace = _load_server(
        tmp_path, monkeypatch, max_transfer_chunk_bytes=4096
    )
    payload = b"actual-upload-payload"
    upload = server.artifact_upload_begin(
        "digest-mismatch.bin", len(payload), sha256_bytes(b"different-payload")
    )
    server.artifact_upload_chunk(
        upload["transfer_id"], 0, base64.b64encode(payload).decode("ascii")
    )

    with pytest.raises(server.TransferIntegrityError) as raised:
        server.artifact_upload_commit(upload["transfer_id"])

    assert raised.value.code == "TRANSFER_SHA256_MISMATCH"
    assert not (workspace / "digest-mismatch.bin").exists()
    manifest_path = (
        server.runtime.settings.data_dir
        / "binary-transfers"
        / upload["transfer_id"]
        / "manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["state"] == "failed"
    assert "TRANSFER_SHA256_MISMATCH" in manifest["error"]


def test_stdio_surfaces_stable_transfer_error_codes(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "stdio-workspace"
    workspace.mkdir()
    data_dir = tmp_path / "stdio-data"
    config = tmp_path / "stdio-config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(workspace).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data_dir).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "approved_sandbox_enabled = false",
                "approved_host_enabled = false",
                "max_structured_file_bytes = 1048576",
                "max_transfer_chunk_bytes = 524288",
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

                payload = random.Random(0x512_001).randbytes(512 * 1024)
                digest = sha256_bytes(payload)
                upload = await session.call_tool(
                    "artifact_upload_begin",
                    {
                        "path": "stdio-512-kib.bin",
                        "total_bytes": len(payload),
                        "sha256": digest,
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
                        "base64_chunk": base64.b64encode(payload).decode("ascii"),
                    },
                )
                assert not chunk.is_error
                assert chunk.structured_content is not None
                assert chunk.structured_content["chunk_sha256"] == digest
                committed = await session.call_tool(
                    "artifact_upload_commit", {"transfer_id": upload_id}
                )
                assert not committed.is_error
                assert committed.structured_content is not None
                assert committed.structured_content["after_sha256"] == digest

                download = await session.call_tool(
                    "artifact_download_begin", {"path": "stdio-512-kib.bin"}
                )
                assert not download.is_error
                assert download.structured_content is not None
                downloaded_chunk = await session.call_tool(
                    "artifact_download_chunk",
                    {
                        "transfer_id": download.structured_content["transfer_id"],
                        "offset": 0,
                    },
                )
                assert not downloaded_chunk.is_error
                assert downloaded_chunk.structured_content is not None
                assert downloaded_chunk.structured_content["sha256"] == digest
                assert (
                    base64.b64decode(
                        downloaded_chunk.structured_content["base64"], validate=True
                    )
                    == payload
                )

                invalid_begin = await session.call_tool(
                    "artifact_upload_begin",
                    {
                        "path": "invalid.bin",
                        "total_bytes": 1,
                        "sha256": sha256_bytes(b"x"),
                    },
                )
                assert invalid_begin.structured_content is not None
                invalid = await session.call_tool(
                    "artifact_upload_chunk",
                    {
                        "transfer_id": invalid_begin.structured_content["transfer_id"],
                        "offset": 0,
                        "base64_chunk": "%%%%",
                    },
                )
                assert invalid.is_error
                assert "TRANSFER_BASE64_INVALID" in _tool_result_text(invalid)

                oversized_payload = b"z" * (512 * 1024 + 1)
                limit_begin = await session.call_tool(
                    "artifact_upload_begin",
                    {
                        "path": "limit.bin",
                        "total_bytes": len(oversized_payload),
                        "sha256": sha256_bytes(oversized_payload),
                    },
                )
                assert limit_begin.structured_content is not None
                oversized = await session.call_tool(
                    "artifact_upload_chunk",
                    {
                        "transfer_id": limit_begin.structured_content["transfer_id"],
                        "offset": 0,
                        "base64_chunk": base64.b64encode(oversized_payload).decode("ascii"),
                    },
                )
                assert oversized.is_error
                assert "TRANSFER_CHUNK_LIMIT" in _tool_result_text(oversized)

    anyio.run(exercise)
