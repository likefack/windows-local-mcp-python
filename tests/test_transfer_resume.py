"""Recovery contracts across duplicate delivery, expiry and MCP process restarts."""

from __future__ import annotations

import base64
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from pydantic import ValidationError
from test_artifact_transfer_errors import _load_server

from windows_local_mcp.config import Settings
from windows_local_mcp.util import sha256_bytes


def encoded(payload):
    return base64.b64encode(payload).decode("ascii")


def begin(server, payload=b"abcdefgh"):
    return server.artifact_upload_begin("out.bin", len(payload), sha256_bytes(payload))[
        "transfer_id"
    ]


def manifest_path(server, transfer_id):
    return server._transfer_root(transfer_id) / "manifest.json"


def test_duplicate_old_and_last_chunks_do_not_write_payload_or_manifest(tmp_path, monkeypatch):
    server, workspace = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    server.artifact_upload_chunk(transfer, 4, encoded(b"efgh"))
    root = server._transfer_root(transfer)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}
    for offset, data in [(0, b"abcd"), (4, b"efgh"), (0, b"abcd")]:
        result = server.artifact_upload_chunk(transfer, offset, encoded(data))
        assert result["received"] == 8 and result["complete"]
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}
    assert server.artifact_transfer_status(transfer)["can_commit"]
    server.artifact_upload_commit(transfer)
    # The retained receipt can acknowledge a lost chunk response even after commit.
    assert server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))["complete"]
    assert server.artifact_transfer_status(transfer)["state"] == "committed"
    assert (workspace / "out.bin").read_bytes() == b"abcdefgh"


@pytest.mark.parametrize("payload", [b"ABCD", b"abc", b"abcde"])
def test_duplicate_mismatch_is_terminal_integrity_failure(tmp_path, monkeypatch, payload):
    server, workspace = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    with pytest.raises(server.TransferIntegrityError, match="TRANSFER_DUPLICATE_MISMATCH"):
        server.artifact_upload_chunk(transfer, 0, encoded(payload))
    assert server.artifact_transfer_status(transfer)["state"] == "failed"
    assert not (workspace / "out.bin").exists()


@pytest.mark.parametrize("offset", [-1, 1, 3, 5, 8])
def test_future_and_partial_overlap_remain_recoverable(tmp_path, monkeypatch, offset):
    server, _ = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    with pytest.raises(server.ArtifactTransferStateError, match="TRANSFER_OFFSET_INVALID"):
        server.artifact_upload_chunk(transfer, offset, encoded(b"xy"))
    assert server.artifact_transfer_status(transfer)["state"] == "open"


def test_crash_before_manifest_publication_is_recoverable(tmp_path, monkeypatch):
    server, _ = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    original = server._write_transfer_manifest
    with monkeypatch.context() as patch:
        patch.setattr(
            server, "_write_transfer_manifest", lambda *_: (_ for _ in ()).throw(OSError("crash"))
        )
        with pytest.raises(OSError, match="crash"):
            server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    assert server.artifact_transfer_status(transfer)["next_offset"] == 0
    assert server._write_transfer_manifest is original
    server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    server.artifact_upload_chunk(transfer, 4, encoded(b"efgh"))
    server.artifact_upload_commit(transfer)


@pytest.mark.parametrize(
    "state", ["preparing", "open", "committed", "completed", "cancelled", "expired", "failed"]
)
def test_status_does_not_write_or_read_payload_and_returns_only_public_fields(
    tmp_path, monkeypatch, state
):
    server, _ = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    path = manifest_path(server, transfer)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest.update(state=state, error="private-internal-error", cancel_reason="private-reason")
    server._write_transfer_manifest(path.parent, manifest)
    before = path.read_bytes(), path.stat().st_mtime_ns
    monkeypatch.setattr(
        server, "_validated_transfer_payload", lambda *_a, **_k: pytest.fail("payload read")
    )
    result = server.artifact_transfer_status(transfer)
    assert result["state"] == state
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert "private" not in json.dumps(result)
    assert (
        not {"path", "error", "source_binding", "operation_id", "payload_identity"} & result.keys()
    )


def test_download_status_has_no_invented_client_acknowledgement(tmp_path, monkeypatch):
    server, workspace = _load_server(tmp_path, monkeypatch)
    (workspace / "source.bin").write_bytes(b"binary")
    transfer = server.artifact_download_begin("source.bin")["transfer_id"]
    status = server.artifact_transfer_status(transfer)
    assert status["state"] == "open" and status["received_bytes"] is None
    assert status["next_offset"] is None and not status["can_commit"]
    server.artifact_download_chunk(transfer, 0)
    assert server.artifact_transfer_status(transfer)["state"] == "completed"


def test_status_expiry_is_read_only_and_terminal_state_does_not_expire(tmp_path, monkeypatch):
    server, _ = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    path = manifest_path(server, transfer)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["created_at"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    manifest["expires_at"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    server._write_transfer_manifest(path.parent, manifest)
    before = path.read_bytes()
    assert server.artifact_transfer_status(transfer)["state"] == "expired"
    assert path.read_bytes() == before
    with pytest.raises(server.ArtifactTransferStateError, match="TRANSFER_EXPIRED"):
        server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    manifest["state"] = "cancelled"
    server._write_transfer_manifest(path.parent, manifest)
    assert server.artifact_transfer_status(transfer)["state"] == "cancelled"


def test_transfer_ttl_and_approval_ttl_are_independent(tmp_path, monkeypatch):
    server, _ = _load_server(tmp_path, monkeypatch)
    server.runtime.settings.binary_transfer_ttl_seconds = 90
    server.runtime.settings.approval_request_ttl_seconds = 30
    transfer = begin(server)
    status = server.artifact_transfer_status(transfer)
    assert (
        datetime.fromisoformat(status["expires_at"]) - datetime.fromisoformat(status["created_at"])
    ).total_seconds() == 90
    server.runtime.settings.approval_request_ttl_seconds = 86400
    server.runtime.settings.binary_transfer_ttl_seconds = 300
    assert server.artifact_transfer_status(transfer)["expires_at"] == status["expires_at"]
    assert server.runtime.settings.approval_request_ttl_seconds == 86400


@pytest.mark.parametrize("value", [29, 86401])
def test_transfer_ttl_configuration_bounds(tmp_path, value):
    with pytest.raises(ValidationError):
        Settings(workspace_root=tmp_path, binary_transfer_ttl_seconds=value)


@pytest.mark.parametrize(
    "value,code",
    [
        ("Zg=", "INVALID"),
        ("%%%%", "INVALID"),
        ("あ", "INVALID"),
        ("Zh==", "NONCANONICAL"),
        ("Zm9=", "NONCANONICAL"),
    ],
)
def test_invalid_or_noncanonical_base64(tmp_path, monkeypatch, value, code):
    server, _ = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    with pytest.raises(server.ArtifactTransferError, match="TRANSFER_BASE64_" + code):
        server.artifact_upload_chunk(transfer, 0, value)
    assert server.artifact_transfer_status(transfer)["state"] == "open"


def test_status_missing_or_invalid_id_has_identifiable_error(tmp_path, monkeypatch):
    server, _ = _load_server(tmp_path, monkeypatch)
    with pytest.raises(server.ArtifactTransferError, match="TRANSFER_ID_INVALID"):
        server.artifact_transfer_status("../escape")
    with pytest.raises(FileNotFoundError, match="TRANSFER_NOT_FOUND"):
        server.artifact_transfer_status(str(uuid.uuid4()))


def test_legacy_upload_can_resume_forward_without_guessing_old_boundaries(tmp_path, monkeypatch):
    server, _ = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    path = manifest_path(server, transfer)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["version"] = 4
    del manifest["receipt_count"]
    del manifest["expires_at"]
    server._write_transfer_manifest(path.parent, manifest)
    assert server.artifact_transfer_status(transfer)["next_offset"] == 4
    with pytest.raises(server.ArtifactTransferStateError, match="legacy upload"):
        server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    server.artifact_upload_chunk(transfer, 4, encoded(b"efgh"))
    server.artifact_upload_commit(transfer)


def test_duplicate_verifies_only_the_received_range_and_detects_corruption(tmp_path, monkeypatch):
    server, _ = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    path = server._transfer_root(transfer) / "payload.bin"
    with path.open("r+b") as output:
        output.write(b"ABCD")
    # A matching receipt hash alone must not acknowledge corrupted durable payload.
    with pytest.raises(server.TransferIntegrityError, match="changed after acknowledgement"):
        server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    assert server.artifact_transfer_status(transfer)["state"] == "failed"


@pytest.mark.parametrize("change", ["write", "replace", "snapshot"])
def test_download_begin_rejects_source_changes_or_persisted_corruption(
    tmp_path, monkeypatch, change
):
    server, workspace = _load_server(tmp_path, monkeypatch)
    source = workspace / "source.bin"
    source.write_bytes(b"original")
    copy = server._copy_source_to_reserved_snapshot

    def changed_copy(source, destination):
        result = copy(source, destination)
        if change == "snapshot":
            destination.write_bytes(b"tampered")
        elif change == "write":
            # Fault injection: production keeps a Windows handle that denies this write.
            # Release it here to test the independent post-copy identity/hash checks too.
            server.release_verified_hold(source)
            source.write_bytes(b"modified")
        else:
            server.release_verified_hold(source)
            replacement = workspace / "replacement.bin"
            replacement.write_bytes(b"original")
            os.replace(replacement, source)
        return result

    monkeypatch.setattr(server, "_copy_source_to_reserved_snapshot", changed_copy)
    with pytest.raises(RuntimeError, match="source changed|snapshot verification failed"):
        server.artifact_download_begin("source.bin")
    manifests = list(
        (server.runtime.settings.data_dir / "binary-transfers").glob("*/manifest.json")
    )
    assert len(manifests) == 1
    assert json.loads(manifests[0].read_text(encoding="utf-8"))["state"] == "failed"


def test_one_shot_oversize_is_rejected_before_decode(tmp_path, monkeypatch):
    from windows_local_mcp.artifact_fast_path import decode_one_shot_upload

    monkeypatch.setattr(base64, "b64decode", lambda *_a, **_k: pytest.fail("decoder called"))
    with pytest.raises(ValueError, match="TRANSFER_BASE64_LIMIT"):
        decode_one_shot_upload("A" * 10_000_000, max_bytes=1024, sha256=sha256_bytes(b""))


def test_extra_receipt_capacity_checks_quota_before_payload_write(tmp_path, monkeypatch):
    server, _ = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    root = server._transfer_root(transfer)
    # Simulate a small initial reservation so the second chunk needs more space.
    with (root / "chunks.bin").open("r+b") as index:
        index.truncate(server.RECEIPT_BYTES)
    server.artifact_upload_chunk(transfer, 0, encoded(b"abcd"))
    before = (root / "payload.bin").read_bytes()
    quota = server.enforce_data_quota
    with monkeypatch.context() as patch:
        patch.setattr(
            server,
            "enforce_data_quota",
            lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("quota exceeded")),
        )
        with pytest.raises(RuntimeError, match="quota exceeded"):
            server.artifact_upload_chunk(transfer, 4, encoded(b"efgh"))
    assert (root / "payload.bin").read_bytes() == before
    assert server.artifact_transfer_status(transfer)["next_offset"] == 4
    assert server.enforce_data_quota is quota
    server.artifact_upload_chunk(transfer, 4, encoded(b"efgh"))
    assert server.artifact_transfer_status(transfer)["can_commit"]


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing semantics")
@pytest.mark.parametrize("replace", [False, True])
def test_real_windows_source_hold_denies_mutation_during_copy(tmp_path, monkeypatch, replace):
    server, workspace = _load_server(tmp_path, monkeypatch)
    source = workspace / "source.bin"
    source.write_bytes(b"original")
    copy = server._copy_source_to_reserved_snapshot

    def attempt_mutation(source, destination):
        result = copy(source, destination)
        with pytest.raises(PermissionError):
            if replace:
                alternative = workspace / "alternative.bin"
                alternative.write_bytes(b"replacement")
                os.replace(alternative, source)
            else:
                source.write_bytes(b"modified")
        return result

    monkeypatch.setattr(server, "_copy_source_to_reserved_snapshot", attempt_mutation)
    result = server.artifact_download_begin("source.bin")
    assert result["sha256"] == sha256_bytes(b"original")


def test_real_stdio_resume_and_schema_across_restart(tmp_path, monkeypatch):
    _server, workspace = _load_server(tmp_path, monkeypatch)
    config = tmp_path / "config.toml"
    env = os.environ.copy()
    env.update(LOCAL_MCP_CONFIG=str(config), PYTHONIOENCODING="utf-8")
    env.pop("LOCAL_MCP_ROOT", None)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "windows_local_mcp.cli", "server"],
        env=env,
        cwd=str(Path(__file__).parents[1]),
    )
    payload = bytes(range(256)) * 2048  # Exactly 512 KiB; generated by the client, never an LLM.

    async def call(session, name, arguments):
        result = await session.call_tool(name, arguments)
        assert not result.is_error, result.content
        return result.structured_content

    async def exercise():
        with anyio.fail_after(60):
            async with stdio_client(params) as streams, ClientSession(*streams) as session:
                await session.initialize()
                tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                descriptor = tools["artifact_import_file"].model_dump(by_alias=True)
                assert descriptor["_meta"]["openai/fileParams"] == ["file"]
                assert set(descriptor["inputSchema"]["properties"]["file"]["properties"]) == {
                    "download_url",
                    "file_id",
                    "mime_type",
                    "file_name",
                }
                assert tools["artifact_transfer_status"].annotations.read_only_hint
                assert (
                    "artifact_export_file" not in tools
                )  # No undocumented ChatGPT export protocol.
                upload = await call(
                    session,
                    "artifact_upload_begin",
                    {
                        "path": "restart.bin",
                        "total_bytes": len(payload),
                        "sha256": sha256_bytes(payload),
                    },
                )
                transfer = upload["transfer_id"]
                arguments = {"transfer_id": transfer, "offset": 0, "base64_chunk": encoded(payload)}
                await call(
                    session, "artifact_upload_chunk", arguments
                )  # Pretend its response was lost.
                expiry = (
                    await call(session, "artifact_transfer_status", {"transfer_id": transfer})
                )["expires_at"]
            async with stdio_client(params) as streams, ClientSession(*streams) as session:
                await session.initialize()
                status = await call(session, "artifact_transfer_status", {"transfer_id": transfer})
                assert status["next_offset"] == len(payload) and status["can_commit"]
                assert status["expires_at"] == expiry
                assert (await call(session, "artifact_upload_chunk", arguments))["complete"]
                oversized = await session.call_tool(
                    "artifact_upload_chunk", {**arguments, "base64_chunk": "A" * (699052 + 4)}
                )
                assert oversized.is_error and "TRANSFER_BASE64_LIMIT" in str(oversized.content)
                await call(session, "artifact_upload_commit", {"transfer_id": transfer})
                assert (await call(session, "artifact_transfer_status", {"transfer_id": transfer}))[
                    "state"
                ] == "committed"
                invalid_file = await session.call_tool(
                    "artifact_import_file",
                    {
                        "file": {"file_id": "f", "download_url": "http://127.0.0.1/private-secret"},
                        "path": "bad.bin",
                    },
                )
                assert invalid_file.is_error and "private-secret" not in str(invalid_file.content)
            assert (workspace / "restart.bin").read_bytes() == payload

    anyio.run(exercise)


def test_admission_read_serializes_with_terminal_manifest_replacement(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from threading import Event, current_thread

    server, _ = _load_server(tmp_path, monkeypatch)
    transfer = begin(server)
    manifest_path = server._transfer_root(transfer) / "manifest.json"
    reading, release, cancelling = Event(), Event(), Event()
    original_read = Path.read_text

    def held_read(path, *args, **kwargs):
        if path == manifest_path and current_thread().name.startswith("admission-read"):
            # Keep the actual Windows read handle open until the competing cancel
            # has tried to replace the manifest, making the old race deterministic.
            with path.open("r", encoding="utf-8") as handle:
                reading.set()
                assert release.wait(5), "admission read was not released"
                return handle.read()
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", held_read)

    def cancel():
        cancelling.set()
        return server.artifact_transfer_cancel(transfer)

    with (
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="admission-read") as reader,
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="terminal-write") as writer,
    ):
        pending_read = reader.submit(server._admit_transfer)
        assert reading.wait(5)
        pending_cancel = writer.submit(cancel)
        assert cancelling.wait(5)
        try:
            with pytest.raises(TimeoutError):
                pending_cancel.result(timeout=0.2)
        finally:
            release.set()
        pending_read.result(timeout=5)
        assert pending_cancel.result(timeout=5)["state"] == "cancelled"
