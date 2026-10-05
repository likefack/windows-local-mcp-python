from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import Client
from PIL import Image
from test_attachment_import import Response, install_network
from test_high_level_operations import load_server

from windows_local_mcp.artifact_errors import ArtifactTransferError
from windows_local_mcp.attachment_import import DownloadedAttachment
from windows_local_mcp.util import sha256_bytes


def _file_reference(*, file_name: str = "source.jpg") -> dict[str, str]:
    return {
        "download_url": "https://files.example.com/file?signature=do-not-persist",
        "file_id": "file_test_123",
        "mime_type": "image/jpeg",
        "file_name": file_name,
    }


def _large_jpeg() -> bytes:
    """Create a real, nontrivial JPEG so the server test exercises binary persistence."""

    image = Image.effect_noise((1024, 768), 100).convert("RGB")
    output = io.BytesIO()
    image.save(output, format="JPEG", quality=92)
    payload = output.getvalue()
    assert len(payload) > 200_000
    return payload


def _configure_import(server: Any) -> None:
    server.runtime.settings.attachment_import_allowed_hosts = ["files.example.com"]
    server.runtime.settings.attachment_import_timeout_seconds = 17


def _audit_text(server: Any, operation_id: str) -> str:
    operation = server.runtime.audit.get_operation(operation_id)
    return json.dumps(operation, ensure_ascii=False, sort_keys=True)


def _result_text(result: object) -> str:
    return "\n".join(
        str(getattr(item, "text", ""))
        for item in getattr(result, "content", [])
        if getattr(item, "text", None) is not None
    )


def test_attachment_import_saves_real_jpeg_with_hash_and_checkpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    payload = _large_jpeg()
    source_sha256 = sha256_bytes(payload)
    calls: list[dict[str, Any]] = []
    (root / "imports").mkdir()

    def fake_download(file: Any, **kwargs: Any) -> DownloadedAttachment:
        calls.append({"file": file, **kwargs})
        return DownloadedAttachment(payload, source_sha256, "image/jpeg")

    monkeypatch.setattr(server, "download_attachment", fake_download)
    result = server.artifact_import_file(
        _file_reference(file_name="../../ignored-name.jpg"),
        "imports/photo.jpg",
        sha256=source_sha256,
    )

    target = root / "imports" / "photo.jpg"
    assert target.read_bytes() == payload
    assert not (root / "ignored-name.jpg").exists()
    assert result["before_sha256"] == sha256_bytes(b"")
    assert result["after_sha256"] == source_sha256
    assert result["after_bytes"] == len(payload)
    assert result["execution_path"] == "attachment_import"
    assert result["detected_mime_type"] == "image/jpeg"
    assert result["embedded_code_executed"] is False
    assert result["source_sha256_verified"] is True
    assert calls == [
        {
            "file": _file_reference(file_name="../../ignored-name.jpg"),
            "allowed_hosts": ["files.example.com"],
            "max_bytes": server.runtime.settings.max_structured_file_bytes,
            "expected_sha256": source_sha256,
            "timeout_seconds": 17,
        }
    ]

    operation = server.runtime.audit.get_operation(result["operation_id"])
    assert operation["status"] == "succeeded"
    assert operation["pre_workspace_path"]
    assert operation["post_workspace_path"]
    before = server.verify_checkpoint_integrity(
        server.runtime.settings, operation["pre_workspace_path"]
    )
    after = server.verify_checkpoint_integrity(
        server.runtime.settings, operation["post_workspace_path"]
    )
    assert "imports/photo.jpg" not in before
    assert after["imports/photo.jpg"] == source_sha256
    audit_text = _audit_text(server, result["operation_id"])
    assert "do-not-persist" not in audit_text
    assert "file_test_123" not in audit_text
    assert "ignored-name.jpg" not in audit_text


def test_attachment_import_integrates_fileparams_network_and_atomic_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    payload = _large_jpeg()
    source_sha256 = sha256_bytes(payload)
    response = Response(payload, headers=[("Content-Length", str(len(payload)))])
    calls = install_network(monkeypatch, response)
    reference = _file_reference(file_name="official-upload.jpg")

    result = server.artifact_import_file(
        reference,
        "integrated.jpg",
        sha256=source_sha256,
    )

    assert (root / "integrated.jpg").read_bytes() == payload
    assert result["after_sha256"] == source_sha256
    assert result["source_sha256_verified"] is True
    assert calls[2] == (
        "GET",
        "/file?signature=do-not-persist",
        {"Accept-Encoding": "identity"},
    )
    assert calls[1].closed is True


@pytest.mark.parametrize(
    ("response", "max_bytes", "error_code"),
    [
        (Response(b"x" * 2048), 1024, "ATTACHMENT_SIZE_LIMIT"),
        (Response(b"x" * 2048, fail=True), 4096, "ATTACHMENT_FETCH_FAILED"),
    ],
    ids=["oversize", "interrupted"],
)
def test_attachment_import_network_failure_never_creates_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: Response,
    max_bytes: int,
    error_code: str,
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    server.runtime.settings.max_structured_file_bytes = max_bytes
    install_network(monkeypatch, response)

    with pytest.raises(ArtifactTransferError, match=error_code):
        server.artifact_import_file(
            {
                "download_url": _file_reference()["download_url"],
                "file_id": "file_failure_test",
            },
            "must-not-exist.bin",
        )

    assert not (root / "must-not-exist.bin").exists()


def test_attachment_import_requires_and_rechecks_destination_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    target = root / "target.bin"
    target.write_bytes(b"original")
    replacement = b"replacement"
    downloads = 0

    def fake_download(_file: Any, **_kwargs: Any) -> DownloadedAttachment:
        nonlocal downloads
        downloads += 1
        return DownloadedAttachment(
            replacement, sha256_bytes(replacement), "application/octet-stream"
        )

    monkeypatch.setattr(server, "download_attachment", fake_download)
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_CAS_REQUIRED"):
        server.artifact_import_file(_file_reference(), "target.bin")
    with pytest.raises(RuntimeError, match="ATTACHMENT_CAS_MISMATCH"):
        server.artifact_import_file(
            _file_reference(), "target.bin", expected_sha256="0" * 64
        )
    assert downloads == 0
    assert target.read_bytes() == b"original"

    result = server.artifact_import_file(
        _file_reference(),
        "target.bin",
        expected_sha256=sha256_bytes(b"original"),
    )
    assert downloads == 1
    assert target.read_bytes() == replacement
    assert result["before_sha256"] == sha256_bytes(b"original")
    assert result["after_sha256"] == sha256_bytes(replacement)


def test_attachment_import_rejects_download_time_destination_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    target = root / "target.bin"
    target.write_bytes(b"original")
    expected = sha256_bytes(target.read_bytes())

    def racing_download(_file: Any, **_kwargs: Any) -> DownloadedAttachment:
        # Simulate another local actor changing the destination while network I/O is active.
        target.write_bytes(b"concurrent")
        payload = b"downloaded"
        return DownloadedAttachment(
            payload, sha256_bytes(payload), "application/octet-stream"
        )

    monkeypatch.setattr(server, "download_attachment", racing_download)
    with pytest.raises(RuntimeError, match="expected_sha256 mismatch"):
        server.artifact_import_file(
            _file_reference(), "target.bin", expected_sha256=expected
        )

    assert target.read_bytes() == b"concurrent"


@pytest.mark.parametrize("path", ["../outside.jpg", "missing/photo.jpg"])
def test_attachment_import_rejects_invalid_destination_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    server, _root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    network_called = False

    def unexpected_download(_file: Any, **_kwargs: Any) -> DownloadedAttachment:
        nonlocal network_called
        network_called = True
        raise AssertionError("network must not run for an invalid destination")

    monkeypatch.setattr(server, "download_attachment", unexpected_download)
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_PATH_REJECTED"):
        server.artifact_import_file(_file_reference(), path)

    assert network_called is False


def test_attachment_import_fetch_failure_is_nonmutating_and_url_free_in_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    target = root / "target.bin"
    target.write_bytes(b"original")
    secret_url = _file_reference()["download_url"]

    def interrupted_download(_file: Any, **_kwargs: Any) -> DownloadedAttachment:
        # Unknown downloader errors may contain the bearer URL and must be normalized.
        raise RuntimeError(f"connection interrupted while reading {secret_url}")

    monkeypatch.setattr(server, "download_attachment", interrupted_download)
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_FETCH_FAILED") as raised:
        server.artifact_import_file(
            _file_reference(),
            "target.bin",
            expected_sha256=sha256_bytes(b"original"),
        )

    assert secret_url not in str(raised.value)
    assert target.read_bytes() == b"original"
    rejected = server.runtime.audit.list_operations(limit=1)[0]
    assert rejected["tool_name"] == "artifact_import_file"
    assert rejected["status"] == "rejected"
    audit_text = _audit_text(server, rejected["id"])
    assert secret_url not in audit_text
    assert "do-not-persist" not in audit_text
    assert "file_test_123" not in audit_text


def test_attachment_import_uses_existing_recovery_after_post_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    target = root / "target.bin"
    target.write_bytes(b"original")
    replacement = b"downloaded replacement"
    real_capture = server.capture_workspace_state

    def fake_download(_file: Any, **_kwargs: Any) -> DownloadedAttachment:
        return DownloadedAttachment(
            replacement, sha256_bytes(replacement), "application/octet-stream"
        )

    def fail_after(settings: Any, operation_id: str, stage: str, *, paths: Any = None):
        if stage == "after":
            raise RuntimeError("forced post-write checkpoint failure")
        return real_capture(settings, operation_id, stage, paths=paths)

    monkeypatch.setattr(server, "download_attachment", fake_download)
    monkeypatch.setattr(server, "capture_workspace_state", fail_after)
    with pytest.raises(server.WorkspaceMutationError) as raised:
        server.artifact_import_file(
            _file_reference(),
            "target.bin",
            expected_sha256=sha256_bytes(b"original"),
        )

    assert raised.value.recovery_state == "failed_recovered"
    assert target.read_bytes() == b"original"
    assert server.workspace_recovery_required(server.runtime.settings) is False
    operation = server.runtime.audit.list_operations(limit=1)[0]
    assert operation["tool_name"] == "artifact_import_file"
    detail = server.runtime.audit.get_operation(operation["id"])
    assert detail["status"] == "failed"


def test_attachment_import_tool_declares_fileparams_and_bounded_file_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _root = load_server(tmp_path, monkeypatch)
    tool = next(
        tool
        for tool in server.mcp._tool_manager.list_tools()
        if tool.name == "artifact_import_file"
    )

    assert tool.meta == {"openai/fileParams": ["file"]}
    file_schema = tool.parameters["properties"]["file"]
    assert file_schema["type"] == "object"
    assert file_schema["required"] == ["download_url", "file_id"]
    assert file_schema["additionalProperties"] is False
    assert set(file_schema["properties"]) == {
        "download_url",
        "file_id",
        "mime_type",
        "file_name",
    }
    assert tool.parameters["required"] == ["file", "path"]


def test_attachment_import_sdk_rejects_invalid_file_without_exposing_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    scalar_secret = "sdk-secret-scalar"
    url_secret = "https://files.example.com/file?signature=sdk-secret-url"

    async def exercise() -> None:
        async with Client(server.mcp) as client:
            scalar = await client.call_tool(
                "artifact_import_file", {"file": scalar_secret, "path": "target.bin"}
            )
            invalid_dict = await client.call_tool(
                "artifact_import_file",
                {
                    "file": {
                        "download_url": url_secret,
                        "file_id": "file_sdk_test",
                        "unknown": "sdk-secret-metadata",
                    },
                    "path": "target.bin",
                },
            )
            missing_path = await client.call_tool(
                "artifact_import_file",
                {
                    "file": {
                        "download_url": url_secret,
                        "file_id": "file_missing_path",
                    }
                },
            )
            invalid_path_type = await client.call_tool(
                "artifact_import_file",
                {
                    "file": {
                        "download_url": url_secret,
                        "file_id": "file_invalid_path",
                    },
                    "path": {"value": "sdk-secret-path"},
                },
            )
            assert scalar.is_error
            assert invalid_dict.is_error
            assert missing_path.is_error
            assert invalid_path_type.is_error
            visible = "".join(
                _result_text(result)
                for result in (scalar, invalid_dict, missing_path, invalid_path_type)
            )
            assert scalar_secret not in visible
            assert "sdk-secret-url" not in visible
            assert "sdk-secret-metadata" not in visible
            assert "sdk-secret-path" not in visible

    anyio.run(exercise)
    operations = server.runtime.audit.list_operations(limit=10)
    audit_text = json.dumps(
        [server.runtime.audit.get_operation(item["id"]) for item in operations],
        ensure_ascii=False,
        sort_keys=True,
    )
    assert scalar_secret not in audit_text
    assert "sdk-secret-url" not in audit_text
    assert "sdk-secret-metadata" not in audit_text
    assert "sdk-secret-path" not in audit_text
