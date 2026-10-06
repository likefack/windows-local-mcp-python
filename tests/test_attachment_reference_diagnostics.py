"""添付参照の診断を、入力の秘匿と公開 MCP 経路を含めて確認する。"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import Client
from PIL import Image
from test_attachment_import import HOST, Response, install_network
from test_high_level_operations import load_server

from windows_local_mcp import attachment_import as subject
from windows_local_mcp.artifact_errors import ArtifactTransferError
from windows_local_mcp.util import sha256_bytes

FILE_ID = "file_0000000011e08206a380acaa5ee5eb22"
PRIVATE = "secret-reference-marker"
EXPECTED = "expected=fileParams object {download_url, file_id, mime_type?, file_name?}"


def _reference(**changes: Any) -> dict[str, Any]:
    return {
        "download_url": f"https://{HOST}/private-input?signature={PRIVATE}",
        "file_id": FILE_ID,
        "mime_type": "image/png",
        "file_name": f"{PRIVATE}.png",
        **changes,
    }


def _assert_diagnostic(
    message: str,
    *,
    kind: str,
    reason: str,
    prefix: str = "invalid file reference",
    field: str | None = None,
    file_id_kind: str | None = None,
) -> None:
    # 従来のコードと文言を残し、追加項目の内容だけを固定値で確認する。
    assert f"ATTACHMENT_REFERENCE_REJECTED: {prefix};" in message
    assert "layer=server_reference_validation" in message
    assert f"reference_kind={kind}" in message
    assert f"reason={reason}" in message
    assert EXPECTED in message
    if field is not None:
        assert f"field={field}" in message
    if file_id_kind is not None:
        assert f"file_id_kind={file_id_kind}" in message
    assert PRIVATE not in message
    assert FILE_ID not in message


def _no_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_dns(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("不正な参照で DNS 解決へ到達した")

    monkeypatch.setattr(subject.socket, "getaddrinfo", unexpected_dns)


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        pytest.param(FILE_ID, "attachment_id", id="provided-attachment-id"),
        pytest.param(f"file-{PRIVATE}", "attachment_id", id="hyphen-attachment-id"),
        pytest.param(f"/mnt/data/{PRIVATE}.png", "local_path", id="posix-path"),
        pytest.param(rf"C:\private\{PRIVATE}.png", "local_path", id="windows-path"),
        pytest.param(f"C:{PRIVATE}", "local_path", id="drive-relative-path"),
        pytest.param(f"file_{PRIVATE}/photo.png", "local_path", id="id-with-path"),
        pytest.param(f"https://{HOST}/{PRIVATE}", "url", id="https-url"),
        pytest.param(f"http://{HOST}/{PRIVATE}", "url", id="http-url"),
        pytest.param(f"file:///C:/{PRIVATE}.png", "url", id="file-url"),
        pytest.param(f"data:image/png;base64,{PRIVATE}", "url", id="data-url"),
        pytest.param(f"{PRIVATE}.jpeg", "filename", id="jpeg-filename"),
        pytest.param(f"{PRIVATE}.jpg", "filename", id="jpg-filename"),
        pytest.param(f"{PRIVATE}.PNG", "filename", id="png-filename"),
        pytest.param(PRIVATE, "text", id="plain-text"),
        pytest.param(None, "missing", id="missing-reference"),
        pytest.param([_reference()], "array", id="array-reference"),
        pytest.param(123, "unsupported_type", id="numeric-reference"),
        pytest.param(True, "unsupported_type", id="boolean-reference"),
    ],
)
def test_bare_references_report_kind_before_dns(
    monkeypatch: pytest.MonkeyPatch, value: Any, kind: str
) -> None:
    _no_dns(monkeypatch)
    with pytest.raises(ArtifactTransferError) as raised:
        subject.download_attachment(value, allowed_hosts=[HOST], max_bytes=4096)
    assert raised.value.code == "ATTACHMENT_REFERENCE_REJECTED"
    _assert_diagnostic(str(raised.value), kind=kind, reason="object_required")


@pytest.mark.parametrize(
    ("value", "reason", "prefix", "field", "hosts"),
    [
        pytest.param(
            _reference(**{f"{PRIVATE}-unknown-key": f"{PRIVATE}-body"}),
            "unsupported_fields",
            "invalid file reference",
            None,
            [HOST],
            id="unknown-field-and-body",
        ),
        pytest.param(
            {"file_id": FILE_ID},
            "required_field_missing",
            "missing file reference field",
            "download_url",
            [HOST],
            id="missing-download-url",
        ),
        pytest.param(
            _reference(download_url=None),
            "required_field_missing",
            "missing file reference field",
            "download_url",
            [HOST],
            id="null-download-url",
        ),
        pytest.param(
            _reference(mime_type=None),
            "metadata_format",
            "invalid file metadata",
            "mime_type",
            [HOST],
            id="invalid-mime-type",
        ),
        pytest.param(
            _reference(file_name=[PRIVATE]),
            "metadata_format",
            "invalid file metadata",
            "file_name",
            [HOST],
            id="invalid-file-name",
        ),
        pytest.param(
            _reference(file_name=PRIVATE * 100),
            "metadata_format",
            "invalid file metadata",
            "file_name",
            [HOST],
            id="overlong-file-name",
        ),
        pytest.param(
            _reference(download_url=f"https://{HOST}/{PRIVATE}\n"),
            "download_url_format",
            "invalid download URL",
            "download_url",
            [HOST],
            id="control-character-url",
        ),
        pytest.param(
            _reference(download_url=f"https://{HOST}/日本語?token={PRIVATE}"),
            "download_url_format",
            "invalid download URL",
            "download_url",
            [HOST],
            id="non-ascii-url",
        ),
        pytest.param(
            _reference(download_url=f"http://{HOST}/{PRIVATE}"),
            "download_url_policy",
            "HTTPS file URL on port 443 required",
            "download_url",
            [HOST],
            id="url-policy",
        ),
        pytest.param(
            _reference(download_url=f"https://[{PRIVATE}/{PRIVATE}"),
            "download_url_policy",
            "HTTPS file URL on port 443 required",
            "download_url",
            [HOST],
            id="malformed-url",
        ),
        pytest.param(
            _reference(download_url=f"https://invalid_host.example/{PRIVATE}"),
            "file_service_host_format",
            "invalid file-service host",
            None,
            [],
            id="non-dns-service-host",
        ),
        pytest.param(
            _reference(download_url=f"https://other.example.com/{PRIVATE}"),
            "host_not_permitted",
            "file host is not permitted",
            None,
            [HOST],
            id="unapproved-host",
        ),
    ],
)
def test_object_rejection_explains_reason_without_echoing_private_fields(
    monkeypatch: pytest.MonkeyPatch,
    value: dict[str, Any],
    reason: str,
    prefix: str,
    field: str | None,
    hosts: list[str],
) -> None:
    _no_dns(monkeypatch)
    with pytest.raises(ArtifactTransferError) as raised:
        subject.download_attachment(value, allowed_hosts=hosts, max_bytes=4096)
    assert raised.value.code == "ATTACHMENT_REFERENCE_REJECTED"
    _assert_diagnostic(
        str(raised.value), kind="file_params_object", reason=reason, prefix=prefix, field=field
    )


@pytest.mark.parametrize(
    ("identifier", "kind", "reason"),
    [
        pytest.param(f"file_{PRIVATE}/image.png", "local_path", "identifier_format", id="path-id"),
        pytest.param(f"https://{HOST}/{PRIVATE}", "url", "identifier_format", id="url-id"),
        pytest.param(f"{PRIVATE}.png", "filename", "identifier_format", id="filename-id"),
        pytest.param(f"file_{PRIVATE}?token", "attachment_id", "identifier_format", id="bad-id"),
        pytest.param(f"{PRIVATE} value", "text", "identifier_format", id="text-id"),
        pytest.param(None, "missing", "required_field_missing", id="null-id"),
        pytest.param([PRIVATE], "array", "required_field_missing", id="array-id"),
        pytest.param(
            {"value": PRIVATE}, "file_params_object", "required_field_missing", id="object-id"
        ),
        pytest.param(123, "unsupported_type", "required_field_missing", id="numeric-id"),
    ],
)
def test_rejected_identifier_has_its_own_safe_classification(
    monkeypatch: pytest.MonkeyPatch, identifier: Any, kind: str, reason: str
) -> None:
    _no_dns(monkeypatch)
    with pytest.raises(ArtifactTransferError) as raised:
        subject.download_attachment(
            _reference(file_id=identifier), allowed_hosts=[HOST], max_bytes=4096
        )
    prefix = (
        "invalid file identifier"
        if reason == "identifier_format"
        else "missing file reference field"
    )
    _assert_diagnostic(
        str(raised.value),
        kind="file_params_object",
        reason=reason,
        prefix=prefix,
        field="file_id",
        file_id_kind=kind,
    )


def _audit_text(server: Any) -> str:
    return json.dumps(
        [
            server.runtime.audit.get_operation(item["id"])
            for item in server.runtime.audit.list_operations(limit=30)
        ],
        ensure_ascii=False,
        sort_keys=True,
    )


def test_mcp_returns_reference_diagnostics_before_download_or_save_and_redacts_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    server.runtime.settings.attachment_import_allowed_hosts = [HOST]
    calls: list[str] = []

    def forbidden(stage: str):
        def fail(*_args: Any, **_kwargs: Any) -> Any:
            calls.append(stage)
            raise AssertionError(f"不正な参照で {stage} へ到達した")

        return fail

    monkeypatch.setattr(subject.socket, "getaddrinfo", forbidden("DNS"))
    monkeypatch.setattr(server, "download_attachment", forbidden("download"))
    monkeypatch.setattr(server, "_atomic_binary_mutation", forbidden("save"))
    cases = [
        (FILE_ID, "attachment_id", "object_required", "invalid file reference", None, None),
        (
            f"/mnt/data/{PRIVATE}.png",
            "local_path",
            "object_required",
            "invalid file reference",
            None,
            None,
        ),
        (f"{PRIVATE}.png", "filename", "object_required", "invalid file reference", None, None),
        (
            _reference()["download_url"],
            "url",
            "object_required",
            "invalid file reference",
            None,
            None,
        ),
        (
            _reference(**{f"{PRIVATE}-key": f"{PRIVATE}-body"}),
            "file_params_object",
            "unsupported_fields",
            "invalid file reference",
            None,
            None,
        ),
        (
            {"download_url": _reference()["download_url"]},
            "file_params_object",
            "required_field_missing",
            "missing file reference field",
            "file_id",
            "missing",
        ),
        (
            _reference(file_id=f"private/{PRIVATE}"),
            "file_params_object",
            "identifier_format",
            "invalid file identifier",
            "file_id",
            "local_path",
        ),
    ]

    async def exercise() -> None:
        async with Client(server.mcp) as client:
            for value, kind, reason, prefix, field, file_id_kind in cases:
                result = await client.call_tool(
                    "artifact_import_file", {"file": value, "path": "not-created.png"}
                )
                assert result.is_error
                visible = "\n".join(getattr(item, "text", "") for item in result.content)
                _assert_diagnostic(
                    visible,
                    kind=kind,
                    reason=reason,
                    prefix=prefix,
                    field=field,
                    file_id_kind=file_id_kind,
                )
                # 本文以外の MCP 応答フィールドにも入力が混入していないことを確認する。
                assert PRIVATE not in result.model_dump_json()
                assert FILE_ID not in result.model_dump_json()

    anyio.run(exercise)
    assert calls == []
    assert not (root / "not-created.png").exists()
    operations = server.runtime.audit.list_operations(limit=30)
    assert len(operations) == len(cases)
    assert all(operation["status"] == "rejected" for operation in operations)
    audit = _audit_text(server)
    assert "ATTACHMENT_REFERENCE_REJECTED" in audit
    assert PRIVATE not in audit
    assert FILE_ID not in audit


def test_mcp_fileparams_schema_and_real_png_save_with_japanese_and_spaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    server.runtime.settings.attachment_import_allowed_hosts = [HOST]
    output = io.BytesIO()
    Image.new("RGB", (24, 16), (12, 34, 56)).save(output, format="PNG")
    payload = output.getvalue()
    digest = sha256_bytes(payload)
    response = Response(payload, headers=[("Content-Length", str(len(payload)))])
    calls = install_network(monkeypatch, response)
    (root / "日本語 保存先").mkdir()
    path = "日本語 保存先/元の画像 01.png"
    # 元の添付名にも日本語と空白を含め、保存先とは独立して扱うことを確認する。
    original_file_name = "日本語 元添付 image 01.png"

    async def exercise() -> dict[str, Any]:
        async with Client(server.mcp) as client:
            tool = next(
                tool
                for tool in (await client.list_tools()).tools
                if tool.name == "artifact_import_file"
            )
            assert tool.meta == {"openai/fileParams": ["file"]}
            file_schema = tool.input_schema["properties"]["file"]
            assert file_schema["type"] == "object"
            assert file_schema["required"] == ["download_url", "file_id"]
            assert file_schema["additionalProperties"] is False
            assert set(file_schema["properties"]) == {
                "download_url",
                "file_id",
                "mime_type",
                "file_name",
            }
            result = await client.call_tool(
                "artifact_import_file",
                {"file": _reference(file_name=original_file_name), "path": path, "sha256": digest},
            )
            assert not result.is_error
            assert result.structured_content is not None
            assert PRIVATE not in result.model_dump_json()
            assert FILE_ID not in result.model_dump_json()
            assert original_file_name not in result.model_dump_json()
            return result.structured_content

    result = anyio.run(exercise)
    assert (root / path).read_bytes() == payload
    assert result["after_sha256"] == digest
    assert result["after_bytes"] == len(payload)
    assert result["detected_mime_type"] == "image/png"
    assert result["source_sha256_verified"] is True
    assert result["execution_path"] == "attachment_import"
    assert calls[2] == (
        "GET",
        f"/private-input?signature={PRIVATE}",
        {"Accept-Encoding": "identity"},
    )
    assert calls[1].closed
    assert PRIVATE not in _audit_text(server)
    assert FILE_ID not in _audit_text(server)
    assert original_file_name not in _audit_text(server)
