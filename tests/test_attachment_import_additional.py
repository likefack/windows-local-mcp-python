"""添付ファイル取り込みの追加回帰テスト。

既存テストで確認済みの境界を繰り返さず、実際の保存経路でのサイズ境界、
部分取得後の非変更性、保存先の逃避拒否、DNS解決結果の固定を確認する。
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any

import pytest
from PIL import Image
from test_attachment_import import PUBLIC, Response, install_network
from test_attachment_import_server import _configure_import, _file_reference
from test_high_level_operations import load_server

from windows_local_mcp import attachment_import as subject
from windows_local_mcp.artifact_errors import ArtifactTransferError
from windows_local_mcp.util import sha256_bytes


def _small_jpeg() -> bytes:
    """モデルが生成したBase64を経由せず、実ファイル相当の小さなJPEGを作る。"""

    output = io.BytesIO()
    image = Image.new("RGB", (48, 48), color=(12, 34, 56))
    image.save(output, format="JPEG", quality=90)
    payload = output.getvalue()
    assert payload.startswith(b"\xff\xd8\xff")
    assert len(payload) < 100_000
    return payload


def test_small_jpeg_import_preserves_bytes_and_sha256(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """小さいJPEGでもfileParams参照からそのまま保存できることを確認する。"""

    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    payload = _small_jpeg()
    source_sha256 = hashlib.sha256(payload).hexdigest()
    reference = _file_reference(file_name="small.jpg")
    calls = install_network(
        monkeypatch,
        Response(payload, headers=[("Content-Length", str(len(payload)))]),
    )

    result = server.artifact_import_file(
        reference,
        "small.jpg",
        sha256=source_sha256,
    )

    target = root / "small.jpg"
    assert target.read_bytes() == payload
    assert sha256_bytes(target.read_bytes()) == source_sha256
    assert result["after_sha256"] == source_sha256
    assert result["after_bytes"] == len(payload)
    assert result["detected_mime_type"] == "image/jpeg"
    # 取り込みではモデルがBase64本体を渡さず、参照URLだけが通信に使われる。
    assert calls[2] == (
        "GET",
        "/file?signature=do-not-persist",
        {"Accept-Encoding": "identity"},
    )


@pytest.mark.parametrize("over_by", [0, 1], ids=["exact-limit", "one-byte-over"])
def test_attachment_import_enforces_exact_size_limit_and_leaves_no_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, over_by: int
) -> None:
    """上限ちょうどは保存し、1バイト超過は保存先を作らず拒否する。"""

    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    payload = _small_jpeg()
    max_bytes = len(payload)
    delivered = payload + (b"x" if over_by else b"")
    reference = _file_reference(file_name="bounded.jpg")
    install_network(
        monkeypatch,
        Response(delivered, headers=[("Content-Length", str(len(delivered)))]),
    )
    server.runtime.settings.max_structured_file_bytes = max_bytes

    if over_by == 0:
        result = server.artifact_import_file(reference, "bounded.jpg")
        assert (root / "bounded.jpg").read_bytes() == payload
        assert result["after_bytes"] == max_bytes
    else:
        with pytest.raises(ArtifactTransferError, match="ATTACHMENT_SIZE_LIMIT"):
            server.artifact_import_file(reference, "bounded.jpg")
        assert not (root / "bounded.jpg").exists()


def test_interrupted_download_preserves_existing_target_and_creates_no_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """取得途中の通信失敗では既存ファイルもworkspaceも変更しない。"""

    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    target = root / "existing.bin"
    original = b"original bytes"
    target.write_bytes(original)
    reference = _file_reference(file_name="interrupted.bin")
    interrupted_payload = b"secret-body-marker" + (b"x" * 2048)
    install_network(
        monkeypatch,
        Response(
            interrupted_payload,
            headers=[("Content-Length", str(len(interrupted_payload)))],
            fail=True,
        ),
    )

    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_FETCH_FAILED"):
        server.artifact_import_file(
            reference,
            "existing.bin",
            expected_sha256=sha256_bytes(original),
        )

    assert target.read_bytes() == original
    assert [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()] == [
        "existing.bin"
    ]


@pytest.mark.parametrize(
    "path_kind",
    ["absolute", "nested-escape", "backslash-escape"],
)
def test_attachment_import_rejects_workspace_escape_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path_kind: str
) -> None:
    """workspace外を指す保存先では、取得処理を開始しない。"""

    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    if path_kind == "absolute":
        path = str(tmp_path / "outside.bin")
    elif path_kind == "nested-escape":
        path = "nested/../../outside.bin"
    else:
        path = r"nested\..\..\outside.bin"

    network_called = False

    def unexpected_download(_file: Any, **_kwargs: Any) -> Any:
        nonlocal network_called
        network_called = True
        raise AssertionError("workspace外の保存先ではネットワークを開始してはいけない")

    monkeypatch.setattr(server, "download_attachment", unexpected_download)
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_PATH_REJECTED"):
        server.artifact_import_file(_file_reference(), path)

    assert network_called is False
    assert not (tmp_path / "outside.bin").exists()
    assert not (root / "outside.bin").exists()


def test_attachment_dns_is_resolved_once_and_first_checked_address_is_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """取得中にDNSを再解決せず、検査済みの宛先へ接続する。"""

    response = Response(b"body", headers=[("Content-Length", "4")])
    dns_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    connection_calls: list[tuple[Any, ...]] = []

    def resolve(*args: Any, **kwargs: Any) -> list[tuple[int, int, int, str, tuple]]:
        dns_calls.append((args, kwargs))
        return PUBLIC

    class Connection:
        sock = None

        def __init__(self, host: str, address: tuple, *, timeout: float) -> None:
            connection_calls.append((host, address, timeout))

        def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
            connection_calls.append((method, target, headers))

        def getresponse(self) -> Response:
            return response

        def close(self) -> None:
            connection_calls.append(("closed",))

    monkeypatch.setattr(subject.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(subject, "_PinnedHTTPSConnection", Connection)

    result = subject.download_attachment(
        {"file_id": "file_dns_once", "download_url": "https://files.example.com/file"},
        allowed_hosts=["files.example.com"],
        max_bytes=100,
    )

    assert result.payload == b"body"
    assert len(dns_calls) == 1
    assert connection_calls[0][0:2] == ("files.example.com", PUBLIC[0])


def test_size_limit_failure_audit_omits_url_file_id_and_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """サイズ超過で失敗しても、URL・識別子・本文を監査記録へ残さない。"""

    server, root = load_server(tmp_path, monkeypatch)
    _configure_import(server)
    server.runtime.settings.max_structured_file_bytes = 1024
    secret_url = "https://files.example.com/file?signature=audit-secret-token"
    reference = {
        "download_url": secret_url,
        "file_id": "audit-secret-file-id",
        "mime_type": "application/octet-stream",
        "file_name": "audit-secret-name.bin",
    }
    oversized_payload = b"audit-secret-body" + (b"x" * 2048)
    install_network(
        monkeypatch,
        Response(
            oversized_payload,
            headers=[("Content-Length", str(len(oversized_payload)))],
        ),
    )

    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_SIZE_LIMIT"):
        server.artifact_import_file(reference, "must-not-exist.bin")

    assert not (root / "must-not-exist.bin").exists()
    audit_text = json.dumps(
        [
            server.runtime.audit.get_operation(item["id"])
            for item in server.runtime.audit.list_operations(limit=10)
        ],
        ensure_ascii=False,
        sort_keys=True,
    )
    for secret in (
        secret_url,
        "audit-secret-token",
        "audit-secret-file-id",
        "audit-secret-name.bin",
        "audit-secret-body",
    ):
        assert secret not in audit_text
