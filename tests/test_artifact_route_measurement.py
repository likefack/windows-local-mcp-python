"""同一バイナリ入力を3つの転送経路で比較する限定的な測定。

ここでの添付ファイル経路は、既存の合成HTTP transport mockを使うため、実ネットワークの
遅延やChatGPT側の処理時間を測定しない。測定値は回帰比較用であり、性能保証ではない。
"""

from __future__ import annotations

import base64
import json
import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from test_attachment_import import Response, install_network
from test_high_level_operations import load_server

from windows_local_mcp.util import sha256_bytes

MEASURED_SIZES = (0, 4 * 1024, 256 * 1024, 512 * 1024)
ONE_SHOT_LIMIT = 256 * 1024
RUNS = 3


def _payload(size: int) -> bytes:
    """圧縮などで入力が変わらないよう、決定的なバイト列を作る。"""

    return bytes((index * 131 + index // 257) % 256 for index in range(size))


def _measure(operation: Callable[[], dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    samples: list[int] = []
    last_result: dict[str, Any] | None = None
    for _ in range(RUNS):
        started = time.perf_counter_ns()
        last_result = operation()
        samples.append(time.perf_counter_ns() - started)
    assert last_result is not None
    return statistics.median(samples) / 1_000_000, last_result


def _assert_transaction_result(
    server: Any,
    root: Path,
    path: str,
    payload: bytes,
    result: dict[str, Any],
    expected_tool: str,
) -> None:
    digest = sha256_bytes(payload)
    assert (root / path).read_bytes() == payload
    assert result["after_sha256"] == digest
    operation = server.runtime.audit.get_operation(result["operation_id"])
    assert operation["tool_name"] == expected_tool
    assert operation["status"] == "succeeded"


def test_attachment_one_shot_and_chunk_routes_have_comparable_measurements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """0/4KiB/256KiB/512KiBを同じ設定で測り、SHA-256と取引完了を確認する。"""

    server, root = load_server(tmp_path, monkeypatch)
    # one-shotは256KiBまで、chunkは既定の512KiBまでを同じランタイム設定で測る。
    server.runtime.settings.max_one_shot_artifact_bytes = ONE_SHOT_LIMIT
    server.runtime.settings.max_transfer_chunk_bytes = 512 * 1024
    server.runtime.settings.max_structured_file_bytes = 2 * 1024 * 1024
    server.runtime.settings.attachment_import_allowed_hosts = ["files.example.com"]
    rows: list[dict[str, Any]] = []

    for size in MEASURED_SIZES:
        payload = _payload(size)
        digest = sha256_bytes(payload)
        encoded = base64.b64encode(payload).decode("ascii")

        import_samples: list[int] = []
        import_result: dict[str, Any] | None = None
        for run in range(RUNS):
            path = f"measurement-import-{size}-{run}.bin"
            reference = {
                "download_url": "https://files.example.com/measurement",
                "file_id": f"measurement-import-{size}-{run}",
            }
            # 実ネットワークは使わず、既存download_attachmentのHTTPモックを通す。
            install_network(
                monkeypatch,
                Response(payload, headers=[("Content-Length", str(size))]),
            )
            started = time.perf_counter_ns()
            import_result = server.artifact_import_file(reference, path, sha256=digest)
            import_samples.append(time.perf_counter_ns() - started)
            _assert_transaction_result(
                server, root, path, payload, import_result, "artifact_import_file"
            )

        rows.append(
            {
                "bytes": size,
                "route": "attachment_import",
                "median_ms": statistics.median(import_samples) / 1_000_000,
                "base64_characters": 0,
                "note": "synthetic HTTP transport; no network delay; attachment body is not Base64",
            }
        )

        if size <= ONE_SHOT_LIMIT:
            one_shot_paths: list[str] = []

            def one_shot_operation(
                *,
                size: int = size,
                encoded: str = encoded,
                digest: str = digest,
                paths: list[str] = one_shot_paths,
                runtime: Any = server,
            ) -> dict[str, Any]:
                one_shot_path = f"measurement-one-shot-{size}-{len(paths)}.bin"
                paths.append(one_shot_path)
                return runtime.artifact_upload(one_shot_path, encoded, digest)

            one_shot_ms, one_shot_result = _measure(
                one_shot_operation
            )
            _assert_transaction_result(
                server, root, one_shot_paths[-1], payload, one_shot_result, "artifact_upload"
            )
            rows.append(
                {
                    "bytes": size,
                    "route": "one_shot_upload",
                    "median_ms": one_shot_ms,
                    "base64_characters": len(encoded),
                    "note": "same settings; one-shot limit is 256KiB",
                }
            )
        else:
            rows.append(
                {
                    "bytes": size,
                    "route": "one_shot_upload",
                    "median_ms": None,
                    "base64_characters": None,
                    "note": "N/A: same settings reject payload above the 256KiB one-shot limit",
                }
            )

        chunk_path = f"measurement-chunk-{size}.bin"
        chunk_samples: list[int] = []
        chunk_result: dict[str, Any] | None = None
        for run in range(RUNS):
            started = time.perf_counter_ns()
            upload = server.artifact_upload_begin(chunk_path + f"-{run}", size, digest)
            if size:
                server.artifact_upload_chunk(upload["transfer_id"], 0, encoded)
            chunk_result = server.artifact_upload_commit(upload["transfer_id"])
            chunk_samples.append(time.perf_counter_ns() - started)
            _assert_transaction_result(
                server,
                root,
                chunk_path + f"-{run}",
                payload,
                chunk_result,
                "artifact_upload_commit",
            )
        assert chunk_result is not None
        rows.append(
            {
                "bytes": size,
                "route": "chunk_upload",
                "median_ms": statistics.median(chunk_samples) / 1_000_000,
                "base64_characters": len(encoded),
                "note": "same settings; one chunk per measured payload",
            }
        )

    # `-s` で実行したときに比較可能な測定結果を出力する。値は環境依存である。
    print(json.dumps(rows, ensure_ascii=False, sort_keys=True))
