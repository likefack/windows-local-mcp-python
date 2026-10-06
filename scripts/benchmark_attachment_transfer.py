"""実 JPEG/PNG の添付取り込みと分割アップロードを合成通信で比較する。

既存の MCP SDK Client と Broker 保存処理を使用する。外部通信、ChatGPT、LLM の
所要時間は測らない。画像本体や Base64 は標準出力・結果 JSON に出さない。
"""

from __future__ import annotations

import argparse
import base64
import gc
import hashlib
import importlib
import json
import math
import os
import platform
import random
import socket
import statistics
import subprocess
import sys
import threading
import time
import traceback
import tracemalloc
import uuid
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path
from typing import Any
from unittest.mock import patch

import anyio
import psutil
from mcp import Client
from PIL import Image

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CHUNK_BYTES = 512 * 1024
TARGET_BYTES = (256 * 1024, 1024 * 1024, 4 * 1024 * 1024)
SYNTHETIC_HOST = "files.example.com"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_hashes() -> dict[str, str]:
    """並行編集の検出用。ソース本文を保存せず、測定区間外で指紋を取る。"""

    package = REPOSITORY_ROOT / "src" / "windows_local_mcp"
    return {
        path.relative_to(REPOSITORY_ROOT).as_posix(): _file_sha256(path)
        for path in sorted(package.rglob("*.py"))
        if path.is_file()
    }


def make_fixture(directory: Path, image_format: str, target_bytes: int) -> dict[str, Any]:
    """固定 seed の RGB 雑音を実エンコードし、目標の約 5% 以内に近付ける。"""

    directory.mkdir(parents=True, exist_ok=True)
    extension = "jpg" if image_format == "JPEG" else "png"
    path = directory / f"image-{target_bytes}-{image_format.lower()}.{extension}"
    bytes_per_pixel = 0.9 if image_format == "JPEG" else 3.0
    side = max(8, round(math.sqrt(target_bytes / bytes_per_pixel)))
    for attempt in range(3):
        pixels = random.Random(20261006 + target_bytes).randbytes(side * side * 3)
        image = Image.frombytes("RGB", (side, side), pixels)
        if image_format == "JPEG":
            image.save(path, format="JPEG", quality=90, optimize=False)
        else:
            image.save(path, format="PNG", compress_level=0)
        image.close()
        actual_bytes = path.stat().st_size
        if abs(actual_bytes - target_bytes) <= target_bytes * 0.05:
            break
        if attempt < 2:
            side = max(8, round(side * math.sqrt(target_bytes / actual_bytes)))
    # シグネチャだけでなく、Pillow で最後まで読める実画像であることを確認する。
    with Image.open(path) as decoded:
        decoded.load()
        if decoded.format != image_format:
            raise RuntimeError("fixture image format mismatch")
        dimensions = list(decoded.size)
    return {
        "path": str(path.resolve()),
        "format": image_format,
        "target_bytes": target_bytes,
        "bytes": actual_bytes,
        "sha256": _file_sha256(path),
        "dimensions": dimensions,
        "mime_type": "image/jpeg" if image_format == "JPEG" else "image/png",
        "generation": "deterministic RGB noise; JPEG quality=90 or PNG compress_level=0",
    }


class _FileResponse:
    """HTTPS の代わりにローカル画像を読み、製品の受信・検証ループを通す。"""

    status = 200

    def __init__(self, path: Path) -> None:
        self.headers = Message()
        self.headers["Content-Length"] = str(path.stat().st_size)
        self.source = path.open("rb")

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)

    def read1(self, count: int) -> bytes:
        return self.source.read(count)

    def close(self) -> None:
        self.source.close()


def _network_patches(path: Path) -> tuple[Any, Any]:
    from windows_local_mcp import attachment_import

    class Connection:
        sock = None

        def __init__(self, host: str, address: Any, *, timeout: float) -> None:
            self.response: _FileResponse | None = None

        def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
            if method != "GET":
                raise RuntimeError("unexpected synthetic request")

        def getresponse(self) -> _FileResponse:
            self.response = _FileResponse(path)
            return self.response

        def close(self) -> None:
            if self.response is not None:
                self.response.close()

    public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    return (
        patch.object(attachment_import.socket, "getaddrinfo", return_value=public),
        patch.object(attachment_import, "_PinnedHTTPSConnection", Connection),
    )


def _load_server(case_root: Path) -> tuple[Any, Path]:
    """実環境と分離した設定だけを用い、保存・取引の実装は置き換えない。"""

    workspace = case_root / "workspace"
    workspace.mkdir(parents=True, exist_ok=False)
    config = case_root / "config.toml"
    config.write_text(
        "\n".join(
            [
                f"workspace_root = {json.dumps(str(workspace))}",
                f"data_dir = {json.dumps(str(case_root / 'data'))}",
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "approved_sandbox_enabled = false",
                "approved_host_enabled = false",
                f"max_transfer_chunk_bytes = {CHUNK_BYTES}",
                "max_data_dir_bytes = 134217728",
                f"attachment_import_allowed_hosts = [{json.dumps(SYNTHETIC_HOST)}]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    os.environ["LOCAL_MCP_CONFIG"] = str(config)
    os.environ.pop("LOCAL_MCP_ROOT", None)
    sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
    server = importlib.import_module("windows_local_mcp.server")
    return server, workspace


class _RssSampler:
    """現在 RSS を周期観測する。短い頂点を取り逃すため観測下限として扱う。"""

    def __init__(self) -> None:
        self.process = psutil.Process()
        self.baseline = self.process.memory_info().rss
        self.peak = self.baseline
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self) -> None:
        while not self.stop_event.wait(0.002):
            self.peak = max(self.peak, self.process.memory_info().rss)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> dict[str, int | None]:
        self.peak = max(self.peak, self.process.memory_info().rss)
        self.stop_event.set()
        self.thread.join(timeout=1)
        info = self.process.memory_info()
        return {
            "rss_baseline_bytes": self.baseline,
            "rss_observed_peak_bytes": self.peak,
            "rss_observed_increase_bytes": max(0, self.peak - self.baseline),
            # Windows の peak_wset はプロセス起動以来の値。測定区間の頂点と混同しない。
            "process_lifetime_peak_working_set_bytes": getattr(info, "peak_wset", None),
        }


class _Recorder:
    def __init__(self, client: Client) -> None:
        self.client = client
        self.calls = 0
        self.base64_characters = 0
        self.input_json_characters = 0
        self.output_json_characters = 0

    async def invoke(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        self.base64_characters += len(arguments.get("base64_chunk", ""))
        # 本体を記録しない。サイズだけ集計し、JSON serialization の費用も区間に含める。
        request = {"name": name, "arguments": arguments}
        self.input_json_characters += len(json.dumps(request, separators=(",", ":")))
        response = await self.client.call_tool(name, arguments)
        if response.is_error:
            # SDK エラー全文を表示せず、本文が診断へ出る余地を作らない。
            raise RuntimeError(f"MCP tool failed: {name}")
        self.output_json_characters += len(
            json.dumps(response.model_dump(mode="json", by_alias=True), separators=(",", ":"))
        )
        result = response.structured_content
        if result is None:
            text_blocks = [item.text for item in response.content if item.type == "text"]
            result = json.loads(text_blocks[0])
        if not isinstance(result, dict):
            raise TypeError("MCP result must be an object")
        return result


def _verify_result(server: Any, workspace: Path, destination: str, fixture: dict[str, Any],
                   result: dict[str, Any], route: str) -> dict[str, Any]:
    target = workspace / destination
    if target.stat().st_size != fixture["bytes"] or _file_sha256(target) != fixture["sha256"]:
        raise RuntimeError("committed image differs from source")
    if result["after_sha256"] != fixture["sha256"]:
        raise RuntimeError("result hash differs from source")
    operation = server.runtime.audit.get_operation(result["operation_id"])
    expected_tool = "artifact_import_file" if route == "attachment_import" else "artifact_upload_commit"
    if operation["status"] != "succeeded" or operation["tool_name"] != expected_tool:
        raise RuntimeError("Broker operation did not succeed")
    before = server.verify_checkpoint_integrity(server.runtime.settings, operation["pre_workspace_path"])
    after = server.verify_checkpoint_integrity(server.runtime.settings, operation["post_workspace_path"])
    if destination in before or after.get(destination) != fixture["sha256"]:
        raise RuntimeError("checkpoint verification failed")
    return {
        "operation_id": result["operation_id"],
        "saved_bytes": target.stat().st_size,
        "saved_sha256": fixture["sha256"],
        "pre_and_post_checkpoints_verified": True,
        "broker_operation_status": operation["status"],
        "execution_path": result["execution_path"],
    }


async def _measure_case(server: Any, workspace: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    fixture = manifest["fixture"]
    source_path = Path(fixture["path"])
    route = manifest["route"]
    destination = "received" + source_path.suffix
    async with Client(server.mcp, mode="legacy") as client:
        recorder = _Recorder(client)
        gc.collect()
        rss = _RssSampler()
        rss.start()
        tracemalloc.start()
        started = time.perf_counter_ns()
        try:
            if route == "attachment_import":
                result = await recorder.invoke(
                    "artifact_import_file",
                    {
                        "file": {
                            "download_url": f"https://{SYNTHETIC_HOST}/benchmark",
                            "file_id": "synthetic-file",
                            "mime_type": fixture["mime_type"],
                            "file_name": source_path.name,
                        },
                        "path": destination,
                        "sha256": fixture["sha256"],
                    },
                )
            else:
                upload = await recorder.invoke(
                    "artifact_upload_begin",
                    {"path": destination, "total_bytes": fixture["bytes"], "sha256": fixture["sha256"]},
                )
                offset = 0
                # プログラムだけが画像と Base64 を保持する。全体を一括 Base64 化しない。
                # ローカル入力の同期読み込みもクライアント処理時間として測る。
                with source_path.open("rb") as source:  # noqa: ASYNC230
                    while raw := source.read(CHUNK_BYTES):
                        encoded = base64.b64encode(raw).decode("ascii")
                        await recorder.invoke(
                            "artifact_upload_chunk",
                            {"transfer_id": upload["transfer_id"], "offset": offset, "base64_chunk": encoded},
                        )
                        offset += len(raw)
                        del raw, encoded
                result = await recorder.invoke(
                    "artifact_upload_commit", {"transfer_id": upload["transfer_id"]}
                )
        finally:
            elapsed_ns = time.perf_counter_ns() - started
            _current, python_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            memory = rss.stop()
    verified = _verify_result(server, workspace, destination, fixture, result, route)
    return {
        "route": route,
        "sample": manifest["sample"],
        "fixture": fixture,
        "local_elapsed_ms": elapsed_ns / 1_000_000,
        "mcp_tool_calls": recorder.calls,
        "mcp_argument_base64_body_characters": recorder.base64_characters,
        "model_copied_base64_body_characters": 0,
        "input_tool_json_characters": recorder.input_json_characters,
        "output_result_json_characters": recorder.output_json_characters,
        "python_tracemalloc_peak_bytes": python_peak,
        **memory,
        "verification": verified,
    }


def _worker(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    server, workspace = _load_server(Path(manifest["case_root"]))
    source_path = Path(manifest["fixture"]["path"])
    dns, connection = _network_patches(source_path)
    # SCM/WFP/ACL 等の実環境の health state は速度比較から外す。取引は本物を使う。
    with patch.object(server, "assert_control_plane_healthy", return_value=None), dns, connection:
        return anyio.run(_measure_case, server, workspace, manifest)


def _safe_failure(error: BaseException) -> dict[str, Any]:
    """例外本文・ローカル変数を含めず、入れ子になった失敗箇所だけを返す。"""

    diagnostic = {
        "type": type(error).__name__,
        "errno": getattr(error, "errno", None),
        "winerror": getattr(error, "winerror", None),
        "locations": [
            {"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
            for frame in traceback.extract_tb(error.__traceback__)
        ],
    }
    if isinstance(error, BaseExceptionGroup):
        diagnostic["children"] = [_safe_failure(child) for child in error.exceptions]
    return diagnostic


def run(output_path: Path, samples: int = 1) -> dict[str, Any]:
    source_start = _source_hashes()
    # 取引・checkpoint は配下に追加の名前を生成するため、測定側の親名を短く保つ。
    # Windows の長い一時ディレクトリでも、製品の実保存処理を省略せずに比較する。
    run_id = "b" + uuid.uuid4().hex[:8]
    run_root = output_path.parent / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    fixtures = [
        make_fixture(run_root / "fixtures", image_format, target)
        for target in TARGET_BYTES
        for image_format in ("JPEG", "PNG")
    ]
    rows = []
    for fixture_index, fixture in enumerate(fixtures):
        for sample in range(1, samples + 1):
            # 交互順で実行し、常に先行する経路による cache 順序効果を抑える。
            routes = ("attachment_import", "chunk_upload")
            if sample % 2 == 0:
                routes = tuple(reversed(routes))
            for route in routes:
                route_code = "i" if route == "attachment_import" else "u"
                case_root = run_root / f"c{fixture_index}-{route_code}-{sample}"
                manifest = {"fixture": fixture, "route": route, "sample": sample, "case_root": str(case_root)}
                manifest_path = case_root.with_suffix(".json")
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                environment = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
                worker = subprocess.run(
                    [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", str(manifest_path)],
                    cwd=REPOSITORY_ROOT, env=environment, capture_output=True, text=True,
                    encoding="utf-8", timeout=120, check=False,
                )
                if worker.returncode:
                    # stderr は画像本体を含む可能性を除外できないため転記しない。
                    try:
                        diagnostic = json.loads(worker.stdout).get("worker_error", {})
                    except (ValueError, AttributeError):
                        diagnostic = {}
                    raise RuntimeError(
                        f"isolated worker failed ({route}, exit={worker.returncode}): {diagnostic}"
                    )
                rows.append(json.loads(worker.stdout))
    source_end = _source_hashes()
    changed_sources = sorted(
        path for path in source_start.keys() | source_end.keys()
        if source_start.get(path) != source_end.get(path)
    )
    summaries = []
    for fixture in fixtures:
        for route in ("attachment_import", "chunk_upload"):
            group = [row for row in rows if row["fixture"]["path"] == fixture["path"] and row["route"] == route]
            fields = ("local_elapsed_ms", "mcp_tool_calls", "mcp_argument_base64_body_characters",
                      "python_tracemalloc_peak_bytes", "rss_baseline_bytes", "rss_observed_peak_bytes",
                      "rss_observed_increase_bytes")
            summaries.append({
                "format": fixture["format"], "bytes": fixture["bytes"], "target_bytes": fixture["target_bytes"],
                "route": route, "medians": {key: statistics.median(row[key] for row in group) for key in fields},
            })
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "samples_per_image_per_route": samples,
        "chunk_raw_bytes": CHUNK_BYTES,
        "source_snapshot": {
            "start_sha256_by_file": source_start,
            "end_sha256_by_file": source_end,
            "unchanged": not changed_sources,
            "changed_files": changed_sources,
            "scope": "src/windows_local_mcp/**/*.py; boundary snapshots exclude measurement timing",
        },
        "comparison_valid": not changed_sources,
        "measurement_scope": {
            "entry_point": "MCP SDK Client(server.mcp, mode=legacy), in-memory transport; fresh worker per sample",
            "includes": ["fixture file reading", "programmatic chunk Base64 encoding", "SDK validation and in-memory calls",
                         "compact JSON size instrumentation", "Broker CAS/transaction/checkpoint/audit and persistence"],
            "excludes": ["fixture generation", "server initialization", "MCP connection initialization",
                         "post-measurement checkpoint/hash verification", "real DNS/HTTPS/TLS/network latency",
                         "stdio/Tunnel/ChatGPT transport", "LLM generation/processing/token latency"],
            "mocked": ["DNS answers and pinned HTTPS connection replaced with local file response",
                       "assert_control_plane_healthy", "isolated config disables data-dir ACL hardening and Git"],
            "unmocked": ["download bounds/hash/signature checks", "Broker filesystem/CAS/transaction/checkpoint/audit"],
            "base64_scope": "MCP argument body character count; client program holds the body; neither route copies body through a model",
            "memory_scope": "client+server+file-backed response shim in one process, excluding fixtures preloaded in memory",
            "python_peak_scope": "tracemalloc allocations during measured calls beginning before input reading; includes SDK and measurement instrumentation, excludes native/untracked allocations",
            "rss_scope": "psutil current RSS sampled every 2 ms; peak/increase are observed lower bounds, not exact transient maxima",
            "lifetime_peak_scope": "Windows peak_wset includes worker initialization and is separate from measured interval RSS",
            "timing_caution": "tracemalloc/sampling/JSON instrumentation add overhead; one sample is descriptive, not a performance guarantee",
            "cache_caution": "OS disk cache is uncontrolled; workers alternate route order on repeated samples",
        },
        "fixtures": fixtures, "samples": rows, "summaries": summaries,
    }
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=1, choices=range(1, 4))
    parser.add_argument("--output", type=Path, default=REPOSITORY_ROOT / ".dev-tmp" / "attachment-reference-20261006" / "benchmark.json")
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        try:
            result = _worker(args.worker)
        except Exception as error:  # noqa: BLE001 - 入力本文を含む SDK 診断を転記しない
            diagnostic = _safe_failure(error)
            print(json.dumps({"worker_error": diagnostic}))
            return 1
        print(json.dumps(result, ensure_ascii=False))
        return 0
    report = run(args.output.resolve(), args.samples)
    print(f"report: {args.output.resolve()}")
    if not report["comparison_valid"]:
        print("comparison invalid: Python sources changed during the run; rerun after edits finish")
        return 2
    for row in report["summaries"]:
        metrics = row["medians"]
        print(f"{row['format']} {row['bytes']} bytes {row['route']}: "
              f"{metrics['local_elapsed_ms']:.3f} ms; calls={metrics['mcp_tool_calls']}; "
              f"Base64 chars={metrics['mcp_argument_base64_body_characters']}; "
              f"Python peak={metrics['python_tracemalloc_peak_bytes']} bytes; "
              f"RSS increase={metrics['rss_observed_increase_bytes']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
