"""測定成果物が画像を保持しつつ本文を公開しないことを実保存経路で確認する。"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from PIL import Image

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_attachment_transfer.py"


def _load_script():
    name = "attachment_transfer_benchmark_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_benchmark_uses_real_images_multichunk_mcp_and_body_free_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    benchmark = _load_script()
    # 512 KiB の境界を越す実画像で、最終端の短いチャンクも検査する。
    monkeypatch.setattr(benchmark, "TARGET_BYTES", (benchmark.CHUNK_BYTES + 64 * 1024,))
    output = tmp_path / "benchmark.json"
    report = benchmark.run(output, samples=1)
    assert json.loads(output.read_text(encoding="utf-8")) == report
    assert len(report["fixtures"]) == 2
    assert len(report["samples"]) == 4
    snapshots = report["source_snapshot"]
    assert snapshots["start_sha256_by_file"]
    assert snapshots["end_sha256_by_file"]
    assert report["comparison_valid"] == snapshots["unchanged"]
    assert snapshots["unchanged"] == (
        snapshots["start_sha256_by_file"] == snapshots["end_sha256_by_file"]
    )
    text = output.read_text(encoding="utf-8") + capsys.readouterr().out

    for fixture in report["fixtures"]:
        path = Path(fixture["path"])
        payload = path.read_bytes()
        assert len(payload) == fixture["bytes"] > benchmark.CHUNK_BYTES
        assert hashlib.sha256(payload).hexdigest() == fixture["sha256"]
        with Image.open(path) as image:
            image.load()
            assert image.format == fixture["format"]
        # 結果 JSON と stdout に画像本体の Base64 を載せていないことを検査する。
        assert base64.b64encode(payload[:256]).decode("ascii") not in text
        expected_characters = sum(
            4 * ((len(payload[offset:offset + benchmark.CHUNK_BYTES]) + 2) // 3)
            for offset in range(0, len(payload), benchmark.CHUNK_BYTES)
        )
        for row in [item for item in report["samples"] if item["fixture"]["path"] == str(path)]:
            assert row["verification"]["pre_and_post_checkpoints_verified"] is True
            assert row["verification"]["saved_sha256"] == fixture["sha256"]
            assert row["model_copied_base64_body_characters"] == 0
            assert row["local_elapsed_ms"] > 0
            assert row["python_tracemalloc_peak_bytes"] > 0
            assert row["rss_observed_peak_bytes"] >= row["rss_baseline_bytes"]
            if row["route"] == "attachment_import":
                assert row["mcp_tool_calls"] == 1
                assert row["mcp_argument_base64_body_characters"] == 0
            else:
                assert row["mcp_tool_calls"] == 4  # begin + 2 chunks + commit
                assert row["mcp_argument_base64_body_characters"] == expected_characters


def test_image_generation_is_reproducible(tmp_path: Path) -> None:
    benchmark = _load_script()
    for image_format in ("JPEG", "PNG"):
        first = benchmark.make_fixture(tmp_path / "first", image_format, 256 * 1024)
        second = benchmark.make_fixture(tmp_path / "second", image_format, 256 * 1024)
        assert first["sha256"] == second["sha256"]
        assert first["dimensions"] == second["dimensions"]
        assert abs(first["bytes"] - first["target_bytes"]) < first["target_bytes"] * 0.05
