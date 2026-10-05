from __future__ import annotations

import ast
import copy
import hashlib
import importlib
import inspect
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import pytest

MEASUREMENT_ROOT = Path(__file__).parents[1] / ".dev-tmp" / "artifact-20261006"
BASELINE_SERVER_PATH = MEASUREMENT_ROOT / "baseline" / "server.py"
MEASURED_SIZES = (0, 4 * 1024, 512 * 1024, 4 * 1024 * 1024)
MAX_MEASURED_SIZE = max(MEASURED_SIZES)
MEASUREMENT_REPETITIONS = 3

SOURCE_HANDLE_OBSERVATION = {
    "resolve_existing": (
        "artifact_download_begin は hold_identity=True の resolve_existing を使い、"
        "read アクセスでは final_read_data=True の _HeldPath を受け取る"
    ),
    "final_share_mode": (
        "最終ファイルハンドルは _FILE_SHARE_READ のみ（FILE_SHARE_WRITE/DELETE を共有しない）"
    ),
    "read_verified_hold": (
        "初回 source_read は copy と同じ _HeldPath._lease、source_recheck は再解決した別の _HeldPath._lease"
    ),
    "release": (
        "artifact_download_begin 内に明示的な release_verified_hold 呼出しはなく、"
        "source/current の _HeldPath は begin のローカル参照が終了した後に weakref.finalize で解放される"
    ),
}


def _load_measurement_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Any, Path]:
    """Load one isolated server with bounds that include the 4 MiB measurement case."""

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
                f"max_structured_file_bytes = {MAX_MEASURED_SIZE + 1024 * 1024}",
                "max_transfer_chunk_bytes = 524288",
                "max_open_transfers = 4",
                "max_data_dir_bytes = 134217728",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    sys.modules.pop("windows_local_mcp.server", None)
    server = importlib.import_module("windows_local_mcp.server")
    # 外部の control-plane health state は、このプロセス内比較の測定対象外とする。
    monkeypatch.setattr(server, "assert_control_plane_healthy", lambda _settings: None)
    return server, workspace


def _payload(size: int) -> bytes:
    """Return deterministic, non-sensitive bytes without relying on host randomness."""

    if size == 0:
        return b""
    pattern = bytes(range(256))
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def _path_role(path: Path, source_path: Path) -> str:
    candidate = Path(os.fspath(path))
    if candidate == source_path:
        return "workspace_source"
    if candidate.name == "payload.bin":
        return "reserved_snapshot"
    return "other"


def _extract_baseline_functions(
    server: Any,
) -> tuple[Any, dict[str, Any], dict[str, dict[str, int]]]:
    """Evaluate only the two baseline function bodies with current runtime globals.

    The baseline source is not imported as a second package. Its decorators are stripped, then
    the selected AST nodes are evaluated in a copy of the current server globals. This keeps the
    comparison inside the test file and makes both variants use the same runtime configuration,
    workspace, and audit implementation.
    """

    source = BASELINE_SERVER_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(BASELINE_SERVER_PATH))
    wanted_names = {"_copy_source_to_reserved_snapshot", "artifact_download_begin"}
    selected: dict[str, ast.FunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted_names:
            selected[node.name] = copy.deepcopy(node)
    assert set(selected) == wanted_names

    baseline_globals = dict(vars(server))
    baseline_globals["__name__"] = "windows_local_mcp.server_baseline_measurement"
    ordered_nodes: list[ast.FunctionDef] = []
    for name in ("_copy_source_to_reserved_snapshot", "artifact_download_begin"):
        node = selected[name]
        # MCP 登録は live server を変更するため、比較対象から外して本体だけ評価する。
        node.decorator_list = []
        ordered_nodes.append(node)
    module = ast.fix_missing_locations(ast.Module(body=ordered_nodes, type_ignores=[]))
    # Only the two locally captured, reviewed task-start functions are evaluated.
    exec(compile(module, str(BASELINE_SERVER_PATH), "exec"), baseline_globals)  # noqa: S102
    locations = {
        name: {"lineno": node.lineno, "end_lineno": node.end_lineno or node.lineno}
        for name, node in selected.items()
    }
    return baseline_globals["artifact_download_begin"], baseline_globals, locations


class _IoProbe:
    """Count full-file helper I/O while executing the original helper once per call."""

    def __init__(self, target_globals: dict[str, Any], source_path: Path) -> None:
        self.target_globals = target_globals
        self.source_path = source_path
        self.read_events: list[dict[str, Any]] = []
        self.hash_events: list[dict[str, Any]] = []
        self.persisted_hash_events: list[dict[str, Any]] = []
        self.copy_events: list[dict[str, Any]] = []
        self.source_read_count = 0
        self.hash_count = 0
        self.copy_source_lease_id: int | None = None
        self._originals: dict[str, Any] = {}

    def install(self) -> None:
        names = (
            "read_verified_bytes",
            "sha256_bytes",
            "sha256_file",
            "_copy_source_to_reserved_snapshot",
        )
        self._originals = {name: self.target_globals[name] for name in names}
        self.target_globals["read_verified_bytes"] = self._read
        self.target_globals["sha256_bytes"] = self._sha256_bytes
        self.target_globals["sha256_file"] = self._sha256_file
        self.target_globals["_copy_source_to_reserved_snapshot"] = self._copy

    def restore(self) -> None:
        self.target_globals.update(self._originals)

    def _read(self, path: Path, max_bytes: int) -> bytes:
        started_ns = time.perf_counter_ns()
        data = self._originals["read_verified_bytes"](path, max_bytes)
        role = _path_role(path, self.source_path)
        event: dict[str, Any] = {
            "kind": "read_verified_bytes",
            "role": role,
            "logical_read_bytes": len(data),
            "elapsed_ns": time.perf_counter_ns() - started_ns,
        }
        if role == "workspace_source":
            self.source_read_count += 1
            lease = getattr(path, "_lease", None)
            event["source_read_sequence"] = self.source_read_count
            event["same_handle_as_snapshot_copy"] = (
                self.copy_source_lease_id is not None
                and lease is not None
                and id(lease) == self.copy_source_lease_id
            )
            event["phase"] = (
                "source_read_same_handle"
                if self.source_read_count == 1
                else "source_recheck_read"
            )
        self.read_events.append(event)
        return data

    def _sha256_bytes(self, data: bytes) -> str:
        started_ns = time.perf_counter_ns()
        digest = self._originals["sha256_bytes"](data)
        self.hash_count += 1
        self.hash_events.append(
            {
                "kind": "sha256_bytes",
                "phase": "copy_source_hash" if self.hash_count == 1 else "source_recheck_hash",
                "input_bytes": len(data),
                "elapsed_ns": time.perf_counter_ns() - started_ns,
                "sha256": digest,
            }
        )
        return digest

    def _sha256_file(self, path: Path, *, max_bytes: int | None = None) -> tuple[str, int]:
        started_ns = time.perf_counter_ns()
        digest, total = self._originals["sha256_file"](path, max_bytes=max_bytes)
        self.persisted_hash_events.append(
            {
                "kind": "sha256_file",
                "phase": "persisted_snapshot_hash",
                "role": _path_role(path, self.source_path),
                "logical_read_bytes": total,
                "elapsed_ns": time.perf_counter_ns() - started_ns,
                "sha256": digest,
            }
        )
        return digest, total

    def _copy(self, source: Path, destination: Path) -> tuple[str, int]:
        lease = getattr(source, "_lease", None)
        self.copy_source_lease_id = id(lease) if lease is not None else None
        started_ns = time.perf_counter_ns()
        digest, copied_bytes = self._originals["_copy_source_to_reserved_snapshot"](
            source, destination
        )
        self.copy_events.append(
            {
                "kind": "copy_source_to_reserved_snapshot",
                "phase": "snapshot_copy",
                "source_role": _path_role(source, self.source_path),
                "destination_role": _path_role(destination, self.source_path),
                "source_bytes": copied_bytes,
                "written_bytes": copied_bytes,
                "elapsed_ns": time.perf_counter_ns() - started_ns,
                "sha256": digest,
            }
        )
        return digest, copied_bytes

    def sample(
        self,
        *,
        result: dict[str, Any],
        manifest: dict[str, Any],
        elapsed_ns: int,
        size: int,
    ) -> dict[str, Any]:
        expected_sha256 = hashlib.sha256(_payload(size)).hexdigest()
        assert result["bytes"] == size
        assert result["sha256"] == expected_sha256
        assert manifest["sha256"] == expected_sha256
        assert manifest["bytes"] == size
        assert len(self.copy_events) == 1
        assert self.copy_events[0]["sha256"] == expected_sha256
        assert self.copy_events[0]["source_bytes"] == size
        assert self.copy_events[0]["written_bytes"] == size
        assert [event["phase"] for event in self.read_events] == [
            "source_read_same_handle",
            "source_recheck_read",
        ]
        assert [event["logical_read_bytes"] for event in self.read_events] == [size, size]
        assert self.read_events[0]["same_handle_as_snapshot_copy"] is True
        assert self.read_events[1]["same_handle_as_snapshot_copy"] is False
        assert [event["phase"] for event in self.hash_events] == [
            "copy_source_hash",
            "source_recheck_hash",
        ]
        assert all(event["sha256"] == expected_sha256 for event in self.hash_events)
        assert len(self.persisted_hash_events) == 1
        assert self.persisted_hash_events[0]["role"] == "reserved_snapshot"
        assert self.persisted_hash_events[0]["sha256"] == expected_sha256
        assert self.persisted_hash_events[0]["logical_read_bytes"] == size
        total_logical_read_bytes = sum(
            event["logical_read_bytes"]
            for event in self.read_events + self.persisted_hash_events
        )
        assert total_logical_read_bytes == size * 3
        assert manifest["state"] == ("completed" if size == 0 else "open")
        return {
            "begin_elapsed_ns": elapsed_ns,
            "begin_elapsed_ms": elapsed_ns / 1_000_000,
            "total_logical_read_bytes": total_logical_read_bytes,
            "expected_logical_read_bytes": size * 3,
            "total_logical_write_bytes": self.copy_events[0]["written_bytes"],
            "result_sha256": result["sha256"],
            "expected_sha256": expected_sha256,
            "read_events": self.read_events,
            "hash_events": self.hash_events,
            "persisted_hash_events": self.persisted_hash_events,
            "copy_events": self.copy_events,
            "manifest_state": manifest["state"],
            "source_hold_observation": {
                "source_read_same_handle": self.read_events[0][
                    "same_handle_as_snapshot_copy"
                ],
                "source_recheck_same_handle": self.read_events[1][
                    "same_handle_as_snapshot_copy"
                ],
                "explicit_release_calls_during_begin": 0,
            },
        }


def _measure_variant(
    function: Any,
    target_globals: dict[str, Any],
    server: Any,
    workspace: Path,
    size: int,
) -> dict[str, Any]:
    source_path = workspace / "source.bin"
    probe = _IoProbe(target_globals, source_path)
    probe.install()
    started_ns = time.perf_counter_ns()
    try:
        result = function("source.bin", chunk_bytes=512 * 1024)
    finally:
        elapsed_ns = time.perf_counter_ns() - started_ns
        probe.restore()
    transfer_root = server.runtime.settings.data_dir / "binary-transfers" / result["transfer_id"]
    manifest = json.loads((transfer_root / "manifest.json").read_text(encoding="utf-8"))
    sample = probe.sample(result=result, manifest=manifest, elapsed_ns=elapsed_ns, size=size)
    # A non-zero begin leaves an open slot by design; cleanup happens outside the measured probe.
    if size:
        server.artifact_transfer_cancel(result["transfer_id"], reason="measurement cleanup")
    return sample


def _median(values: list[int]) -> int | float:
    return statistics.median(values)


def _summarize_variant(samples: list[dict[str, Any]], size: int) -> dict[str, Any]:
    phase_events: dict[str, list[int]] = {}
    for sample in samples:
        all_events = (
            sample["read_events"]
            + sample["hash_events"]
            + sample["persisted_hash_events"]
            + sample["copy_events"]
        )
        for event in all_events:
            phase_events.setdefault(event["phase"], []).append(event["elapsed_ns"])
    phase_medians_ns = {phase: _median(values) for phase, values in sorted(phase_events.items())}
    sha_values = {sample["result_sha256"] for sample in samples}
    expected_sha256 = hashlib.sha256(_payload(size)).hexdigest()
    return {
        "sample_count": len(samples),
        "begin_elapsed_ns_median": _median([sample["begin_elapsed_ns"] for sample in samples]),
        "begin_elapsed_ms_median": _median(
            [sample["begin_elapsed_ns"] for sample in samples]
        )
        / 1_000_000,
        "phase_medians_ns": phase_medians_ns,
        "total_logical_read_bytes": [sample["total_logical_read_bytes"] for sample in samples],
        "total_logical_read_bytes_median": _median(
            [sample["total_logical_read_bytes"] for sample in samples]
        ),
        "expected_logical_read_bytes_3N": size * 3,
        "total_logical_write_bytes": [sample["total_logical_write_bytes"] for sample in samples],
        "total_logical_write_bytes_median": _median(
            [sample["total_logical_write_bytes"] for sample in samples]
        ),
        "sha256_values": sorted(sha_values),
        "sha256_matches_expected": sha_values == {expected_sha256},
        "source_hold_observations": [sample["source_hold_observation"] for sample in samples],
    }


@pytest.mark.parametrize("size", MEASURED_SIZES, ids=lambda value: f"{value}-bytes")
def test_artifact_download_begin_baseline_current_comparison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    """Compare baseline and current begin paths under the same runtime conditions.

    Each size runs baseline then current three times. The test records performance only; it does
    not treat a latency difference as an optimization claim or remove any verification read.
    """

    if not BASELINE_SERVER_PATH.is_file():
        pytest.skip("comparison requires the captured pre-change server.py baseline")
    server, workspace = _load_measurement_server(tmp_path, monkeypatch)
    payload = _payload(size)
    source_path = workspace / "source.bin"
    source_path.write_bytes(payload)
    current_function = server.artifact_download_begin
    baseline_function, baseline_globals, baseline_locations = _extract_baseline_functions(server)
    current_line = inspect.getsourcelines(current_function)[1]

    samples: dict[str, list[dict[str, Any]]] = {"baseline": [], "current": []}
    execution_order: list[str] = []
    for _repetition in range(MEASUREMENT_REPETITIONS):
        for variant, function, target_globals in (
            ("baseline", baseline_function, baseline_globals),
            ("current", current_function, vars(server)),
        ):
            execution_order.append(variant)
            samples[variant].append(
                _measure_variant(function, target_globals, server, workspace, size)
            )

    summaries = {
        variant: _summarize_variant(variant_samples, size)
        for variant, variant_samples in samples.items()
    }
    baseline_summary = summaries["baseline"]
    current_summary = summaries["current"]
    begin_delta_ns = (
        current_summary["begin_elapsed_ns_median"]
        - baseline_summary["begin_elapsed_ns_median"]
    )
    begin_ratio = (
        current_summary["begin_elapsed_ns_median"]
        / baseline_summary["begin_elapsed_ns_median"]
        if baseline_summary["begin_elapsed_ns_median"]
        else None
    )
    logical_read_delta = (
        current_summary["total_logical_read_bytes_median"]
        - baseline_summary["total_logical_read_bytes_median"]
    )
    logical_write_delta = (
        current_summary["total_logical_write_bytes_median"]
        - baseline_summary["total_logical_write_bytes_median"]
    )
    assert all(
        summary["total_logical_read_bytes"] == [size * 3] * MEASUREMENT_REPETITIONS
        for summary in summaries.values()
    )
    assert all(summary["sha256_matches_expected"] for summary in summaries.values())
    assert baseline_summary["phase_medians_ns"].keys() == current_summary["phase_medians_ns"].keys()

    expected_sha256 = hashlib.sha256(payload).hexdigest()
    comparison = {
        "measurement": "artifact_download_begin_baseline_current_comparison",
        "date": "2026-10-06",
        "size_bytes": size,
        "repetitions_per_variant": MEASUREMENT_REPETITIONS,
        "execution_order": execution_order,
        "expected_sha256": expected_sha256,
        "baseline": baseline_summary,
        "current": current_summary,
        "delta_current_minus_baseline": {
            "begin_elapsed_ns_median": begin_delta_ns,
            "begin_elapsed_ms_median": begin_delta_ns / 1_000_000,
            "begin_elapsed_ratio": begin_ratio,
            "total_logical_read_bytes_median": logical_read_delta,
            "total_logical_write_bytes_median": logical_write_delta,
            "phase_medians_ns": {
                phase: current_summary["phase_medians_ns"][phase]
                - baseline_summary["phase_medians_ns"][phase]
                for phase in current_summary["phase_medians_ns"]
            },
        },
        "io_shape": {
            "expected_logical_read_bytes": "3N",
            "expected_logical_write_bytes": "N",
            "baseline_read_matches_3N": baseline_summary[
                "total_logical_read_bytes_median"
            ]
            == size * 3,
            "current_read_matches_3N": current_summary["total_logical_read_bytes_median"]
            == size * 3,
            "baseline_current_read_shape_equal": baseline_summary[
                "total_logical_read_bytes_median"
            ]
            == current_summary["total_logical_read_bytes_median"],
            "baseline_current_write_shape_equal": baseline_summary[
                "total_logical_write_bytes_median"
            ]
            == current_summary["total_logical_write_bytes_median"],
            "sha256_equal": baseline_summary["sha256_values"]
            == current_summary["sha256_values"]
            == [expected_sha256],
        },
        "optimization_claim": "削減なし。検証読込が変わっていないことのみを記録",
        "source_hold_observation": SOURCE_HANDLE_OBSERVATION,
        "implementation_sources": {
            "baseline_server": str(BASELINE_SERVER_PATH),
            "baseline_extracted_functions": baseline_locations,
            "current_server": str(Path(server.__file__).resolve()),
            "current_artifact_download_begin_lineno": current_line,
            "evaluation": "baseline AST function bodies evaluated with current runtime globals",
        },
        "verification_boundary": {
            "execution": "通常の Windows Python プロセス内で実ファイルを使った直接呼出し",
            "instrumentation": "各 helper を測定用にラップし、元実装を各呼出しで一度だけ実行",
            "real_paths": True,
            "security_and_lifecycle_implementation": "実装そのまま",
            "not_verified": [
                "Secure Tunnel の接続",
                "Approved Host サービスの実機経路",
                "ChatGPT MCP のネットワーク経路",
            ],
        },
        "host": {
            "os_name": os.name,
            "platform": platform.platform(),
            "python": sys.executable,
        },
        "samples": samples,
    }
    MEASUREMENT_ROOT.mkdir(parents=True, exist_ok=True)
    output_path = MEASUREMENT_ROOT / f"measurement-{size}.json"
    output_path.write_text(
        json.dumps(comparison, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
