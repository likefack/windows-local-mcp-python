#!/usr/bin/env python
"""Compare legacy model-orchestrated workflows with deterministic Broker tools.

This benchmark calls the Python MCP tool entry points in-process.  It does not
measure MCP transport latency, model reasoning time, user confirmation time, or
a live ChatGPT/Windows host round trip.  Payload sizes are compact UTF-8 JSON
representations of tool arguments and results, rather than captured wire bytes.
Only synthetic fixture content is used.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sqlite3
import statistics
import sys
import time
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

BATCH_CONTENT = "synthetic deterministic payload\n"
REPLACE_OLD = "synthetic_old_marker()"
REPLACE_NEW = "synthetic_new_marker()"
REPLACE_FILE_COUNT = 4


@dataclass
class WorkflowMetrics:
    workflow: str
    sample: int
    mcp_tool_calls: int
    input_json_characters: int
    input_json_utf8_bytes: int
    output_json_characters: int
    output_json_utf8_bytes: int
    raw_hash_state_copied_characters: int
    opaque_plan_state_copied_characters: int
    local_elapsed_ms: float
    audit_total_ns_sum: int
    audit_event_count: int
    audit_sqlite_connections: int
    audit_sql_write_statements: int
    sqlite_transaction_statements: int
    sqlite_write_statement_types: dict[str, int]
    operation_ids: list[str]
    final_state: dict[str, dict[str, Any]]


class WorkflowRecorder:
    """Measure local tool calls and bounded Audit SQLite activity."""

    def __init__(self, server: Any, workflow: str, sample: int) -> None:
        self.server = server
        self.workflow = workflow
        self.sample = sample
        self.calls = 0
        self.input_characters = 0
        self.input_bytes = 0
        self.output_characters = 0
        self.output_bytes = 0
        self.operation_ids: list[str] = []
        self.connection_count = 0
        self.statement_types: Counter[str] = Counter()
        self.transaction_statements = 0
        self._original_connect: Callable[[], sqlite3.Connection] | None = None

    @staticmethod
    def _json_size(value: Any) -> tuple[int, int]:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return len(encoded), len(encoded.encode("utf-8"))

    def _trace_statement(self, statement: str) -> None:
        command = statement.lstrip().split(None, 1)[0].upper() if statement.strip() else ""
        if command in {"INSERT", "UPDATE", "DELETE", "REPLACE"}:
            self.statement_types[command] += 1
        elif command in {"BEGIN", "COMMIT", "ROLLBACK"}:
            self.transaction_statements += 1

    def start_sql_trace(self) -> None:
        audit = self.server.runtime.audit
        original = audit._connect
        self._original_connect = original

        def traced_connect() -> sqlite3.Connection:
            connection = original()
            self.connection_count += 1
            connection.set_trace_callback(self._trace_statement)
            return connection

        # Each Audit operation opens short-lived connections, so instrument the
        # connection factory rather than relying on one persistent connection.
        audit._connect = traced_connect

    def stop_sql_trace(self) -> None:
        if self._original_connect is not None:
            self.server.runtime.audit._connect = self._original_connect
            self._original_connect = None

    def invoke(self, tool_name: str, **arguments: Any) -> dict[str, Any]:
        request = {"tool": tool_name, "arguments": arguments}
        characters, byte_count = self._json_size(request)
        self.input_characters += characters
        self.input_bytes += byte_count
        self.calls += 1

        result = getattr(self.server, tool_name)(**arguments)
        if not isinstance(result, dict):
            raise TypeError(f"{tool_name} returned a non-object result")
        characters, byte_count = self._json_size(result)
        self.output_characters += characters
        self.output_bytes += byte_count
        operation_id = result.get("operation_id")
        if isinstance(operation_id, str):
            self.operation_ids.append(operation_id)
        return result

    def finish(
        self,
        *,
        elapsed_ns: int,
        raw_hash_characters: int,
        opaque_plan_characters: int,
        final_state: dict[str, dict[str, Any]],
    ) -> WorkflowMetrics:
        audit_total_ns = 0
        event_count = 0
        for operation_id in self.operation_ids:
            operation = self.server.runtime.audit.get_operation(operation_id)
            event_count += len(operation["events"])
            timings = operation.get("timings")
            if not isinstance(timings, dict) or not isinstance(timings.get("total_ns"), int):
                raise RuntimeError(  # noqa: TRY004 - missing diagnostics is a runtime failure
                    f"missing Audit timings for operation {operation_id}"
                )
            audit_total_ns += int(timings["total_ns"])
        return WorkflowMetrics(
            workflow=self.workflow,
            sample=self.sample,
            mcp_tool_calls=self.calls,
            input_json_characters=self.input_characters,
            input_json_utf8_bytes=self.input_bytes,
            output_json_characters=self.output_characters,
            output_json_utf8_bytes=self.output_bytes,
            raw_hash_state_copied_characters=raw_hash_characters,
            opaque_plan_state_copied_characters=opaque_plan_characters,
            local_elapsed_ms=elapsed_ns / 1_000_000,
            audit_total_ns_sum=audit_total_ns,
            audit_event_count=event_count,
            audit_sqlite_connections=self.connection_count,
            audit_sql_write_statements=sum(self.statement_types.values()),
            sqlite_transaction_statements=self.transaction_statements,
            sqlite_write_statement_types=dict(sorted(self.statement_types.items())),
            operation_ids=list(self.operation_ids),
            final_state=final_state,
        )


def _toml_path(path: Path) -> str:
    return str(path).replace("\\", "\\\\")


def _load_server(sample_root: Path) -> tuple[Any, Path]:
    workspace = sample_root / "workspace"
    workspace.mkdir(parents=True)
    data_dir = sample_root / "data"
    config = sample_root / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{_toml_path(workspace)}"',
                f'data_dir = "{_toml_path(data_dir)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "approved_host_enabled = false",
                "max_text_file_bytes = 16384",
                "max_write_bytes = 16384",
                "max_backup_bytes = 65536",
                "max_high_level_total_bytes = 131072",
                "approval_manifest_max_bytes = 262144",
                "approval_manifest_max_files = 64",
            ]
        ),
        encoding="utf-8",
    )
    os.environ["LOCAL_MCP_CONFIG"] = str(config)
    os.environ.pop("LOCAL_MCP_ROOT", None)
    sys.modules.pop("windows_local_mcp.server", None)
    server = importlib.import_module("windows_local_mcp.server")
    server.assert_control_plane_healthy = lambda _settings: None
    required = {"workspace_batch", "workspace_replace", "workspace_plan_apply"}
    missing = sorted(name for name in required if not hasattr(server, name))
    if missing:
        raise RuntimeError(f"new deterministic tools are unavailable: {', '.join(missing)}")
    return server, workspace


def _workspace_state(workspace: Path) -> dict[str, dict[str, Any]]:
    from windows_local_mcp.util import sha256_bytes

    state: dict[str, dict[str, Any]] = {}
    for path in sorted(workspace.rglob("*"), key=lambda item: item.as_posix().casefold()):
        relative = path.relative_to(workspace).as_posix()
        if path.is_dir():
            state[relative] = {"kind": "directory"}
        elif path.is_file():
            payload = path.read_bytes()
            state[relative] = {
                "kind": "file",
                "bytes": len(payload),
                "sha256": sha256_bytes(payload),
            }
        else:
            raise RuntimeError(f"unexpected fixture entry: {relative}")
    return state


def _measure(
    server: Any,
    workspace: Path,
    workflow: str,
    sample: int,
    execute: Callable[[WorkflowRecorder], tuple[int, int]],
) -> WorkflowMetrics:
    recorder = WorkflowRecorder(server, workflow, sample)
    recorder.start_sql_trace()
    started = time.perf_counter_ns()
    try:
        raw_hash_characters, opaque_plan_characters = execute(recorder)
    finally:
        elapsed = time.perf_counter_ns() - started
        recorder.stop_sql_trace()
    return recorder.finish(
        elapsed_ns=elapsed,
        raw_hash_characters=raw_hash_characters,
        opaque_plan_characters=opaque_plan_characters,
        final_state=_workspace_state(workspace),
    )


def _legacy_batch_workflow(recorder: WorkflowRecorder) -> tuple[int, int]:
    recorder.invoke("make_directory", path="flow", parents=False, reason="synthetic benchmark")
    created = recorder.invoke(
        "write_file",
        path="flow/source.txt",
        content=BATCH_CONTENT,
        expected_sha256=None,
        reason="synthetic benchmark",
    )
    inspected = recorder.invoke("read_file", path="obsolete.txt")
    source_digest = str(created["after_sha256"])
    obsolete_digest = str(inspected["sha256"])
    recorder.invoke(
        "move_file",
        source_path="flow/source.txt",
        destination_path="flow/moved.txt",
        expected_source_sha256=source_digest,
        reason="synthetic benchmark",
    )
    recorder.invoke(
        "delete_file",
        path="obsolete.txt",
        expected_sha256=obsolete_digest,
        reason="synthetic benchmark",
    )
    return len(source_digest) + len(obsolete_digest), 0


def _deterministic_batch_workflow(recorder: WorkflowRecorder) -> tuple[int, int]:
    recorder.invoke(
        "workspace_batch",
        operations=[
            {"op": "mkdir", "path": "flow"},
            {"op": "create", "path": "flow/source.txt", "content": BATCH_CONTENT},
            {"op": "move", "source": "flow/source.txt", "destination": "flow/moved.txt"},
            {"op": "delete", "path": "obsolete.txt"},
        ],
        preview=False,
        reason="synthetic benchmark",
    )
    return 0, 0


def _prepare_batch_fixture(workspace: Path) -> None:
    (workspace / "obsolete.txt").write_bytes(BATCH_CONTENT.encode("utf-8"))


def _prepare_replace_fixture(workspace: Path) -> None:
    for index in range(REPLACE_FILE_COUNT):
        (workspace / f"replace-{index}.txt").write_text(
            f"file {index}: {REPLACE_OLD}\n",
            encoding="utf-8",
        )


def _legacy_replace_workflow(recorder: WorkflowRecorder) -> tuple[int, int]:
    searched = recorder.invoke(
        "workspace_search",
        path=".",
        query=REPLACE_OLD,
        file_glob="*.txt",
        case_sensitive=True,
        max_depth=2,
        max_entries=32,
        max_files=16,
        max_results=16,
        max_total_bytes=65536,
    )
    paths = sorted({str(match["path"]) for match in searched["matches"]})
    if len(paths) != REPLACE_FILE_COUNT:
        raise RuntimeError("legacy search did not select the expected synthetic files")
    read = recorder.invoke(
        "read_files",
        paths=paths,
        max_files=16,
        max_total_bytes=65536,
        start_line=None,
        end_line=None,
    )
    edits = [
        {
            "path": item["path"],
            "expected_sha256": item["sha256"],
            "replacements": [{"old_text": REPLACE_OLD, "new_text": REPLACE_NEW}],
        }
        for item in read["files"]
    ]
    recorder.invoke("workspace_apply", edits=edits, reason="synthetic benchmark")
    return sum(len(str(item["expected_sha256"])) for item in edits), 0


def _deterministic_replace_workflow(recorder: WorkflowRecorder) -> tuple[int, int]:
    recorder.invoke(
        "workspace_replace",
        path=".",
        old_text=REPLACE_OLD,
        new_text=REPLACE_NEW,
        expected_total_matches=REPLACE_FILE_COUNT,
        file_glob="*.txt",
        case_sensitive=True,
        match_mode="unique_per_file",
        preview=False,
        reason="synthetic benchmark",
        max_depth=2,
        max_entries=32,
        max_files=16,
        max_total_bytes=65536,
        max_matches=16,
        max_changed_files=16,
    )
    return 0, 0


def _verify_replaced_state(state: dict[str, dict[str, Any]], workspace: Path) -> None:
    if len([item for item in state.values() if item["kind"] == "file"]) != REPLACE_FILE_COUNT:
        raise RuntimeError("replace workflow produced an unexpected file count")
    for index in range(REPLACE_FILE_COUNT):
        text = (workspace / f"replace-{index}.txt").read_text(encoding="utf-8")
        if REPLACE_OLD in text or text.count(REPLACE_NEW) != 1:
            raise RuntimeError("replace workflow result verification failed")


def _median_summary(samples: list[WorkflowMetrics]) -> dict[str, Any]:
    fields = (
        "mcp_tool_calls",
        "input_json_characters",
        "input_json_utf8_bytes",
        "output_json_characters",
        "output_json_utf8_bytes",
        "raw_hash_state_copied_characters",
        "opaque_plan_state_copied_characters",
        "local_elapsed_ms",
        "audit_total_ns_sum",
        "audit_event_count",
        "audit_sqlite_connections",
        "audit_sql_write_statements",
        "sqlite_transaction_statements",
    )
    return {
        field: statistics.median(float(getattr(sample, field)) for sample in samples)
        for field in fields
    }


def _comparison(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    compared: dict[str, Any] = {}
    for key, value in old.items():
        old_value = float(value)
        new_value = float(new[key])
        compared[key] = {
            "legacy_median": old_value,
            "deterministic_median": new_value,
            "absolute_change": new_value - old_value,
            "reduction_percent": None
            if old_value == 0
            else (old_value - new_value) / old_value * 100,
        }
    return compared


def run(output_root: Path, sample_count: int) -> Path:
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    run_root = output_root / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    collected: list[WorkflowMetrics] = []

    for sample in range(1, sample_count + 1):
        batch_results: dict[str, WorkflowMetrics] = {}
        for name, executor in (
            ("legacy_batch", _legacy_batch_workflow),
            ("deterministic_batch", _deterministic_batch_workflow),
        ):
            server, workspace = _load_server(run_root / f"sample-{sample}" / name)
            _prepare_batch_fixture(workspace)
            result = _measure(server, workspace, name, sample, executor)
            batch_results[name] = result
            collected.append(result)
        if batch_results["legacy_batch"].final_state != batch_results["deterministic_batch"].final_state:
            raise RuntimeError("batch workflow final states differ")

        replace_results: dict[str, tuple[WorkflowMetrics, Path]] = {}
        for name, executor in (
            ("legacy_replace", _legacy_replace_workflow),
            ("deterministic_replace", _deterministic_replace_workflow),
        ):
            server, workspace = _load_server(run_root / f"sample-{sample}" / name)
            _prepare_replace_fixture(workspace)
            result = _measure(server, workspace, name, sample, executor)
            _verify_replaced_state(result.final_state, workspace)
            replace_results[name] = (result, workspace)
            collected.append(result)
        if replace_results["legacy_replace"][0].final_state != replace_results["deterministic_replace"][0].final_state:
            raise RuntimeError("replace workflow final states differ")

    by_workflow = {
        name: [item for item in collected if item.workflow == name]
        for name in (
            "legacy_batch",
            "deterministic_batch",
            "legacy_replace",
            "deterministic_replace",
        )
    }
    medians = {name: _median_summary(items) for name, items in by_workflow.items()}
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "samples_per_workflow": sample_count,
        "measurement_scope": {
            "entry_point": "direct in-process Python calls to MCP tool functions",
            "includes": [
                "tool implementation elapsed time",
                "compact JSON argument/result size estimates",
                "Audit timings.total_ns per returned operation_id",
                "Audit event rows and SQLite write trace during measured calls",
            ],
            "excludes": [
                "MCP transport",
                "LLM reasoning or token latency",
                "ChatGPT confirmation UI",
                "normal Windows host end-to-end latency",
                "fixture creation and result diagnostics",
            ],
            "fixture": "bounded synthetic UTF-8 content without secrets",
            "sqlite_scope": "AuditStore connections only; file journal I/O is not a SQLite write",
        },
        "equivalence_checks": {
            "batch_final_workspace_state": "identical for every sample",
            "replace_final_workspace_state": "identical for every sample",
        },
        "samples": [asdict(item) for item in collected],
        "medians": medians,
        "comparisons": {
            "batch": _comparison(medians["legacy_batch"], medians["deterministic_batch"]),
            "replace": _comparison(medians["legacy_replace"], medians["deterministic_replace"]),
        },
    }
    output = run_root / "report.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--samples",
        type=int,
        default=3,
        choices=range(1, 11),
        metavar="1..10",
        help="bounded samples per workflow (default: 3)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPOSITORY_ROOT / ".dev-tmp" / "deterministic-benchmark",
        help="directory for synthetic fixtures and report.json",
    )
    arguments = parser.parse_args()
    report = run(arguments.output_dir.resolve(), arguments.samples)
    parsed = json.loads(report.read_text(encoding="utf-8"))
    print(f"report: {report}")
    print("scope: local in-process MCP tool entry points; transport and LLM time are not measured")
    for comparison_name, workflows in (
        ("batch", ("legacy_batch", "deterministic_batch")),
        ("replace", ("legacy_replace", "deterministic_replace")),
    ):
        old, new = (parsed["medians"][name] for name in workflows)
        print(
            f"{comparison_name}: calls {old['mcp_tool_calls']:g} -> {new['mcp_tool_calls']:g}; "
            f"elapsed median {old['local_elapsed_ms']:.3f} -> {new['local_elapsed_ms']:.3f} ms; "
            f"raw hash copied {old['raw_hash_state_copied_characters']:g} -> "
            f"{new['raw_hash_state_copied_characters']:g} chars"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
