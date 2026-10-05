# ruff: noqa: TRY004
"""Bounded, in-memory timing traces for durable Audit records.

The trace deliberately uses :func:`time.perf_counter_ns` for elapsed time.
Wall-clock timestamps in the Audit record answer *when* an operation happened;
the values in this module answer *how long* it took.  A trace is collected in
memory and written once when its operation scope finishes.  Phase durations
therefore include nested work and must not be added together to obtain the
operation duration.

This module has no event or Live Activity integration.  Low-level phase data is
diagnostic Audit data only.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from typing import Any, Self

TIMING_SCHEMA_VERSION = 2
MAX_PHASES = 128
MAX_DROPPED_PHASES = 131_072
MAX_PHASE_NAME_BYTES = 64
MAX_TIMING_JSON_BYTES = 64 * 1024
_MAX_INT64 = (1 << 63) - 1

# Phase names are intentionally a closed vocabulary.  Keeping the list here
# prevents request data from becoming an unbounded or user-controlled label.
PHASE_NAMES = frozenset(
    {
        "path_validation",
        "checkpoint_capture",
        "checkpoint_verification",
        "transaction_prepare",
        "transaction_open",
        "transaction_finish",
        "rollback_finalization",
        "operation_body",
        "request_validation",
        "validation",
        "workspace_validation",
        "workspace_path_validation",
        "identity_validation",
        "optimistic_concurrency_validation",
        "source_open",
        "open",
        "source_read",
        "read",
        "source_hash",
        "source_sha256",
        "hash_validation",
        "after_hash",
        "after_sha256",
        "checkpoint_before",
        "checkpoint_after",
        "manifest_before",
        "manifest_after",
        "transform",
        "structured_processing",
        "structured_transform",
        "output_encoding",
        "staging",
        "temporary_output",
        "cas_recheck",
        "transactional_commit",
        "atomic_replacement",
        "post_write_verification",
        "diff_generation",
        "rollback",
        "rollback_recovery",
        "rollback_metadata_finalization",
        "decode_parse",
        "result_serialization",
        "audit_result_persistence",
        "operation_finalization",
        "workspace_lock_wait",
        "control_plane_lock_wait",
        "data_directory_scan",
        "quota_validation",
        "artifact_pruning",
        "checkpoint_hash",
        "checkpoint_blob_store",
        "checkpoint_blob_verify",
        "checkpoint_manifest_load",
        "checkpoint_manifest_write",
        "checkpoint_scan",
        "journal_write",
        "audit_lock_wait",
        "audit_connect",
        "audit_capacity_check",
        "audit_payload_encoding",
        "audit_sql_execute",
        "audit_commit",
        "audit_rollback",
        "control_plane_health_check",
        "backup_write",
        "attachment_fetch",
        "artifact_encoding",
        "artifact_decoding",
    }
)

_PHASE_STATUSES = frozenset({"succeeded", "failed"})
_TRACE_STATUSES = frozenset({"succeeded", "failed"})
_TRACE_KEYS = frozenset(
    {
        "schema_version",
        "total_ns",
        "total_ms",
        "status",
        "phases",
        "dropped_phase_count",
        "failed_phase",
        "phase_summary",
        "uninstrumented_ns",
    }
)
_PHASE_KEYS = frozenset({"name", "offset_ns", "duration_ns", "status", "sequence"})
_DETAIL_KEYS = frozenset({"parent_sequence", "self_ns"})
_SUMMARY_KEYS = frozenset(
    {"name", "count", "failed_count", "total_ns", "self_ns", "min_ns", "max_ns"}
)


def _is_int(value: object) -> bool:
    """Return whether *value* is an integer, excluding ``bool``."""

    return isinstance(value, int) and not isinstance(value, bool)


def _require_uint(value: object, field: str) -> int:
    if not _is_int(value) or int(value) < 0 or int(value) > _MAX_INT64:
        raise ValueError(f"timing {field} must be a non-negative integer")
    return int(value)


def validate_phase_name(name: str) -> str:
    """Validate and return a closed-vocabulary phase name."""

    if not isinstance(name, str) or name not in PHASE_NAMES:
        raise ValueError(f"unknown timing phase: {name!r}")
    if len(name.encode("utf-8")) > MAX_PHASE_NAME_BYTES:
        raise ValueError("timing phase name is too long")
    return name


def validate_timing_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize the persisted timing schema.

    This function is used both before writing a trace and when reading an
    existing database row.  It rejects unknown fields, invalid numbers,
    non-closed phase names, phase overflow, and more than ``MAX_PHASES``
    entries.  Returning a fresh dictionary prevents callers from mutating the
    object after it has been validated.
    """

    if not isinstance(payload, Mapping):
        raise ValueError("timing payload must be an object")
    unknown = set(payload) - _TRACE_KEYS
    if unknown:
        raise ValueError(f"unknown timing fields: {sorted(unknown)!r}")

    # 旧 API の version 省略値は v1 のまま保つ。
    schema_version = payload.get("schema_version", 1)
    if not _is_int(schema_version) or schema_version not in (1, TIMING_SCHEMA_VERSION):
        raise ValueError("unsupported timing schema_version")
    if schema_version == 1 and ({"phase_summary", "uninstrumented_ns"} & set(payload)):
        raise ValueError("v1 timing cannot contain v2 fields")
    total_ns = _require_uint(payload.get("total_ns"), "total_ns")

    total_ms_value = payload.get("total_ms", total_ns / 1_000_000)
    if isinstance(total_ms_value, bool) or not isinstance(total_ms_value, (int, float)):
        raise ValueError("timing total_ms must be a finite number")
    total_ms = float(total_ms_value)
    if not math.isfinite(total_ms) or total_ms < 0:
        raise ValueError("timing total_ms must be a finite non-negative number")
    expected_ms = total_ns / 1_000_000
    if abs(total_ms - expected_ms) > max(1e-6, expected_ms * 1e-9):
        raise ValueError("timing total_ms does not match total_ns")

    status = payload.get("status", "succeeded")
    if not isinstance(status, str) or status not in _TRACE_STATUSES:
        raise ValueError("timing status is invalid")

    phases_value = payload.get("phases", [])
    if not isinstance(phases_value, list):
        raise ValueError("timing phases must be an array")
    if len(phases_value) > MAX_PHASES:
        raise ValueError("timing phase count exceeds limit")

    phases: list[dict[str, Any]] = []
    previous_offset = -1
    first_failed: str | None = None
    for position, item in enumerate(phases_value, start=1):
        if not isinstance(item, Mapping):
            raise ValueError("timing phase must be an object")
        allowed_phase_keys = _PHASE_KEYS | _DETAIL_KEYS if schema_version == 2 else _PHASE_KEYS
        unknown_phase_fields = set(item) - allowed_phase_keys
        if unknown_phase_fields:
            raise ValueError(f"unknown timing phase fields: {sorted(unknown_phase_fields)!r}")
        name = validate_phase_name(item.get("name"))
        offset_ns = _require_uint(item.get("offset_ns"), "phase offset_ns")
        duration_ns = _require_uint(item.get("duration_ns"), "phase duration_ns")
        if offset_ns < previous_offset:
            raise ValueError("timing phases must be in start order")
        if offset_ns + duration_ns > total_ns:
            raise ValueError("timing phase exceeds total duration")
        phase_status = item.get("status")
        if not isinstance(phase_status, str) or phase_status not in _PHASE_STATUSES:
            raise ValueError("timing phase status is invalid")
        sequence = item.get("sequence", position)
        if not _is_int(sequence) or sequence != position:
            raise ValueError("timing phase sequence is invalid")
        normalized_phase = {
            "name": name,
            "offset_ns": offset_ns,
            "duration_ns": duration_ns,
            "status": phase_status,
            "sequence": position,
        }
        if schema_version == 2:
            self_ns = _require_uint(item.get("self_ns"), "phase self_ns")
            if self_ns > duration_ns:
                raise ValueError("timing self duration exceeds inclusive duration")
            parent = item.get("parent_sequence")
            if parent is not None:
                if not _is_int(parent) or not 1 <= parent < position:
                    raise ValueError("timing parent sequence is invalid")
                parent_item = phases[parent - 1]
                if (
                    offset_ns < parent_item["offset_ns"]
                    or offset_ns + duration_ns
                    > parent_item["offset_ns"] + parent_item["duration_ns"]
                ):
                    raise ValueError("timing child exceeds parent duration")
            normalized_phase.update(parent_sequence=parent, self_ns=self_ns)
        phases.append(normalized_phase)
        previous_offset = offset_ns
        if phase_status == "failed" and first_failed is None:
            first_failed = name

    dropped = payload.get("dropped_phase_count", 0)
    dropped_count = _require_uint(dropped, "dropped_phase_count")
    if dropped_count > MAX_DROPPED_PHASES:
        raise ValueError("timing dropped phase count exceeds limit")
    failed_phase = payload.get("failed_phase")
    if failed_phase is not None:
        failed_phase = validate_phase_name(failed_phase)
    failed_names = {p["name"] for p in phases if p["status"] == "failed"}
    if failed_phase is not None and failed_phase not in failed_names and not dropped_count:
        raise ValueError("timing failed_phase does not match phase status")

    result = {
        "schema_version": schema_version,
        "total_ns": total_ns,
        "total_ms": total_ms,
        "status": status,
        "phases": phases,
        "dropped_phase_count": dropped_count,
        "failed_phase": failed_phase,
    }
    if schema_version == 2:
        # 保存前の検証も段階数に比例させ、細分化による二重走査を避ける。
        details_by_name: dict[str, list[dict[str, Any]]] = {}
        child_totals: dict[int, int] = {}
        for item in phases:
            details_by_name.setdefault(item["name"], []).append(item)
            parent_sequence = item["parent_sequence"]
            if parent_sequence is not None:
                child_totals[parent_sequence] = (
                    child_totals.get(parent_sequence, 0) + item["duration_ns"]
                )
        summaries = payload.get("phase_summary")
        if not isinstance(summaries, list) or len(summaries) > len(PHASE_NAMES):
            raise ValueError("timing phase_summary must be a bounded array")
        normalized_summaries = []
        seen = set()
        for entry in summaries:
            if not isinstance(entry, Mapping) or set(entry) != _SUMMARY_KEYS:
                raise ValueError("timing phase summary fields are invalid")
            name = validate_phase_name(entry.get("name"))
            if name in seen:
                raise ValueError("timing phase summary names must be unique")
            seen.add(name)
            summary = {"name": name}
            for key in _SUMMARY_KEYS - {"name"}:
                summary[key] = _require_uint(entry[key], "summary " + key)
            count = summary["count"]
            if (
                not count
                or summary["failed_count"] > count
                or summary["self_ns"] > summary["total_ns"]
                or summary["min_ns"] > summary["max_ns"]
                or summary["max_ns"] > total_ns
                or not summary["min_ns"] * count <= summary["total_ns"] <= summary["max_ns"] * count
            ):
                raise ValueError("timing phase summary values are inconsistent")
            detail = details_by_name.get(name, [])
            if (
                len(detail) > count
                or sum(p["status"] == "failed" for p in detail) > summary["failed_count"]
                or sum(p["duration_ns"] for p in detail) > summary["total_ns"]
                or sum(p["self_ns"] for p in detail) > summary["self_ns"]
            ):
                raise ValueError("timing phase summary omits retained detail")
            normalized_summaries.append(summary)
        if any(p["name"] not in seen for p in phases):
            raise ValueError("timing phase summary is missing a phase")
        total_count = sum(s["count"] for s in normalized_summaries)
        actual_dropped = total_count - len(phases)
        if min(MAX_DROPPED_PHASES, actual_dropped) != dropped_count:
            raise ValueError("timing phase summary count does not match dropped details")
        for item in phases:
            child_ns = child_totals.get(item["sequence"], 0)
            available_self_ns = item["duration_ns"] - child_ns
            if item["self_ns"] > available_self_ns or (
                not actual_dropped and item["self_ns"] != available_self_ns
            ):
                raise ValueError("timing self duration does not match child phases")
        if not actual_dropped:
            # 全明細が残る場合は、集計だけを改変した保存データも拒否する。
            for summary in normalized_summaries:
                detail = details_by_name[summary["name"]]
                expected = {
                    "name": summary["name"], "count": len(detail),
                    "failed_count": sum(p["status"] == "failed" for p in detail),
                    "total_ns": sum(p["duration_ns"] for p in detail),
                    "self_ns": sum(p["self_ns"] for p in detail),
                    "min_ns": min(p["duration_ns"] for p in detail),
                    "max_ns": max(p["duration_ns"] for p in detail),
                }
                if summary != expected:
                    raise ValueError("timing phase summary does not match complete detail")
        uninstrumented_ns = _require_uint(payload.get("uninstrumented_ns"), "uninstrumented_ns")
        if uninstrumented_ns > total_ns:
            raise ValueError("timing uninstrumented duration exceeds total")
        if sum(s["self_ns"] for s in normalized_summaries) + uninstrumented_ns != total_ns:
            raise ValueError("timing self durations do not partition operation time")
        result.update(phase_summary=normalized_summaries, uninstrumented_ns=uninstrumented_ns)
    return result


def encode_timing_payload(payload: Mapping[str, Any]) -> str:
    """Validate and serialize a timing payload with a bounded JSON size."""

    normalized = validate_timing_payload(payload)
    serialized = json.dumps(
        normalized,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized.encode("utf-8")) > MAX_TIMING_JSON_BYTES:
        raise ValueError("timing payload exceeds max size")
    return serialized


def decode_timing_payload(value: str) -> dict[str, Any]:
    """Decode and strictly validate a timing JSON value from SQLite."""

    if not isinstance(value, str):
        raise ValueError("timing_json must be a string")
    if len(value.encode("utf-8")) > MAX_TIMING_JSON_BYTES:
        raise ValueError("timing payload exceeds max size")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as error:
        raise ValueError("timing_json is not valid JSON") from error
    if not isinstance(parsed, Mapping):
        raise ValueError("timing_json must contain an object")
    return validate_timing_payload(parsed)


def _exception_key(error):
    """Correlate propagation without retaining traceback frames or file handles."""
    traceback = error.__traceback__
    while traceback is not None and traceback.tb_next is not None:
        traceback = traceback.tb_next
    return id(error), id(traceback)


class OperationTrace:
    """One bounded invocation; nested tools share this collector through ContextVar."""

    def __init__(self, *, audit=None, operation_id=None):
        self._bindings = []
        if audit is not None and operation_id is not None:
            self.bind(operation_id, audit)
        self._phases = []
        self._summary = {}
        self._root_duration_ns = 0
        self._owner_thread = None
        self._failures = {}
        self._dropped = 0
        self._start_ns = 0
        self._payload = None
        self.persistence_error = None

    def bind(self, operation_id, audit):
        # Existing mutation failure paths may also create a rejection row.
        binding = (audit, operation_id)
        if binding not in self._bindings and len(self._bindings) < 8:
            self._bindings.append(binding)

    def __enter__(self) -> Self:
        self._start_ns = time.perf_counter_ns()
        self._owner_thread = threading.get_ident()
        self._token = _ACTIVE_TRACE.set(self)
        return self

    def __exit__(self, exc_type, exc, traceback):
        try:
            failed_phase = None
            current = exc
            for _ in range(16):
                if current is None:
                    break
                failed_phase = self._failures.get(_exception_key(current), failed_phase)
                current = current.__cause__ or current.__context__
            total_ns = max(0, time.perf_counter_ns() - self._start_ns)
            self._payload = {
                "schema_version": TIMING_SCHEMA_VERSION,
                "total_ns": total_ns,
                "total_ms": total_ns / 1_000_000,
                "status": "failed" if exc_type else "succeeded",
                "phases": self._phases,
                "dropped_phase_count": self._dropped,
                "failed_phase": failed_phase,
                "phase_summary": [self._summary[name] for name in sorted(self._summary)],
                "uninstrumented_ns": max(0, total_ns - self._root_duration_ns),
            }
            encoded = encode_timing_payload(self._payload)
            # Do not time diagnostic persistence recursively, or publish lifecycle events.
            _ACTIVE_TRACE.reset(self._token)
            self._token = None
            for audit, operation_id in self._bindings:
                try:
                    audit.persist_timings(
                        operation_id, timing_json=encoded, duration_ms=total_ns // 1_000_000
                    )
                except Exception as error:  # noqa: BLE001 - diagnostic write only
                    self.persistence_error = type(error).__name__
        except Exception as error:  # noqa: BLE001 - preserve original operation result
            self.persistence_error = type(error).__name__
        finally:
            self._failures.clear()
            if self._token is not None:
                _ACTIVE_TRACE.reset(self._token)
        return False

    def to_payload(self):
        return validate_timing_payload(self._payload)


_ACTIVE_TRACE: ContextVar[OperationTrace | None] = ContextVar(
    "audit_performance_trace", default=None
)
_ACTIVE_PHASE: ContextVar[dict | None] = ContextVar("audit_performance_phase", default=None)


def current_trace():
    trace = _ACTIVE_TRACE.get()
    # 同期呼び出しの区間を別 thread の作業へ混ぜない。転送先は独自の trace を作る。
    if trace is not None and trace._owner_thread != threading.get_ident():
        return None
    return trace


def operation_trace(*, audit=None, operation_id=None):
    return OperationTrace(audit=audit, operation_id=operation_id)


@contextmanager
def phase(name):
    validate_phase_name(name)
    trace = current_trace()
    if trace is None:
        yield
        return
    started = time.perf_counter_ns()
    parent = _ACTIVE_PHASE.get()
    if parent is not None and parent["trace"] is not trace:
        parent = None
    item = None
    if len(trace._phases) < MAX_PHASES:
        item = {
            "name": name,
            "offset_ns": max(0, started - trace._start_ns),
            "duration_ns": 0,
            "status": "succeeded",
            "sequence": len(trace._phases) + 1,
            "parent_sequence": parent["sequence"] if parent is not None else None,
            "self_ns": 0,
        }
        trace._phases.append(item)  # Reserve at start: nested phases retain execution order.
    else:
        trace._dropped = min(MAX_DROPPED_PHASES, trace._dropped + 1)
    # 終了済みの子を保持せず、直接の子の時間だけを集計する。
    frame = {"trace": trace, "sequence": item["sequence"] if item else None, "child_ns": 0}
    token = _ACTIVE_PHASE.set(frame)
    failed = False
    try:
        yield
    except BaseException as error:
        failed = True
        if item is not None:
            item["status"] = "failed"
        if len(trace._failures) < MAX_PHASES:
            trace._failures.setdefault(_exception_key(error), name)
        raise
    finally:
        duration_ns = max(0, time.perf_counter_ns() - started)
        self_ns = max(0, duration_ns - frame["child_ns"])
        _ACTIVE_PHASE.reset(token)
        if parent is None:
            trace._root_duration_ns += duration_ns
        else:
            parent["child_ns"] += duration_ns
        if item is not None:
            item["duration_ns"] = duration_ns
            item["self_ns"] = self_ns
        summary = trace._summary.setdefault(name, {
            "name": name, "count": 0, "failed_count": 0,
            "total_ns": 0, "self_ns": 0, "min_ns": duration_ns, "max_ns": duration_ns,
        })
        summary["count"] += 1
        summary["failed_count"] += int(failed)
        summary["total_ns"] += duration_ns
        summary["self_ns"] += self_ns
        summary["min_ns"] = min(summary["min_ns"], duration_ns)
        summary["max_ns"] = max(summary["max_ns"], duration_ns)


def traced_operation(function):
    """Instrument synchronous Broker calls, preserving their public signatures."""

    @wraps(function)
    def wrapped(*args, **kwargs):
        if current_trace() is not None:
            return function(*args, **kwargs)
        with operation_trace(), phase("operation_body"):
            return function(*args, **kwargs)

    return wrapped


def timed_phase(name):
    validate_phase_name(name)

    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if current_trace() is None:
                return function(*args, **kwargs)
            with phase(name):
                return function(*args, **kwargs)

        return wrapped

    return decorate
