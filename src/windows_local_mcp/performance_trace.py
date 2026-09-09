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
import time
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from typing import Any, Self

TIMING_SCHEMA_VERSION = 1
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
    }
)
_PHASE_KEYS = frozenset({"name", "offset_ns", "duration_ns", "status", "sequence"})


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

    schema_version = payload.get("schema_version", TIMING_SCHEMA_VERSION)
    if not _is_int(schema_version) or schema_version != TIMING_SCHEMA_VERSION:
        raise ValueError("unsupported timing schema_version")
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
        unknown_phase_fields = set(item) - _PHASE_KEYS
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

    return {
        "schema_version": TIMING_SCHEMA_VERSION,
        "total_ns": total_ns,
        "total_ms": total_ms,
        "status": status,
        "phases": phases,
        "dropped_phase_count": dropped_count,
        "failed_phase": failed_phase,
    }


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


def current_trace():
    return _ACTIVE_TRACE.get()


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
    item = None
    if len(trace._phases) < MAX_PHASES:
        item = {
            "name": name,
            "offset_ns": max(0, started - trace._start_ns),
            "duration_ns": 0,
            "status": "succeeded",
            "sequence": len(trace._phases) + 1,
        }
        trace._phases.append(item)  # Reserve at start: nested phases retain execution order.
    else:
        trace._dropped = min(MAX_DROPPED_PHASES, trace._dropped + 1)
    try:
        yield
    except BaseException as error:
        if item is not None:
            item["status"] = "failed"
        if len(trace._failures) < MAX_PHASES:
            trace._failures.setdefault(_exception_key(error), name)
        raise
    finally:
        if item is not None:
            item["duration_ns"] = max(0, time.perf_counter_ns() - started)


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
