from __future__ import annotations

import importlib
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

from .tool_safety import capture_file_identity, hold_file_identity
from .util import canonical_json, sha256_text
from .wfp_guard import GUARD_POLICY_GENERATION, GUARD_VERSION, WfpGuardError

_IDENTITY_SCHEMA_VERSION = 1
_IMPLEMENTATION_MODULES = (
    "windows_local_mcp.tool_safety",
    "windows_local_mcp.util",
    "windows_local_mcp.wfp_guard",
    "windows_local_mcp.wfp_guard_identity",
    "windows_local_mcp.wfp_guard_runtime",
    "windows_local_mcp.windows_wfp",
)


def capture_wfp_guard_implementation_identity() -> dict[str, Any]:
    """Bind the exact imported files that implement and verify the WFP Guard."""

    modules: list[dict[str, Any]] = []
    for name in _IMPLEMENTATION_MODULES:
        module = importlib.import_module(name)
        origin = getattr(getattr(module, "__spec__", None), "origin", None)
        if not origin or origin in {"built-in", "frozen"}:
            raise WfpGuardError(f"WFP Guard module has no regular-file origin: {name}")
        captured = capture_file_identity(
            Path(origin),
            provenance="imported-wfp-guard-module",
        )
        modules.append(
            {
                "name": name,
                "canonical_path": captured["path"],
                "sha256": captured["sha256"],
                "stable_file_identity": captured["stable_file_identity"],
                "size": captured["size"],
                # mtime is retained only as an auxiliary drift signal. Content and the
                # Windows handle-derived stable identity are the security anchors.
                "mtime_ns": captured["mtime_ns"],
            }
        )
    identity: dict[str, Any] = {
        "version": _IDENTITY_SCHEMA_VERSION,
        "guard_version": GUARD_VERSION,
        "policy_generation": GUARD_POLICY_GENERATION,
        "modules": modules,
    }
    identity["digest"] = sha256_text(canonical_json(identity))
    return identity


def _hold_input(module: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": module["canonical_path"],
        "sha256": module["sha256"],
        "stable_file_identity": module["stable_file_identity"],
        "size": module["size"],
        "mtime_ns": module["mtime_ns"],
        "provenance": "imported-wfp-guard-module",
    }


@contextmanager
def hold_wfp_guard_implementation(
    expected: dict[str, Any] | None = None,
) -> Iterator[dict[str, Any]]:
    """Hold every imported Guard implementation file against TOCTOU replacement."""

    captured = capture_wfp_guard_implementation_identity()
    if expected is not None and captured != expected:
        raise WfpGuardError("WFP Guard implementation identity changed after verification")
    with ExitStack() as stack:
        for module in captured["modules"]:
            stack.enter_context(hold_file_identity(_hold_input(module)))
        # Re-capture after all handles are held so a partial replacement race cannot
        # produce a mixed implementation manifest.
        verified = capture_wfp_guard_implementation_identity()
        if verified != captured:
            raise WfpGuardError("WFP Guard implementation changed while acquiring holds")
        yield verified
