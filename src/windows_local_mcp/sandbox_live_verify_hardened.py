from __future__ import annotations

import shutil
import uuid
from typing import Any

from .config import Settings
from .sandbox_backend import (
    hold_codex_sandbox_backend,
    resolve_codex_sandbox_backend,
)
from .sandbox_brokered_process import (
    brokered_process_probe_command,
    classify_brokered_process_probe,
)
from .sandbox_live_verify import (
    _run,
    _sandbox_verification_serialized,
    _write_evidence,
)
from .sandbox_live_verify import (
    verify_codex_sandbox_live as _base_verify_codex_sandbox_live,
)
from .util import canonical_json, sha256_text

_BROKERED_CHECK = "brokered_process_creation_denied"
_BROKERED_PROPERTIES = ("termination", "resource_bound")


def _apply_brokered_process_result(
    result: dict[str, Any], value: bool | None, reason: str
) -> None:
    checks = result.setdefault("checks", {})
    if not isinstance(checks, dict):
        checks = {}
        result["checks"] = checks
    checks[_BROKERED_CHECK] = value

    properties = result.setdefault("properties", {})
    if not isinstance(properties, dict):
        properties = {}
        result["properties"] = properties

    for property_name in _BROKERED_PROPERTIES:
        item = properties.get(property_name)
        if not isinstance(item, dict):
            item = {
                "status": "unverified",
                "checks": [],
                "failed": [],
                "unverified": [],
                "missing_or_failed": [],
                "reasons": {},
            }
            properties[property_name] = item

        required = list(item.get("checks") or [])
        if _BROKERED_CHECK not in required:
            required.append(_BROKERED_CHECK)
        item["checks"] = required

        failed = [name for name in list(item.get("failed") or []) if name != _BROKERED_CHECK]
        unverified = [
            name for name in list(item.get("unverified") or []) if name != _BROKERED_CHECK
        ]
        incomplete = [
            name
            for name in list(item.get("missing_or_failed") or [])
            if name != _BROKERED_CHECK
        ]
        reasons = dict(item.get("reasons") or {})
        reasons.pop(_BROKERED_CHECK, None)

        if value is False:
            failed.append(_BROKERED_CHECK)
            incomplete.append(_BROKERED_CHECK)
            reasons[_BROKERED_CHECK] = reason
            item["status"] = "failed"
        elif value is None:
            unverified.append(_BROKERED_CHECK)
            incomplete.append(_BROKERED_CHECK)
            reasons[_BROKERED_CHECK] = reason
            if item.get("status") != "failed":
                item["status"] = "unverified"

        item["failed"] = failed
        item["unverified"] = unverified
        item["missing_or_failed"] = incomplete
        item["reasons"] = reasons

    diagnostics = result.setdefault("diagnostics", {})
    if isinstance(diagnostics, dict):
        if value is True:
            diagnostics.pop(_BROKERED_CHECK, None)
        else:
            diagnostics[_BROKERED_CHECK] = reason

    result["passed"] = all(
        isinstance(item, dict) and item.get("status") == "verified"
        for item in properties.values()
    )


@_sandbox_verification_serialized
def verify_codex_sandbox_live(settings: Settings) -> dict[str, Any]:
    """Run base live verification plus the non-spawning WMI brokered-process probe."""

    base = getattr(_base_verify_codex_sandbox_live, "__wrapped__", None)
    if base is None:
        raise RuntimeError("base Sandbox verifier cannot be invoked under the shared lock")
    result = base(settings)

    backend = resolve_codex_sandbox_backend(settings)
    assert settings.sandbox_scratch_dir is not None
    root = (
        settings.sandbox_scratch_dir
        / "live-verification"
        / f"brokered-{uuid.uuid4().hex}"
    )
    root.mkdir(parents=True, exist_ok=False)
    probe_diagnostics = result.setdefault("probe_diagnostics", [])
    if not isinstance(probe_diagnostics, list):
        probe_diagnostics = []
        result["probe_diagnostics"] = probe_diagnostics

    try:
        if (
            result.get("backend_digest")
            != sha256_text(canonical_json(backend.as_dict()))
            or result.get("backend_version") != backend.version
        ):
            raise RuntimeError("Codex backend changed between live verification phases")
        command = brokered_process_probe_command(uuid.uuid4().hex)
        with hold_codex_sandbox_backend(backend):
            probe = _run(
                settings,
                backend,
                root,
                command,
                timeout=20,
                probe_name=_BROKERED_CHECK,
                probe_diagnostics=probe_diagnostics,
            )
        value, reason = classify_brokered_process_probe(
            probe.returncode, probe.stdout
        )
    except Exception as error:  # noqa: BLE001 - evidence must fail closed
        value = None
        reason = (
            "unverified: brokered Win32_Process.Create probe failed: "
            f"{type(error).__name__}"
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)

    _apply_brokered_process_result(result, value, reason)
    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    _write_evidence(marker, result)
    return result
