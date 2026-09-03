from __future__ import annotations

import shutil
import uuid
from typing import Any

from .config import Settings
from .sandbox_backend import (
    SANDBOX_LIVE_MARKER_VERSION,
    hold_codex_sandbox_backend,
    resolve_codex_sandbox_backend,
    sandbox_live_verification_route_eligible,
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
from .sandbox_source_acl import ensure_source_workspace_read_deny
from .util import canonical_json, sha256_text, utc_now_iso
from .wfp_guard import resolve_sandbox_account_identity

_BROKERED_CHECK = "brokered_process_creation_denied"
_BROKERED_PROPERTIES = ("termination", "resource_bound")


def _finalize_verification_status(result: dict[str, Any], attempted_at: str) -> None:
    properties = result.get("properties")
    failed = (
        sorted(
            name
            for name, item in properties.items()
            if isinstance(item, dict) and item.get("status") == "failed"
        )
        if isinstance(properties, dict)
        else []
    )
    result["attempted_at"] = attempted_at
    if sandbox_live_verification_route_eligible(result):
        result["verification_status"] = "verified"
        result["verification_failure_reason"] = None
    elif failed:
        result["verification_status"] = "failed"
        result["verification_failure_reason"] = (
            "security boundary failed: " + ", ".join(failed)
        )
    else:
        result["verification_status"] = "unverified"
        diagnostics = result.get("diagnostics")
        reason = diagnostics.get("verification_error") if isinstance(diagnostics, dict) else None
        result["verification_failure_reason"] = (
            reason if isinstance(reason, str) and reason else "required live properties unverified"
        )


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
    """Provision the source read boundary, then run all live Sandbox probes."""

    base = getattr(_base_verify_codex_sandbox_live, "__wrapped__", None)
    if base is None:
        raise RuntimeError("base Sandbox verifier cannot be invoked under the shared lock")

    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    attempted_at = utc_now_iso()
    # 検証中は既存の有効 marker も置き換え、全必須 probe 完了前の実行を防ぐ。
    _write_evidence(
        marker,
        {
            "version": SANDBOX_LIVE_MARKER_VERSION,
            "attempted_at": attempted_at,
            "verification_status": "verifying",
            "passed": False,
        },
    )

    account = resolve_sandbox_account_identity()
    source_guard_before = ensure_source_workspace_read_deny(
        settings.workspace_root, account.sid
    )
    # brokered-process probe 前の暫定結果を別 process が有効 marker として読まないようにする。
    result = base(settings, persist_evidence=False)
    marker_account = result.get("sandbox_account_identity")
    # 基礎 probe が identity 測定前に失敗した場合は、その unverified 診断を保持する。
    # identity を実測できた場合だけ、ACL 設定前後の置換を明示的に拒否する。
    if isinstance(marker_account, dict) and marker_account.get("sid") != account.sid:
        raise RuntimeError(
            "Codex Sandbox account changed after source-workspace ACL provisioning"
        )

    # The base verifier's fixed `exit 0` command is the setup-readiness gate. If it
    # failed, do not launch the hardened follow-up and risk repeating the same UAC.
    checks = result.get("checks")
    if not isinstance(checks, dict) or checks.get("simple_command") is not True:
        _apply_brokered_process_result(
            result,
            None,
            "unverified: skipped after foundational Sandbox setup failure",
        )
        source_guard_after = ensure_source_workspace_read_deny(
            settings.workspace_root, account.sid
        )
        source_guard_after["added_before_verification"] = bool(
            source_guard_before.get("added")
        )
        result["source_workspace_read_acl_guard"] = source_guard_after
        _finalize_verification_status(result, attempted_at)
        _write_evidence(marker, result)
        return result

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
    source_guard_after = ensure_source_workspace_read_deny(
        settings.workspace_root, account.sid
    )
    source_guard_after["added_before_verification"] = bool(
        source_guard_before.get("added")
    )
    result["source_workspace_read_acl_guard"] = source_guard_after
    _finalize_verification_status(result, attempted_at)
    _write_evidence(marker, result)
    return result
