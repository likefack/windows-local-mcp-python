from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .config import Settings, load_settings
from .control_plane_guard import (
    _approved_host_postflight_marker,
    _is_reparse,
    _tamper_marker,
    assert_control_plane_healthy,
)
from .tool_safety import capture_file_identity, hold_file_identity
from .util import sha256_bytes

_RECOVERY_VERSION = 1
_ALLOWED_OPERATION_ID_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
)


def _validate_operation_id(operation_id: str) -> str:
    value = str(operation_id)
    if not value or len(value) > 200 or any(
        character not in _ALLOWED_OPERATION_ID_CHARACTERS for character in value
    ):
        raise ValueError("invalid Approved Host recovery operation id")
    return value


def _assert_control_plane_directory_safe(settings: Settings) -> Path:
    root = settings.data_dir / "control-plane"
    if not root.exists() or not root.is_dir():
        raise RuntimeError(f"control-plane directory is unavailable: {root}")
    if _is_reparse(root):
        raise RuntimeError(f"control-plane directory is a reparse point: {root}")
    resolved = root.resolve(strict=True)
    data_root = settings.data_dir.resolve(strict=True)
    try:
        resolved.relative_to(data_root)
    except ValueError as error:
        raise RuntimeError("control-plane directory escaped configured data_dir") from error
    return root


def _inspect_marker_path(
    path: Path,
    *,
    expected_operation_id: str,
) -> dict[str, Any]:
    operation_id = _validate_operation_id(expected_operation_id)
    if _is_reparse(path):
        raise RuntimeError(f"Approved Host postflight marker is a reparse point: {path}")
    details = path.stat()
    if not path.is_file() or details.st_nlink != 1:
        raise RuntimeError("Approved Host postflight marker has unsafe file identity")

    identity = capture_file_identity(
        path,
        provenance="approved-host-explicit-recovery",
    )
    with hold_file_identity(identity) as locked:
        data = locked.read_bytes()
        if sha256_bytes(data) != str(identity["sha256"]):
            raise RuntimeError("Approved Host postflight marker changed while locked")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise RuntimeError("Approved Host postflight marker is unreadable") from error
        if not isinstance(payload, dict):
            raise RuntimeError("Approved Host postflight marker is not an object")
        if payload.get("version") != 1:
            raise RuntimeError("Approved Host postflight marker version changed")
        if payload.get("state") != "postflight_pending":
            raise RuntimeError("Approved Host postflight marker state changed")
        if payload.get("operation_id") != operation_id:
            raise RuntimeError("Approved Host postflight marker operation binding changed")
        if payload.get("recovery") != "manual operator review required":
            raise RuntimeError("Approved Host postflight marker recovery contract changed")

    return {
        "version": _RECOVERY_VERSION,
        "operation_id": operation_id,
        "marker_path": str(path.resolve(strict=True)),
        "marker_identity": identity,
        "marker_payload": payload,
    }


def inspect_postflight_recovery(
    settings: Settings,
    expected_operation_id: str,
) -> dict[str, Any]:
    operation_id = _validate_operation_id(expected_operation_id)
    _assert_control_plane_directory_safe(settings)
    tamper = _tamper_marker(settings)
    if tamper.exists():
        raise RuntimeError(
            "control-plane tamper marker is also present; Approved Host postflight recovery "
            "must not clear an independent tamper latch"
        )

    marker = _approved_host_postflight_marker(settings)
    if not marker.exists():
        return {
            "version": _RECOVERY_VERSION,
            "operation_id": operation_id,
            "present": False,
            "marker_path": str(marker.absolute()),
        }

    evidence = _inspect_marker_path(marker, expected_operation_id=operation_id)
    evidence["present"] = True
    return evidence


def quarantine_postflight_recovery(
    settings: Settings,
    expected_operation_id: str,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    operation_id = _validate_operation_id(expected_operation_id)
    digest = str(expected_sha256).casefold()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("expected marker SHA-256 is invalid")

    evidence = inspect_postflight_recovery(settings, operation_id)
    marker = _approved_host_postflight_marker(settings)
    quarantine = marker.with_name(
        f"approved-host-postflight-recovered-{operation_id}-{digest[:16]}.json"
    )

    if not bool(evidence.get("present")):
        if not quarantine.exists():
            raise RuntimeError(
                "Approved Host postflight marker disappeared before explicit recovery"
            )
        recovered = _inspect_marker_path(
            quarantine,
            expected_operation_id=operation_id,
        )
        if str(recovered["marker_identity"]["sha256"]).casefold() != digest:
            raise RuntimeError("quarantined Approved Host postflight marker digest changed")
        recovered.update(
            {
                "present": False,
                "quarantined": True,
                "resumed_partial_recovery": True,
                "quarantine_path": str(quarantine.resolve(strict=True)),
            }
        )
        return recovered

    identity = dict(evidence["marker_identity"])
    if str(identity.get("sha256") or "").casefold() != digest:
        raise RuntimeError("Approved Host postflight marker changed after operator review")
    if quarantine.exists():
        raise RuntimeError(
            "Approved Host postflight recovery quarantine already exists while the pending "
            "marker is still present"
        )

    # The path can be raced after the read-only verification interval because the marker is in
    # runtime-user-owned storage. Move it first, then require that the moved object has the exact
    # content and stable file identity that was reviewed. Any replacement/race leaves the
    # SYSTEM-owned authority latch in place because callers remove active.json only after this
    # function succeeds.
    os.rename(marker, quarantine)
    recovered = _inspect_marker_path(
        quarantine,
        expected_operation_id=operation_id,
    )
    recovered_identity = dict(recovered["marker_identity"])
    if recovered_identity.get("stable_file_identity") != identity.get("stable_file_identity"):
        raise RuntimeError(
            "Approved Host postflight marker stable identity changed during recovery move"
        )
    if str(recovered_identity.get("sha256") or "").casefold() != digest:
        raise RuntimeError("Approved Host postflight marker digest changed during recovery move")
    if marker.exists():
        raise RuntimeError(
            "Approved Host postflight marker path reappeared during explicit recovery"
        )

    # This proves the user-owned guard no longer blocks operation creation. The independently
    # privileged authority latch must still exist at this point in the integrated recovery path.
    assert_control_plane_healthy(settings)
    recovered.update(
        {
            "present": False,
            "quarantined": True,
            "resumed_partial_recovery": False,
            "quarantine_path": str(quarantine.resolve(strict=True)),
        }
    )
    return recovered


def _load_explicit_config(config_path: Path) -> Settings:
    resolved = config_path.resolve(strict=True)
    os.environ["LOCAL_MCP_CONFIG"] = str(resolved)
    os.environ.pop("LOCAL_MCP_ROOT", None)
    return load_settings()


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--config", type=Path, required=True)
    inspect_parser.add_argument("--operation-id", required=True)

    quarantine_parser = subparsers.add_parser("quarantine")
    quarantine_parser.add_argument("--config", type=Path, required=True)
    quarantine_parser.add_argument("--operation-id", required=True)
    quarantine_parser.add_argument("--expected-sha256", required=True)

    args = parser.parse_args()
    settings = _load_explicit_config(args.config)
    if args.mode == "inspect":
        result = inspect_postflight_recovery(settings, args.operation_id)
    else:
        result = quarantine_postflight_recovery(
            settings,
            args.operation_id,
            expected_sha256=args.expected_sha256,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
