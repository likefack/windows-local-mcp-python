from __future__ import annotations

from typing import Any

from .policy import NormalizedCommand


def command_risk_facts(
    normalized: NormalizedCommand, *, workspace_write: bool, manifest: dict[str, Any]
) -> dict[str, Any]:
    key = normalized.program_key
    args = [value.casefold() for value in normalized.args]
    deletes = any(
        value in {"rm", "remove", "clean", "delete", "reset", "checkout"} for value in args
    )
    git_commit = (
        key == "git"
        and bool(args)
        and args[0] in {"commit", "push", "reset", "checkout", "merge", "rebase"}
    )
    git_push = key == "git" and bool(args) and args[0] == "push"
    adb_mutation = key == "adb" and any(
        value in {"install", "uninstall", "push", "shell", "emu"} for value in args
    )
    staged = manifest.get("mode") == "staged-cwd"
    high = deletes or git_push or adb_mutation or normalized.network_expected or workspace_write
    detected: dict[str, Any] = {
        "workspace_write_requested": workspace_write or git_commit,
        "file_delete_command_detected": deletes,
        "network_requested": normalized.network_expected,
        "git_operation": args[0]
        if key == "git"
        and args
        and args[0] in {"commit", "push", "reset", "checkout", "merge", "rebase"}
        else None,
        "git_push_detected": git_push,
        "adb_device_mutation_detected": adb_mutation,
        "external_state_change_detected": git_push
        or normalized.network_expected
        or adb_mutation,
    }
    detected = {name: value for name, value in detected.items() if value not in {False, None, ""}}
    return {
        "risk_level": "high" if high else ("medium" if staged or git_commit else "low"),
        "detected_requested_effects": detected,
        "effective_host_capabilities": {
            "identity": "real Windows user token",
            "filesystem_outside_workspace_os_possible": True,
            "direct_socket_api_os_possible": True,
            "child_process_creation_os_possible": True,
            "note": "These are token capabilities, not effects detected in this command.",
        },
        "rollback": "workspace files only"
        if workspace_write
        else (
            "not guaranteed"
            if git_commit or normalized.network_expected or adb_mutation
            else "not applicable"
        ),
        "impact_scope": "workspace source files"
        if workspace_write
        else (
            "external service or device"
            if git_push or normalized.network_expected or adb_mutation
            else "staged execution copy; process still runs with the local account token"
        ),
    }
