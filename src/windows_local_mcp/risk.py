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
    return {
        "risk_level": "high" if high else ("medium" if staged or git_commit else "low"),
        "writes_workspace_declared": workspace_write or git_commit,
        "may_delete_files": True if deletes else ("possible" if workspace_write else False),
        "workspace_outside_access_possible": True,
        "network_declared": normalized.network_expected,
        "network_access_possible": True,
        "external_state_change_possible": git_push or normalized.network_expected or adb_mutation,
        "git_operation": args[0]
        if key == "git"
        and args
        and args[0] in {"commit", "push", "reset", "checkout", "merge", "rebase"}
        else None,
        "adb_device_state_change": adb_mutation,
        "starts_child_processes": True,
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
