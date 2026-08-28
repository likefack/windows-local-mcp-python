from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .config import Settings
from .git_broker_sandbox import (
    GitBrokerContainment,
    GitBrokerUnavailable,
    require_git_broker_containment,
    run_git_broker_batch,
)
from .resources import NamedControlPlaneLock, _try_remove_disposable_artifact
from .sandbox_backend import SANDBOX_SECURITY_PROPERTIES
from .tool_safety import pinned_helper_identity
from .util import canonical_json, sha256_text, utc_now_iso

GIT_BROKER_LIVE_MARKER_VERSION = 1
GIT_BROKER_COMMAND_POLICY_VERSION = 5
_GIT_BROKER_ALLOWED_BUILTINS = frozenset(
    {"status", "diff", "log", "show", "rev-parse", "ls-files", "symbolic-ref"}
)
_GIT_BROKER_REQUIRED_CHECKS = (
    "git_inside_worktree",
    "git_projection_snapshot_bound",
    "git_status_readonly",
    "git_allowed_commands_builtin",
)
_GIT_LIVE_PROBE_BUDGET_PER_COMMAND_SECONDS = 60.0


def _marker_path(settings: Settings) -> Path:
    return settings.data_dir / "control-plane" / "git-broker-live-verification.json"


def configured_git_identity(settings: Settings) -> dict[str, Any]:
    """Resolve the pinned Git identity without recursively consulting route availability."""

    if not settings.git_enabled:
        raise GitBrokerUnavailable("Automatic Git Broker is disabled by configuration")
    try:
        return pinned_helper_identity(settings, "git")
    except (FileNotFoundError, OSError, PermissionError, ValueError) as error:
        raise GitBrokerUnavailable(str(error)) from error


def _require_strict_sandbox_properties(evidence: dict[str, Any]) -> None:
    properties = evidence.get("properties")
    if not isinstance(properties, dict):
        raise GitBrokerUnavailable(
            "Automatic Git Broker requires complete Codex Sandbox live property evidence"
        )
    incomplete = [
        name
        for name in SANDBOX_SECURITY_PROPERTIES
        if not isinstance(properties.get(name), dict)
        or properties[name].get("status") != "verified"
    ]
    if incomplete:
        raise GitBrokerUnavailable(
            "Automatic Git Broker requires every Sandbox security property to be live verified; "
            "not verified: " + ", ".join(incomplete)
        )


def git_broker_live_context(
    settings: Settings,
    git_identity: dict[str, Any],
    *,
    containment: GitBrokerContainment | None = None,
) -> dict[str, Any]:
    """Build the exact machine/workspace/backend identity bound to Git availability."""

    containment = containment or require_git_broker_containment(settings, git_identity)
    _require_strict_sandbox_properties(containment.live_evidence)
    return {
        "version": GIT_BROKER_LIVE_MARKER_VERSION,
        "command_policy_version": GIT_BROKER_COMMAND_POLICY_VERSION,
        "git_executable_identity": git_identity,
        "git_process_cwd": "trusted-executable-directory-before-fixed--C",
        "git_subcommand_execution": "required-automatic-commands-must-be-builtins",
        "containment_policy_digest": containment.policy_digest,
        "sandbox_backend": containment.backend.as_dict(),
        "sandbox_live_evidence_digest": sha256_text(
            canonical_json(containment.live_evidence)
        ),
        "workspace_root": str(settings.workspace_root.resolve(strict=True)),
        "max_sandbox_scratch_bytes": settings.max_sandbox_scratch_bytes,
        "source_workspace_access": "deny",
        "execution_input": "sanitized-disposable-repository-snapshot",
        "network": "deny",
        "host_fallback": False,
    }


def require_git_broker_live_verification(
    settings: Settings, git_identity: dict[str, Any]
) -> dict[str, Any]:
    """Require an exact, current Git-specific live marker before automatic execution."""

    context = git_broker_live_context(settings, git_identity)
    expected_digest = sha256_text(canonical_json(context))
    try:
        marker = json.loads(_marker_path(settings).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise GitBrokerUnavailable(
            "Automatic Git Broker has not completed Git-specific Windows live verification; "
            "run verify-git-broker explicitly"
        ) from error
    checks = marker.get("checks")
    if (
        marker.get("version") != GIT_BROKER_LIVE_MARKER_VERSION
        or marker.get("context") != context
        or marker.get("context_digest") != expected_digest
        or marker.get("route_eligible") is not True
        or not isinstance(checks, dict)
        or any(checks.get(name) is not True for name in _GIT_BROKER_REQUIRED_CHECKS)
    ):
        raise GitBrokerUnavailable(
            "Automatic Git Broker live verification is missing, failed, or stale for the "
            "current Git/Sandbox/workspace identity; run verify-git-broker explicitly"
        )
    return marker


def _git_probe_base(git: str) -> list[str]:
    return [
        git,
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "maintenance.auto=false",
        "-c",
        "gc.auto=0",
        "-c",
        "diff.autoRefreshIndex=false",
        "-c",
        "diff.external=",
        "-c",
        "credential.helper=",
    ]


def _valid_snapshot_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value.casefold())
    )


def _builtins_from_output(data: bytes) -> set[str]:
    try:
        return set(data.decode("utf-8", errors="strict").split())
    except UnicodeDecodeError:
        return set()


def _atomic_write_marker(settings: Settings, payload: dict[str, Any]) -> None:
    path = _marker_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_json(payload).encode("utf-8")
    temporary: Path | None = None
    with NamedControlPlaneLock(settings, "sandbox-verification"):
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", delete=False, dir=path.parent
            ) as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
                temporary = Path(output.name)
            os.replace(temporary, path)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def verify_git_broker_live(settings: Settings) -> dict[str, Any]:
    """Run the explicit pinned-Git E2E and persist its exact availability binding."""

    git_identity = configured_git_identity(settings)
    containment = require_git_broker_containment(settings, git_identity)
    context = git_broker_live_context(settings, git_identity, containment=containment)
    git = str(git_identity["path"])
    base = _git_probe_base(git)
    commands = (
        [*base, "rev-parse", "--is-inside-work-tree"],
        [*base, "status", "--porcelain=v1", "--untracked-files=no"],
        [*base, "--list-cmds=builtins"],
    )
    token = f"live-{uuid.uuid4().hex}"
    stage_root = (
        settings.sandbox_scratch_dir / "git-broker" / token
        if settings.sandbox_scratch_dir is not None
        else None
    )
    try:
        # The runner's timeout is a shared batch deadline.  Budget each trusted verifier launch
        # the same 60-second allowance used for one command, rather than forcing three sequential
        # Sandbox launches to compete for a single-command budget.
        results = run_git_broker_batch(
            settings=settings,
            git_identity=git_identity,
            commands=commands,
            cwd=str(settings.workspace_root),
            timeout=_GIT_LIVE_PROBE_BUDGET_PER_COMMAND_SECONDS * len(commands),
            output_limit=64 * 1024,
            token=token,
            live_verification_probe=True,
        )
    finally:
        if stage_root is not None:
            _try_remove_disposable_artifact(stage_root)
    if len(results) != 3:
        raise GitBrokerUnavailable(
            "Automatic Git Broker live verification returned an incomplete probe set"
        )
    inside, status, builtins = results
    inside_ok = inside.returncode == 0 and inside.stdout.strip().lower() == b"true"
    snapshot_digests = {
        getattr(result, "snapshot_digest", None)
        for result in results
        if _valid_snapshot_digest(getattr(result, "snapshot_digest", None))
    }
    snapshot_bound = len(snapshot_digests) == 1 and all(
        _valid_snapshot_digest(getattr(result, "snapshot_digest", None))
        for result in results
    )
    status_ok = status.returncode == 0
    builtin_names = _builtins_from_output(builtins.stdout)
    builtins_ok = (
        builtins.returncode == 0 and _GIT_BROKER_ALLOWED_BUILTINS.issubset(builtin_names)
    )
    checks = {
        "git_inside_worktree": inside_ok,
        "git_projection_snapshot_bound": snapshot_bound,
        "git_status_readonly": status_ok,
        "git_allowed_commands_builtin": builtins_ok,
    }
    payload = {
        "version": GIT_BROKER_LIVE_MARKER_VERSION,
        "verified_at": utc_now_iso(),
        "context": context,
        "context_digest": sha256_text(canonical_json(context)),
        "checks": checks,
        "route_eligible": all(checks.values()),
    }
    if payload["route_eligible"] is not True:
        raise GitBrokerUnavailable(
            "Automatic Git Broker Git-specific live verification failed"
        )
    _atomic_write_marker(settings, payload)
    return payload
