from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .config import Settings
from .git_broker_sandbox import (
    GitBrokerContainment,
    GitBrokerUnavailable,
    require_git_broker_containment,
    run_git_broker_batch,
)
from .resources import NamedControlPlaneLock
from .sandbox_backend import SANDBOX_SECURITY_PROPERTIES
from .tool_safety import capture_executable_identity, ensure_external_tool_executable
from .util import canonical_json, sha256_text, utc_now_iso

GIT_BROKER_LIVE_MARKER_VERSION = 1
GIT_BROKER_COMMAND_POLICY_VERSION = 2
_GIT_BROKER_REQUIRED_CHECKS = (
    "git_inside_worktree",
    "git_top_level_projection",
    "git_status_readonly",
)


def _marker_path(settings: Settings) -> Path:
    return settings.data_dir / "control-plane" / "git-broker-live-verification.json"


def configured_git_identity(settings: Settings) -> dict[str, Any]:
    """Resolve the pinned Git identity without recursively consulting route availability."""

    if not settings.git_enabled:
        raise GitBrokerUnavailable("Automatic Git Broker is disabled by configuration")
    if settings.git_executable_path is None or settings.git_executable_sha256 is None:
        raise GitBrokerUnavailable(
            "Automatic Git Broker requires git_executable_path and git_executable_sha256"
        )
    executable = ensure_external_tool_executable(
        settings.git_executable_path,
        workspace_root=settings.workspace_root,
        data_dir=settings.data_dir,
        sandbox_scratch_dir=settings.sandbox_scratch_dir,
    )
    return capture_executable_identity(
        executable,
        expected_sha256=settings.git_executable_sha256,
        provenance="explicit-local-config",
    )


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
        "diff.autoRefreshIndex=false",
        "-c",
        "diff.external=",
        "-c",
        "credential.helper=",
    ]


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
    results = run_git_broker_batch(
        settings=settings,
        git_identity=git_identity,
        commands=(
            [*base, "rev-parse", "--is-inside-work-tree"],
            [*base, "rev-parse", "--show-toplevel"],
            [*base, "status", "--porcelain=v1", "--untracked-files=no"],
        ),
        cwd=str(settings.workspace_root),
        timeout=60,
        output_limit=64 * 1024,
    )
    if len(results) != 3:
        raise GitBrokerUnavailable(
            "Automatic Git Broker live verification returned an incomplete probe set"
        )
    inside, top_level, status = results
    inside_ok = inside.returncode == 0 and inside.stdout.strip().lower() == b"true"
    try:
        top_level_path = Path(
            top_level.stdout.decode("utf-8", errors="strict").strip()
        ).resolve(strict=True)
    except (OSError, UnicodeDecodeError, ValueError):
        top_level_path = Path()
    top_level_ok = (
        top_level.returncode == 0
        and os.path.normcase(str(top_level_path))
        == os.path.normcase(str(settings.workspace_root.resolve(strict=True)))
    )
    status_ok = status.returncode == 0
    checks = {
        "git_inside_worktree": inside_ok,
        "git_top_level_projection": top_level_ok,
        "git_status_readonly": status_ok,
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
