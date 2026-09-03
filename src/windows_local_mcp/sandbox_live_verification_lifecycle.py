from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .config import Settings
from .redaction import redact_text
from .resources import NamedControlPlaneLock
from .sandbox_backend import (
    SANDBOX_LIVE_MARKER_VERSION,
    CodexSandboxBackend,
    codex_sandbox_live_verification_status,
    isolation_context_digest,
    resolve_codex_sandbox_backend,
)
from .sandbox_live_verify import _write_evidence
from .sandbox_live_verify_hardened import verify_codex_sandbox_live
from .util import canonical_json, sha256_text, utc_now_iso

_ATTEMPT_STATE_VERSION = 1
_AUTOMATIC_LOCK_TIMEOUT_SECONDS = 15 * 60


def automatic_verification_identity_digest(
    settings: Settings, backend: CodexSandboxBackend
) -> str:
    """Bind retry state to the same backend and isolation inputs as live evidence."""

    return sha256_text(
        canonical_json(
            {
                "marker_version": SANDBOX_LIVE_MARKER_VERSION,
                "backend_digest": sha256_text(canonical_json(backend.as_dict())),
                "isolation_context_digest": isolation_context_digest(settings, backend),
                "retry_cooldown_seconds": (
                    settings.sandbox_live_verification_retry_cooldown_seconds
                ),
            }
        )
    )


def _attempt_state_path(settings: Settings) -> Path:
    return settings.data_dir / "control-plane" / "sandbox-live-verification-attempt.json"


def _read_attempt_state(settings: Settings) -> dict[str, Any] | None:
    try:
        value = json.loads(_attempt_state_path(settings).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("version") != _ATTEMPT_STATE_VERSION:
        return None
    return value


def _write_attempt_state(settings: Settings, payload: dict[str, Any]) -> None:
    _write_evidence(
        _attempt_state_path(settings),
        {"version": _ATTEMPT_STATE_VERSION, **payload},
    )


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _cooldown_remaining_seconds(
    settings: Settings,
    attempt: dict[str, Any] | None,
    *,
    identity_digest: str,
    now: datetime,
) -> int:
    if (
        not isinstance(attempt, dict)
        or attempt.get("identity_digest") != identity_digest
        or attempt.get("status") not in {"failed", "unverified", "verifying"}
    ):
        return 0
    attempted_at = _parse_time(attempt.get("last_attempt_at"))
    if attempted_at is None:
        return 0
    retry_at = attempted_at + timedelta(
        seconds=settings.sandbox_live_verification_retry_cooldown_seconds
    )
    return max(0, int((retry_at - now).total_seconds() + 0.999))


def _outcome(
    inspection: dict[str, Any],
    *,
    action: str,
    performed: bool,
    attempt: dict[str, Any] | None = None,
    retry_after_seconds: int = 0,
) -> dict[str, Any]:
    return {
        "status": inspection.get("status", "unverified"),
        "action": action,
        "full_verification_performed": performed,
        "last_verified_at": inspection.get("last_verified_at"),
        "last_verification_attempt_at": (
            attempt.get("last_attempt_at")
            if isinstance(attempt, dict)
            else inspection.get("last_verification_attempt_at")
        ),
        "stale_reason": inspection.get("stale_reason"),
        "failure_reason": inspection.get("failure_reason"),
        "retry_after_seconds": retry_after_seconds,
        "automatic_verification_deferred": retry_after_seconds > 0,
    }


def ensure_codex_sandbox_live_verification(
    settings: Settings, *, force: bool = False
) -> dict[str, Any]:
    """Reuse valid evidence or serialize one complete live probe for the current identity."""

    backend = resolve_codex_sandbox_backend(settings)
    identity_digest = automatic_verification_identity_digest(settings, backend)
    with NamedControlPlaneLock(
        settings,
        "sandbox-verification",
        timeout=_AUTOMATIC_LOCK_TIMEOUT_SECONDS,
    ):
        # Recheck under the process-shared lock so concurrent startups never probe twice.
        inspection = codex_sandbox_live_verification_status(settings, backend)
        if not force and inspection.get("status") == "verified":
            return _outcome(inspection, action="reused", performed=False)

        now = datetime.now(UTC)
        previous_attempt = _read_attempt_state(settings)
        remaining = _cooldown_remaining_seconds(
            settings,
            previous_attempt,
            identity_digest=identity_digest,
            now=now,
        )
        if not force and remaining > 0:
            deferred_inspection = dict(inspection)
            if isinstance(previous_attempt, dict):
                previous_status = str(previous_attempt.get("status", "unverified"))
                deferred_inspection["status"] = (
                    previous_status
                    if previous_status in {"failed", "unverified"}
                    else "unverified"
                )
                deferred_inspection["failure_reason"] = (
                    previous_attempt.get("last_failure_reason")
                    or "previous verification ended before a terminal result was stored"
                )
            return _outcome(
                deferred_inspection,
                action="cooldown",
                performed=False,
                attempt=previous_attempt,
                retry_after_seconds=remaining,
            )

        attempted_at = utc_now_iso()
        _write_attempt_state(
            settings,
            {
                "identity_digest": identity_digest,
                "status": "verifying",
                "last_attempt_at": attempted_at,
                "last_failure_reason": None,
            },
        )
        try:
            verify_codex_sandbox_live(settings)
        except Exception as error:  # noqa: BLE001 - Broker startup must remain available
            failure_reason = redact_text(f"{type(error).__name__}: {error}")[:2000]
            attempt = {
                "identity_digest": identity_digest,
                "status": "unverified",
                "last_attempt_at": attempted_at,
                "last_failure_reason": failure_reason,
            }
            _write_attempt_state(settings, attempt)
            failed_inspection = codex_sandbox_live_verification_status(settings, backend)
            failed_inspection["status"] = "unverified"
            failed_inspection["failure_reason"] = failure_reason
            return _outcome(
                failed_inspection,
                action="unverified",
                performed=True,
                attempt=attempt,
            )

        inspection = codex_sandbox_live_verification_status(settings, backend)
        final_status = str(inspection.get("status", "unverified"))
        failure_reason = inspection.get("failure_reason")
        attempt = {
            "identity_digest": identity_digest,
            "status": final_status,
            "last_attempt_at": attempted_at,
            "last_failure_reason": failure_reason,
        }
        _write_attempt_state(settings, attempt)
        return _outcome(
            inspection,
            action="verified" if final_status == "verified" else final_status,
            performed=True,
            attempt=attempt,
        )


class SandboxLiveVerificationLifecycle:
    """Process-local view of the non-blocking automatic verifier."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._guard = threading.Lock()
        self._thread: threading.Thread | None = None
        self._state: dict[str, Any] = {
            "status": "missing",
            "action": "not_started",
            "full_verification_performed": False,
            "last_verified_at": None,
            "last_verification_attempt_at": None,
            "stale_reason": None,
            "failure_reason": None,
            "retry_after_seconds": 0,
            "automatic_verification_deferred": False,
        }

    def start(self) -> bool:
        """Start once and return immediately; Broker startup never waits for live probes."""

        if not self.settings.approved_sandbox_enabled:
            return False
        with self._guard:
            if self._thread is not None:
                return False
            self._state = {**self._state, "status": "verifying", "action": "starting"}
            self._thread = threading.Thread(
                target=self.run_once,
                name="wlmcp-sandbox-live-verification",
                daemon=True,
            )
            self._thread.start()
            return True

    def run_once(self) -> dict[str, Any]:
        with self._guard:
            self._state = {**self._state, "status": "verifying", "action": "checking"}
        try:
            outcome = ensure_codex_sandbox_live_verification(self.settings)
        except Exception as error:  # noqa: BLE001 - never couple Broker startup to Sandbox
            outcome = {
                **self._state,
                "status": "unverified",
                "action": "unverified",
                "failure_reason": redact_text(f"{type(error).__name__}: {error}")[:2000],
            }
        with self._guard:
            self._state = dict(outcome)
        return dict(outcome)

    def snapshot(self) -> dict[str, Any]:
        with self._guard:
            return dict(self._state)
