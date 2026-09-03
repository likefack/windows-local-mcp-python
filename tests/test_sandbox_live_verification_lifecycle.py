from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.sandbox_live_verification_lifecycle import (
    SandboxLiveVerificationLifecycle,
    ensure_codex_sandbox_live_verification,
)


def _settings(tmp_path: Path, *, cooldown: int = 300) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        sandbox_live_verification_retry_cooldown_seconds=cooldown,
    )
    settings.ensure_directories()
    return settings


def _install_fake_boundary(
    monkeypatch: pytest.MonkeyPatch,
    state: dict[str, object],
    verifier,
) -> None:
    module = "windows_local_mcp.sandbox_live_verification_lifecycle"
    monkeypatch.setattr(f"{module}.resolve_codex_sandbox_backend", lambda _settings: object())
    monkeypatch.setattr(
        f"{module}.automatic_verification_identity_digest",
        lambda _settings, _backend: str(state.get("identity", "identity-a")),
    )

    def inspect(_settings, _backend):
        return {
            "status": state["status"],
            "evidence": None,
            "last_verified_at": state.get("last_verified_at"),
            "last_verification_attempt_at": state.get("last_attempt_at"),
            "stale_reason": state.get("stale_reason"),
            "failure_reason": state.get("failure_reason"),
        }

    monkeypatch.setattr(f"{module}.codex_sandbox_live_verification_status", inspect)
    monkeypatch.setattr(f"{module}.verify_codex_sandbox_live", verifier)


def test_valid_marker_is_reused_across_restarts_without_full_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    state: dict[str, object] = {"status": "verified"}

    def unexpected(_settings):
        raise AssertionError("valid marker must not trigger a full verification")

    _install_fake_boundary(monkeypatch, state, unexpected)
    first = ensure_codex_sandbox_live_verification(settings)
    second = ensure_codex_sandbox_live_verification(settings)

    assert first["action"] == second["action"] == "reused"
    assert first["full_verification_performed"] is False


@pytest.mark.parametrize("initial", ["missing", "stale"])
def test_invalid_marker_runs_once_and_becomes_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, initial: str
) -> None:
    settings = _settings(tmp_path)
    state: dict[str, object] = {
        "status": initial,
        "stale_reason": "isolation_context_mismatch" if initial == "stale" else None,
    }
    calls = 0

    def verify(_settings):
        nonlocal calls
        calls += 1
        state.update(status="verified", stale_reason=None, last_verified_at="now")

    _install_fake_boundary(monkeypatch, state, verify)
    outcome = ensure_codex_sandbox_live_verification(settings)

    assert outcome["status"] == "verified"
    assert outcome["full_verification_performed"] is True
    assert calls == 1


@pytest.mark.parametrize("final", ["failed", "unverified"])
def test_failed_or_unverified_probe_keeps_only_sandbox_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, final: str
) -> None:
    settings = _settings(tmp_path)
    state: dict[str, object] = {"status": "missing"}

    def verify(_settings):
        state.update(status=final, failure_reason=f"probe {final}")

    _install_fake_boundary(monkeypatch, state, verify)
    outcome = ensure_codex_sandbox_live_verification(settings)

    assert outcome["status"] == final
    assert outcome["full_verification_performed"] is True
    # lifecycle failure is returned as capability state and never raises into Broker startup.
    assert outcome["failure_reason"] == f"probe {final}"


def test_concurrent_startups_share_one_full_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    state: dict[str, object] = {"status": "missing"}
    calls = 0
    calls_guard = threading.Lock()

    def verify(_settings):
        nonlocal calls
        with calls_guard:
            calls += 1
        time.sleep(0.15)
        state["status"] = "verified"

    _install_fake_boundary(monkeypatch, state, verify)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _value: ensure_codex_sandbox_live_verification(settings), range(2)))

    assert calls == 1
    assert sorted(item["action"] for item in outcomes) == ["reused", "verified"]


def test_probe_crash_releases_lock_and_force_retry_uses_same_core(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    state: dict[str, object] = {"status": "missing"}
    calls = 0

    def verify(_settings):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated verifier crash")
        state["status"] = "verified"

    _install_fake_boundary(monkeypatch, state, verify)
    first = ensure_codex_sandbox_live_verification(settings)
    cooled = ensure_codex_sandbox_live_verification(settings)
    second = ensure_codex_sandbox_live_verification(settings, force=True)

    assert first["status"] == "unverified"
    assert cooled["status"] == "unverified"
    assert cooled["action"] == "cooldown"
    assert second["status"] == "verified"
    assert calls == 2


def test_failure_cooldown_prevents_storm_but_new_identity_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, cooldown=300)
    state: dict[str, object] = {"status": "missing", "identity": "identity-a"}
    calls = 0

    def verify(_settings):
        nonlocal calls
        calls += 1
        state.update(status="unverified", failure_reason="temporary launch failure")

    _install_fake_boundary(monkeypatch, state, verify)
    first = ensure_codex_sandbox_live_verification(settings)
    cooled = ensure_codex_sandbox_live_verification(settings)
    state.update(identity="identity-b", status="stale", stale_reason="backend_identity_mismatch")
    changed = ensure_codex_sandbox_live_verification(settings)

    assert first["full_verification_performed"] is True
    assert cooled["action"] == "cooldown"
    assert cooled["automatic_verification_deferred"] is True
    assert changed["full_verification_performed"] is True
    assert calls == 2


def test_manual_force_ignores_cooldown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, cooldown=300)
    state: dict[str, object] = {"status": "missing"}
    calls = 0

    def verify(_settings):
        nonlocal calls
        calls += 1
        state.update(status="unverified", failure_reason="measurement unavailable")

    _install_fake_boundary(monkeypatch, state, verify)
    ensure_codex_sandbox_live_verification(settings)
    ensure_codex_sandbox_live_verification(settings, force=True)

    assert calls == 2


def test_background_start_returns_while_probe_is_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    state: dict[str, object] = {"status": "missing"}
    entered = threading.Event()
    release = threading.Event()

    def verify(_settings):
        entered.set()
        release.wait(timeout=5)
        state["status"] = "verified"

    _install_fake_boundary(monkeypatch, state, verify)
    lifecycle = SandboxLiveVerificationLifecycle(settings)

    started_at = time.monotonic()
    assert lifecycle.start() is True
    elapsed = time.monotonic() - started_at
    assert entered.wait(timeout=2)
    assert elapsed < 0.5
    assert lifecycle.snapshot()["status"] == "verifying"
    release.set()


def test_manual_cli_forces_the_same_managed_verifier(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from windows_local_mcp import cli
    from windows_local_mcp import sandbox_backend as backend_module
    from windows_local_mcp import sandbox_live_verification_lifecycle as lifecycle_module

    settings = SimpleNamespace()
    backend = object()
    calls: list[bool] = []
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    monkeypatch.setattr(
        lifecycle_module,
        "ensure_codex_sandbox_live_verification",
        lambda _settings, *, force=False: calls.append(force) or {"status": "verified"},
    )
    monkeypatch.setattr(
        backend_module,
        "resolve_codex_sandbox_backend",
        lambda _settings: backend,
    )
    monkeypatch.setattr(
        backend_module,
        "codex_sandbox_live_verification_status",
        lambda _settings, _backend: {"status": "verified", "evidence": {"version": 5}},
    )
    monkeypatch.setattr("sys.argv", ["windows-local-mcp", "verify-codex-sandbox"])

    cli.main()

    assert calls == [True]
    assert '"route_eligible": true' in capsys.readouterr().out
