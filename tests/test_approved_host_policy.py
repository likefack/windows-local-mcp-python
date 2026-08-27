from __future__ import annotations

import pytest

from windows_local_mcp.approved_host_policy import (
    _authority_worker_bypass_allowed,
    _service_query_indicates_installed,
)


def test_service_query_accepts_running_or_stopped_installed_service_result() -> None:
    assert _service_query_indicates_installed(0) is True


def test_service_query_treats_only_service_does_not_exist_as_absent() -> None:
    assert _service_query_indicates_installed(1060) is False


@pytest.mark.parametrize("returncode", [1, 5, 87, 1058, 1722])
def test_service_query_other_failures_fail_closed(returncode: int) -> None:
    with pytest.raises(RuntimeError, match="SCM query failed closed"):
        _service_query_indicates_installed(returncode)


def test_provisioned_authority_latch_is_checked_even_when_host_config_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from windows_local_mcp import approved_host_policy, control_plane_guard

    calls: list[str] = []

    class DisabledSettings:
        approved_host_enabled = False

    class FakeAuthorityClient:
        def assert_available(self) -> dict[str, object]:
            calls.append("checked")
            return {"healthy": True}

    monkeypatch.setattr(control_plane_guard, "assert_control_plane_healthy", lambda _settings: None)
    monkeypatch.setattr(approved_host_policy.os, "name", "nt")
    monkeypatch.delenv("WINDOWS_LOCAL_MCP_AUTHORITY_WORKER", raising=False)
    monkeypatch.setattr(approved_host_policy, "_authority_service_installed", lambda: True)
    monkeypatch.setattr(approved_host_policy, "ApprovedHostAuthorityClient", FakeAuthorityClient)

    approved_host_policy.install_approved_host_authority_health_gate()
    control_plane_guard.assert_control_plane_healthy(DisabledSettings())

    assert calls == ["checked"]


def test_authority_worker_environment_flag_alone_cannot_bypass_latch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from windows_local_mcp import approved_host_policy
    from windows_local_mcp import approved_host_service

    monkeypatch.setattr(approved_host_policy.os, "name", "nt")
    monkeypatch.setenv("WINDOWS_LOCAL_MCP_AUTHORITY_WORKER", "1")
    monkeypatch.setattr(
        approved_host_service,
        "_current_process_sid",
        lambda: "S-1-5-21-1000",
    )

    assert _authority_worker_bypass_allowed() is False


def test_authority_worker_bypass_requires_localsystem_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from windows_local_mcp import approved_host_policy
    from windows_local_mcp import approved_host_service

    monkeypatch.setattr(approved_host_policy.os, "name", "nt")
    monkeypatch.setenv("WINDOWS_LOCAL_MCP_AUTHORITY_WORKER", "1")
    monkeypatch.setattr(
        approved_host_service,
        "_current_process_sid",
        lambda: "S-1-5-18",
    )

    assert _authority_worker_bypass_allowed() is True
