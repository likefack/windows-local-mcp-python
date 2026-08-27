from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from windows_local_mcp.approved_host_service_entry import (
    HardenedApprovedHostAuthorityServer,
)


class _Store:
    def __init__(self, root: Path) -> None:
        self.root = root


def test_production_service_rejects_runtime_user_cancel_before_base_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = object.__new__(HardenedApprovedHostAuthorityServer)
    server.runtime_sid = "S-1-5-21-test"
    server.store = _Store(tmp_path / "authority")
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        "windows_local_mcp.approved_host_service_entry.assert_authority_state_security",
        lambda root: calls.append(("state", root)),
    )
    monkeypatch.setattr(
        "windows_local_mcp.approved_host_service_entry.assert_authority_service_security",
        lambda sid: calls.append(("service", sid)),
    )

    def forbidden_parent(
        _self: object,
        _client_pid: int,
        _request: object,
    ) -> dict[str, Any]:
        raise AssertionError("cancel must not reach the base authority dispatcher")

    monkeypatch.setattr(
        "windows_local_mcp.approved_host_service.ApprovedHostAuthorityServer.handle_request",
        forbidden_parent,
    )

    with pytest.raises(PermissionError, match="cancellation is not exposed"):
        server.handle_request(123, {"action": "cancel"})

    assert calls == [
        ("state", tmp_path / "authority"),
        ("service", "S-1-5-21-test"),
    ]
