from __future__ import annotations

import pytest

from windows_local_mcp.approved_host_process_census import capture_user_processes


def test_process_census_is_bound_to_explicit_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        def __init__(self, pid: int, username: str, create_time: float) -> None:
            self.pid = pid
            self.info = {
                "pid": pid,
                "username": username,
                "create_time": create_time,
            }

    monkeypatch.setattr(
        "windows_local_mcp.approved_host_process_census.psutil.process_iter",
        lambda _fields: [
            FakeProcess(10, "DOMAIN\\runtime", 1.0),
            FakeProcess(11, "NT AUTHORITY\\SYSTEM", 2.0),
            FakeProcess(12, "domain\\RUNTIME", 3.0),
        ],
    )

    assert capture_user_processes("DOMAIN\\runtime") == {(10, 1.0), (12, 3.0)}
