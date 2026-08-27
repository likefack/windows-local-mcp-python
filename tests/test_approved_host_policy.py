from __future__ import annotations

import pytest

from windows_local_mcp.approved_host_policy import _service_query_indicates_installed


def test_service_query_accepts_running_or_stopped_installed_service_result() -> None:
    assert _service_query_indicates_installed(0) is True


def test_service_query_treats_only_service_does_not_exist_as_absent() -> None:
    assert _service_query_indicates_installed(1060) is False


@pytest.mark.parametrize("returncode", [1, 5, 87, 1058, 1722])
def test_service_query_other_failures_fail_closed(returncode: int) -> None:
    with pytest.raises(RuntimeError, match="SCM query failed closed"):
        _service_query_indicates_installed(returncode)
