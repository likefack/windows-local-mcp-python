from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

_MUTABLE_CHECKOUT_HOST_TESTS = {
    "test_approval_execution_integration.py",
    "test_approved_host_audit_integrity.py",
}


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    """明示した入れ子のbasetempに必要な親ディレクトリを事前に作成する。"""
    basetemp = config.getoption("basetemp")
    if basetemp is None:
        return
    Path(basetemp).parent.mkdir(parents=True, exist_ok=True)


def _trusted_runtime_evidence() -> dict[str, Any]:
    return {
        "version": 1,
        "scope": "complete-runtime",
        "path_count": 0,
        "file_count": 0,
        "directory_count": 0,
        "ancestor_directory_count": 0,
        "digest": "0" * 64,
        "distributions": [],
    }


@pytest.fixture(autouse=True)
def _isolate_downstream_approved_host_integration(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Let mutable-checkout tests exercise controls after the production runtime gate."""
    if request.path.name not in _MUTABLE_CHECKOUT_HOST_TESTS:
        return
    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",
        _trusted_runtime_evidence,
    )
