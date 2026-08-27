from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from windows_local_mcp.approved_host_authority import (
    AuthorityLaunchResult,
    AuthorityWorkerIdentity,
)
from windows_local_mcp.process_utils import capture_process_identity, creation_flags

_MUTABLE_CHECKOUT_HOST_TESTS = {
    "test_active_config_security_integration.py",
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


class _DownstreamAuthorityStub:
    """Test-only old-style launcher for controls downstream of the production authority."""

    def launch(self, **kwargs: object) -> AuthorityLaunchResult:
        operation_id = str(kwargs["operation_id"])
        context_path = Path(str(kwargs["context_path"]))
        context_sha256 = str(kwargs["context_sha256"])
        process_nonce = str(kwargs["process_nonce"])
        worker_environment = dict(kwargs["worker_environment"])  # type: ignore[arg-type]
        package = Path(__file__).resolve().parents[1] / "src" / "windows_local_mcp"
        source_root = package.parent
        bootstrap = (
            "import runpy,sys;"
            f"sys.path.insert(0,{str(source_root)!r});"
            "runpy.run_module('windows_local_mcp.worker',run_name='__main__')"
        )
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                bootstrap,
                "--operation-id",
                operation_id,
                "--context",
                str(context_path),
                "--context-sha256",
                context_sha256,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=creation_flags(),
            start_new_session=(os.name != "nt"),
            env={str(key): str(value) for key, value in worker_environment.items()},
        )
        identity = capture_process_identity(process.pid, process_nonce)
        return AuthorityLaunchResult(
            worker=AuthorityWorkerIdentity(
                pid=identity.pid,
                create_time=identity.create_time,
                executable=identity.executable,
            ),
            service_epoch="pytest-downstream-authority",
        )

    def probe(self) -> dict[str, object]:
        return {
            "protocol_version": 1,
            "ok": True,
            "healthy": True,
            "service_epoch": "pytest-downstream-authority",
        }


@pytest.fixture(autouse=True)
def _isolate_downstream_approved_host_integration(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise legacy downstream guards without weakening the production authority gate."""
    if request.path.name not in _MUTABLE_CHECKOUT_HOST_TESTS:
        return
    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",
        _trusted_runtime_evidence,
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_authority_available",
        lambda: {
            "healthy": True,
            "service_epoch": "pytest-downstream-authority",
        },
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.ApprovedHostAuthorityClient",
        _DownstreamAuthorityStub,
    )
