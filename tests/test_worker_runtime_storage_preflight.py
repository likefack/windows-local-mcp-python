from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import windows_local_mcp.worker as worker


def test_runtime_storage_preflight_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        worker,
        "_safe_runtime_storage_error",
        lambda *_args, **_kwargs: "safe runtime storage validation failed: ADS",
    )

    with pytest.raises(worker.RuntimeStoragePolicyError, match="ADS"):
        worker._enforce_runtime_storage_preflight(
            tmp_path,
            byte_limit=1024,
            entry_limit=128,
        )


def test_runtime_storage_preflight_occurs_before_codex_launch() -> None:
    source = inspect.getsource(worker.run_operation)

    preflight_index = source.index("_enforce_runtime_storage_preflight(")
    launch_index = source.index("guard_and_launch_codex_sandbox(")

    assert preflight_index < launch_index
