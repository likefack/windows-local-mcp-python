from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from windows_local_mcp.util import canonical_json, sha256_text
from windows_local_mcp.wfp_guard import (
    GUARD_POLICY_GENERATION,
    GUARD_VERSION,
    WfpGuardError,
)
from windows_local_mcp.wfp_guard_identity import (
    capture_wfp_guard_implementation_identity,
    hold_wfp_guard_implementation,
)


def test_guard_identity_binds_the_actual_imported_module_files() -> None:
    identity = capture_wfp_guard_implementation_identity()
    modules = identity["modules"]

    assert identity["guard_version"] == GUARD_VERSION
    assert identity["policy_generation"] == GUARD_POLICY_GENERATION
    assert identity["digest"] == sha256_text(
        canonical_json({key: value for key, value in identity.items() if key != "digest"})
    )
    assert modules
    for item in modules:
        imported = importlib.import_module(item["name"])
        origin = imported.__spec__.origin if imported.__spec__ is not None else None
        assert origin is not None
        assert Path(item["canonical_path"]) == Path(origin).resolve(strict=True)
        assert len(item["sha256"]) == 64
        assert item["size"] > 0
        assert item["stable_file_identity"]["platform"] in {"windows", "posix"}


def test_guard_identity_hold_rejects_a_stale_manifest() -> None:
    identity = capture_wfp_guard_implementation_identity()
    stale = dict(identity)
    stale["digest"] = "0" * 64

    with (
        pytest.raises(WfpGuardError, match="changed after verification"),
        hold_wfp_guard_implementation(stale),
    ):
        raise AssertionError("stale manifest must not be yielded")


def test_guard_identity_hold_preserves_the_complete_manifest() -> None:
    identity = capture_wfp_guard_implementation_identity()

    with hold_wfp_guard_implementation(identity) as held:
        assert held == identity
