from __future__ import annotations

from windows_local_mcp.sandbox_backend import (
    SANDBOX_SECURITY_PROPERTIES,
    sandbox_live_verification_route_eligible,
)
from windows_local_mcp.sandbox_brokered_process import classify_brokered_process_probe
from windows_local_mcp.sandbox_live_verify_hardened import _apply_brokered_process_result


def _verified_properties() -> dict[str, dict[str, object]]:
    return {
        name: {
            "status": "verified",
            "checks": [],
            "failed": [],
            "unverified": [],
            "missing_or_failed": [],
            "reasons": {},
        }
        for name in SANDBOX_SECURITY_PROPERTIES
    }


def test_brokered_probe_requires_explicit_denial() -> None:
    assert classify_brokered_process_probe(
        0, b"WLMCP_BROKERED_PROCESS=DENIED\r\n"
    )[0] is True
    assert classify_brokered_process_probe(
        9, b"WLMCP_BROKERED_PROCESS=REACHABLE\r\n"
    )[0] is False
    assert classify_brokered_process_probe(
        21, b"WLMCP_BROKERED_PROCESS=UNVERIFIED\r\n"
    )[0] is None
    assert classify_brokered_process_probe(0, b"")[0] is None


def test_route_gate_requires_brokered_process_denial() -> None:
    evidence: dict[str, object] = {
        "properties": _verified_properties(),
        "checks": {},
    }
    assert sandbox_live_verification_route_eligible(evidence) is False

    evidence["checks"] = {"brokered_process_creation_denied": True}
    assert sandbox_live_verification_route_eligible(evidence) is True


def test_brokered_reachability_fails_termination_and_resource_bound() -> None:
    result: dict[str, object] = {
        "properties": _verified_properties(),
        "checks": {},
        "diagnostics": {},
        "passed": True,
    }

    _apply_brokered_process_result(
        result,
        False,
        "failed: brokered Win32_Process.Create reached process creation",
    )

    checks = result["checks"]
    assert isinstance(checks, dict)
    assert checks["brokered_process_creation_denied"] is False
    properties = result["properties"]
    assert isinstance(properties, dict)
    for name in ("termination", "resource_bound"):
        item = properties[name]
        assert isinstance(item, dict)
        assert item["status"] == "failed"
        assert "brokered_process_creation_denied" in item["failed"]
        assert "brokered_process_creation_denied" in item["checks"]
    assert result["passed"] is False


def test_ambiguous_brokered_probe_is_unverified_not_verified() -> None:
    result: dict[str, object] = {
        "properties": _verified_properties(),
        "checks": {},
        "diagnostics": {},
        "passed": True,
    }

    _apply_brokered_process_result(
        result,
        None,
        "unverified: brokered Win32_Process.Create denial was not established",
    )

    properties = result["properties"]
    assert isinstance(properties, dict)
    for name in ("termination", "resource_bound"):
        item = properties[name]
        assert isinstance(item, dict)
        assert item["status"] == "unverified"
        assert "brokered_process_creation_denied" in item["unverified"]
    assert result["passed"] is False


def test_explicit_brokered_denial_preserves_existing_verified_properties() -> None:
    result: dict[str, object] = {
        "properties": _verified_properties(),
        "checks": {},
        "diagnostics": {},
        "passed": True,
    }

    _apply_brokered_process_result(
        result,
        True,
        "verified: brokered Win32_Process.Create is explicitly denied",
    )

    properties = result["properties"]
    assert isinstance(properties, dict)
    for name in ("termination", "resource_bound"):
        item = properties[name]
        assert isinstance(item, dict)
        assert item["status"] == "verified"
        assert "brokered_process_creation_denied" in item["checks"]
        assert "brokered_process_creation_denied" not in item["missing_or_failed"]
    assert result["passed"] is True
