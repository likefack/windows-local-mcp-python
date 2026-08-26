from __future__ import annotations

from pathlib import Path

# Trigger the main-branch Windows verification harness after workflow registration.


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected 1 exact match, found {count}")
    return text.replace(old, new, 1)


path = Path("tests/test_sandbox_contract_residual_risks.py")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    'MANDATORY_DESCENDANT_CHECKS = (\n    "child_source_workspace_write_denied",',
    'MANDATORY_DESCENDANT_CHECKS = (\n    "child_source_workspace_read_denied",\n    "child_source_workspace_write_denied",',
    "child source read mandatory check",
)
text = replace_once(
    text,
    '    "grandchild_source_workspace_write_denied",',
    '    "grandchild_source_workspace_read_denied",\n    "grandchild_source_workspace_write_denied",',
    "grandchild source read mandatory check",
)
text = replace_once(
    text,
    '    properties["protected_information_read"] = {"status": "failed"}\n    properties["lan"] = {"status": "failed"}',
    '    properties["lan"] = {"status": "failed"}',
    "protected information is no longer residual",
)
text = replace_once(
    text,
    '        {\n            "child_protected_information_denied": False,\n            "child_lan_denied": False,\n            "grandchild_protected_information_denied": False,\n            "grandchild_lan_denied": False,\n        }',
    '        {\n            "child_protected_information_denied": True,\n            "child_lan_denied": False,\n            "grandchild_protected_information_denied": True,\n            "grandchild_lan_denied": False,\n        }',
    "descendant residual risk checks",
)
text = replace_once(
    text,
    'def test_accepted_workspace_secret_and_lan_failures_do_not_block_route(',
    'def test_only_accepted_lan_failures_do_not_block_route(',
    "residual risk test name",
)
text = replace_once(
    text,
    '    assert accepted["properties"]["protected_information_read"]["status"] == "failed"\n    assert accepted["properties"]["lan"]["status"] == "failed"',
    '    assert accepted["properties"]["protected_information_read"]["status"] == "verified"\n    assert accepted["properties"]["lan"]["status"] == "failed"',
    "accepted property assertions",
)

append = '''\n\ndef test_workspace_protected_information_failure_blocks_route(\n    tmp_path: Path, monkeypatch: pytest.MonkeyPatch\n) -> None:\n    settings = _settings(tmp_path)\n    monkeypatch.setattr(\n        "windows_local_mcp.sandbox_backend.resolve_sandbox_account_identity",\n        _account_identity,\n    )\n    backend = _backend(tmp_path)\n    evidence = _accepted_residual_risk_evidence(settings, backend)\n    properties = evidence["properties"]\n    assert isinstance(properties, dict)\n    properties["protected_information_read"] = {"status": "failed"}\n\n    assert sandbox_live_verification_route_eligible(evidence) is False\n\n    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"\n    marker.write_text(canonical_json(evidence), encoding="utf-8")\n    with pytest.raises(ApprovedSandboxUnavailable, match="missing, failed, or stale"):\n        require_codex_sandbox_live_verification(settings, backend)\n'''
if "def test_workspace_protected_information_failure_blocks_route(" not in text:
    text += append
path.write_text(text, encoding="utf-8", newline="\n")


path = Path("tests/test_mcp_stdio_integration.py")
text = path.read_text(encoding="utf-8")
old = '''            approval = await session.call_tool(
                "request_host_command",
                {
                    "command": [sys.executable, "-c", "print('approval request only')"],
                    "reason": "verify request-only MCP behavior",
                    "risk_summary": "test request must not launch a child process",
                },
            )
'''
new = '''            rejected_project_host = await session.call_tool(
                "request_host_command",
                {
                    "command": [sys.executable, "-c", "print('must stay sandboxed')"],
                    "reason": "verify project-controlled code is rejected from Approved Host",
                    "risk_summary": "test request must fail before approval creation",
                },
            )
            assert rejected_project_host.is_error

            approval = await session.call_tool(
                "request_host_command",
                {
                    "command": [git, "status", "--short"],
                    "reason": "verify explicit approved Git request-only MCP behavior",
                    "risk_summary": "test request must not launch a child process",
                },
            )
'''
text = replace_once(text, old, new, "stdio Approved Host route")
path.write_text(text, encoding="utf-8", newline="\n")


path = Path("tests/test_approval_execution_integration.py")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''    result = executor.launch("snapshot-bound-workspace", 30)\n\n    assert result["status"] == "succeeded"\n''',
    '''    result = executor.launch("snapshot-bound-workspace", 30)\n    operation = store.get_operation("snapshot-bound-workspace")\n\n    assert result["status"] == "succeeded", operation\n''',
    "snapshot success diagnostic",
)
text = replace_once(
    text,
    '''    result = executor.launch("approved-host-legitimate-descendant", 30)\n\n    assert result["status"] == "succeeded"\n''',
    '''    result = executor.launch("approved-host-legitimate-descendant", 30)\n    operation = store.get_operation("approved-host-legitimate-descendant")\n\n    assert result["status"] == "succeeded", operation\n''',
    "descendant success diagnostic",
)
text = replace_once(
    text,
    '''    result = executor.launch("approved-host-descendant-timeout", 10)\n    time.sleep(1.5)\n\n    assert result["status"] == "timed_out"\n''',
    '''    result = executor.launch("approved-host-descendant-timeout", 10)\n    time.sleep(1.5)\n    operation = store.get_operation("approved-host-descendant-timeout")\n\n    assert result["status"] == "timed_out", operation\n''',
    "descendant timeout diagnostic",
)
path.write_text(text, encoding="utf-8", newline="\n")
