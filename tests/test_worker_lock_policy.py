from windows_local_mcp.worker import _requires_workspace_execution_lock


def _safe(program_key: str, args: list[str]) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    operation: dict[str, object] = {"tier": "safe_command"}
    request: dict[str, object] = {}
    normalized: dict[str, object] = {"program_key": program_key, "args": args}
    return operation, request, normalized


def test_read_only_safe_commands_do_not_take_workspace_lock() -> None:
    cases = [
        _safe("git", ["--no-pager", "status", "--short"]),
        _safe("flutter", ["analyze", "--no-pub"]),
        _safe("dart", ["analyze"]),
        _safe("dart", ["format", "--output=show", "C:\\workspace\\lib"]),
        _safe("adb", ["devices"]),
    ]
    for operation, request, normalized in cases:
        assert not _requires_workspace_execution_lock(operation, request, normalized)


def test_dart_format_that_writes_original_workspace_keeps_exclusive_lock() -> None:
    operation, request, normalized = _safe(
        "dart", ["format", "C:\\workspace\\lib"]
    )
    assert _requires_workspace_execution_lock(operation, request, normalized)


def test_snapshot_backed_host_execution_does_not_take_workspace_lock() -> None:
    operation: dict[str, object] = {"tier": "host_approval"}
    request: dict[str, object] = {
        "workspace_write": False,
        "approval_manifest_summary": {"mode": "staged-cwd"},
    }
    normalized: dict[str, object] = {"program_key": "python", "args": ["main.py"]}
    assert not _requires_workspace_execution_lock(operation, request, normalized)


def test_host_execution_against_real_workspace_remains_exclusive() -> None:
    operation: dict[str, object] = {"tier": "host_approval"}
    normalized: dict[str, object] = {"program_key": "git", "args": ["checkout", "branch"]}

    assert _requires_workspace_execution_lock(
        operation,
        {
            "workspace_write": True,
            "approval_manifest_summary": {"mode": "source-workspace"},
        },
        normalized,
    )
    assert _requires_workspace_execution_lock(
        operation,
        {
            "workspace_write": False,
            "approval_manifest_summary": {"mode": "git-state-source-workspace"},
        },
        normalized,
    )


def test_old_host_rows_without_snapshot_metadata_fail_conservative() -> None:
    operation: dict[str, object] = {"tier": "host_approval"}
    request: dict[str, object] = {"workspace_write": False}
    normalized: dict[str, object] = {"program_key": "python", "args": ["main.py"]}
    assert _requires_workspace_execution_lock(operation, request, normalized)
