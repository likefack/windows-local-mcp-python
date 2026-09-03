from windows_local_mcp.live_activity import format_activity


def _operation(operation_id: str | None, status: str = "succeeded") -> dict[str, object]:
    operation: dict[str, object] = {
        "tool_name": "write_file",
        "status": status,
        "updated_at": "2026-09-03T06:00:00+00:00",
        "request": {"path": "README.md"},
    }
    if operation_id is not None:
        operation["id"] = operation_id
    return operation


def test_live_activity_displays_full_operation_id_at_end() -> None:
    operation_id = "12345678-1234-5678-9abc-1234567890ab"

    line = format_activity(_operation(operation_id))

    assert line is not None
    operation_tag = f"[op:{operation_id}]"
    assert line.endswith(operation_tag)
    assert line.index("Edited") < line.index("ファイルを編集") < line.index("README.md") < line.index(operation_tag)


def test_live_activity_keeps_operation_id_across_lifecycle() -> None:
    operation_id = "abcdefab-cdef-4abc-8def-abcdefabcdef"

    running = format_activity(_operation(operation_id, status="running"))
    finished = format_activity(_operation(operation_id, status="succeeded"))

    operation_tag = f"[op:{operation_id}]"
    assert running is not None and running.endswith(operation_tag)
    assert finished is not None and finished.endswith(operation_tag)
    assert "Running" in running
    assert "Edited" in finished


def test_live_activity_omits_empty_operation_tag_for_legacy_rows() -> None:
    line = format_activity(_operation(None))

    assert line is not None
    assert "[op:]" not in line
    assert "README.md" in line
