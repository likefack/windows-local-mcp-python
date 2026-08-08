from windows_local_mcp.approval_ui import _format_activity


def test_live_activity_formats_read_edit_run_and_finish() -> None:
    common = {"updated_at": "2026-08-07T11:00:00+00:00", "request": {}}

    read = _format_activity(
        {
            **common,
            "tool_name": "read_file",
            "status": "succeeded",
            "request": {"path": "lib/main.dart"},
        }
    )
    edited = _format_activity(
        {
            **common,
            "tool_name": "write_file",
            "status": "succeeded",
            "request": {"path": "lib/main.dart"},
        }
    )
    running = _format_activity(
        {
            **common,
            "tool_name": "execute_readonly",
            "status": "running",
            "request": {"safe_request": {"program": "git", "args": ["status", "--short"]}},
        }
    )
    finished = _format_activity(
        {
            **common,
            "tool_name": "execute_readonly",
            "status": "succeeded",
            "request": {"safe_request": {"program": "git", "args": ["status", "--short"]}},
        }
    )

    assert read is not None and "Read" in read and "lib/main.dart" in read
    assert edited is not None and "Edited" in edited and "lib/main.dart" in edited
    assert running is not None and "Running" in running and "git status --short" in running
    assert finished is not None and "Finished" in finished and "[succeeded]" in finished


def test_live_activity_ignores_audit_poll_noise() -> None:
    assert (
        _format_activity(
            {
                "tool_name": "poll_job",
                "status": "succeeded",
                "updated_at": "2026-08-07T11:00:00+00:00",
                "request": {},
            }
        )
        is None
    )
