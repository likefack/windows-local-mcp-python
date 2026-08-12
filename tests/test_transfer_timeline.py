from windows_local_mcp.timeline import _transfer_display_state


def _chunk_event(event_type: str, occurred_at: str, result: dict[str, object]) -> dict[str, object]:
    return {
        "event_type": event_type,
        "occurred_at": occurred_at,
        "payload": {"result": result},
    }


def test_download_timeline_stays_transferring_until_all_ranges_are_observed() -> None:
    operation = {
        "tool_name": "artifact_download_begin",
        "status": "succeeded",
        "created_at": "2026-08-13T00:00:00+00:00",
        "updated_at": "2026-08-13T00:00:01+00:00",
        "finished_at": "2026-08-13T00:00:01+00:00",
        "result": {"bytes": 8192},
        "events": [],
    }

    assert _transfer_display_state(operation) == (
        "transferring",
        None,
        "2026-08-13T00:00:00+00:00",
    )

    # Seeing the last chunk alone must not imply that the whole random-access download completed.
    operation["events"] = [
        _chunk_event(
            "artifact_download_chunk",
            "2026-08-13T00:00:02+00:00",
            {"offset": 4096, "bytes": 4096, "complete": True},
        )
    ]
    assert _transfer_display_state(operation) == (
        "transferring",
        None,
        "2026-08-13T00:00:02+00:00",
    )

    operation["events"].append(
        _chunk_event(
            "artifact_download_chunk",
            "2026-08-13T00:00:03+00:00",
            {"offset": 0, "bytes": 4096, "complete": False},
        )
    )
    assert _transfer_display_state(operation) == (
        "succeeded",
        "2026-08-13T00:00:03+00:00",
        "2026-08-13T00:00:03+00:00",
    )


def test_upload_timeline_finishes_on_complete_chunk_event() -> None:
    operation = {
        "tool_name": "artifact_upload_begin",
        "status": "succeeded",
        "created_at": "2026-08-13T00:00:00+00:00",
        "updated_at": "2026-08-13T00:00:01+00:00",
        "finished_at": "2026-08-13T00:00:01+00:00",
        "result": {"total_bytes": 8192},
        "events": [
            _chunk_event(
                "artifact_upload_chunk",
                "2026-08-13T00:00:02+00:00",
                {"received": 4096, "complete": False},
            )
        ],
    }

    assert _transfer_display_state(operation) == (
        "transferring",
        None,
        "2026-08-13T00:00:02+00:00",
    )

    operation["events"].append(
        _chunk_event(
            "artifact_upload_chunk",
            "2026-08-13T00:00:03+00:00",
            {"received": 8192, "complete": True},
        )
    )
    assert _transfer_display_state(operation) == (
        "succeeded",
        "2026-08-13T00:00:03+00:00",
        "2026-08-13T00:00:03+00:00",
    )


def test_empty_transfer_is_complete_at_begin() -> None:
    operation = {
        "tool_name": "artifact_download_begin",
        "status": "succeeded",
        "created_at": "2026-08-13T00:00:00+00:00",
        "updated_at": "2026-08-13T00:00:01+00:00",
        "finished_at": "2026-08-13T00:00:01+00:00",
        "result": {"bytes": 0},
        "events": [],
    }

    assert _transfer_display_state(operation) == (
        "succeeded",
        "2026-08-13T00:00:01+00:00",
        "2026-08-13T00:00:01+00:00",
    )
