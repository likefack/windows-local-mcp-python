import base64
import io
import zipfile

import pytest
from test_server_operations import load_server

from windows_local_mcp.performance_trace import MAX_PHASES, validate_timing_payload
from windows_local_mcp.util import sha256_bytes


def checked(server, oid):
    operation = server.runtime.audit.get_operation(oid)
    timing = operation["timings"]
    assert timing is not None
    assert validate_timing_payload(timing) == timing
    assert operation["duration_ms"] == timing["total_ns"] // 1_000_000
    assert 0 < len(timing["phases"]) <= MAX_PHASES
    assert all(p["duration_ns"] >= 0 for p in timing["phases"])
    assert all(p["offset_ns"] + p["duration_ns"] <= timing["total_ns"] for p in timing["phases"])
    assert not any("phase" in e["event_type"] for e in operation["events"])
    return operation


def test_read_write_and_activity_compatibility(tmp_path, monkeypatch):
    server, _root = load_server(tmp_path, monkeypatch)
    result = server.write_file("a.txt", "before")
    operation = checked(server, result["operation_id"])
    names = {p["name"] for p in operation["timings"]["phases"]}
    assert {"checkpoint_before", "checkpoint_after", "transactional_commit"} <= names
    assert operation["rollback_state"] == "complete"
    assert operation["timings"]["failed_phase"] is None
    result = server.read_file("a.txt")
    assert result["content"] == "before"
    operation = checked(server, result["operation_id"])
    assert {"source_read", "decode_parse"} <= {p["name"] for p in operation["timings"]["phases"]}
    timeline = server.activity_timeline()
    assert len([r for r in timeline if r["operation_id"] == result["operation_id"]]) == 1
    assert all("phases" not in r and "timings" not in r for r in timeline)
    assert server.audit_get(result["operation_id"])["timings"] == operation["timings"]
    assert server.activity_get(result["operation_id"])["status"] == "succeeded"


def test_structured_upload_and_zip(tmp_path, monkeypatch):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "a.csv").write_bytes(b"a,b\n1,2\n")
    result = server.structured_file_apply(
        "a.csv",
        [{"op": "cell_set", "row": 1, "column": 1, "value": "3"}],
        expected_sha256=sha256_bytes(b"a,b\n1,2\n"),
    )
    operation = checked(server, result["operation_id"])
    assert "transform" in {p["name"] for p in operation["timings"]["phases"]}
    result = server.structured_file_inspect("a.csv")
    checked(server, result["operation_id"])
    payload = b"binary\x00payload"
    upload = server.artifact_upload_begin("b.bin", len(payload), sha256_bytes(payload))
    server.artifact_upload_chunk(upload["transfer_id"], 0, base64.b64encode(payload).decode())
    result = server.artifact_upload_commit(upload["transfer_id"])
    checked(server, result["operation_id"])
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("entry.txt", b"zip fixture")
    (root / "a.zip").write_bytes(stream.getvalue())
    result = server.zip_extract_many("a.zip", "out", sha256_bytes(stream.getvalue()))
    checked(server, result["operation_id"])
    assert (root / "out" / "entry.txt").read_bytes() == b"zip fixture"


@pytest.mark.parametrize("failure", ["validation", "cas", "transform", "commit", "recovery"])
def test_failure_phase_and_recovery(tmp_path, monkeypatch, failure):
    server, root = load_server(tmp_path, monkeypatch)
    (root / "a.txt").write_bytes(b"before")
    expected = sha256_bytes(b"before")
    wanted = {
        "validation": "request_validation",
        "cas": "cas_recheck",
        "transform": "transform",
        "commit": "transactional_commit",
        "recovery": "checkpoint_after",
    }[failure]
    if failure == "commit":

        def fail_commit(*args, **kwargs):
            raise RuntimeError("injected commit failure")

        monkeypatch.setattr(server.runtime.workspace, "commit_bytes", fail_commit)
    if failure == "recovery":
        original = server.capture_workspace_state

        def fail_checkpoint(settings, oid, stage, **kwargs):
            if stage == "after":
                raise RuntimeError("injected checkpoint failure")
            return original(settings, oid, stage, **kwargs)

        monkeypatch.setattr(server, "capture_workspace_state", fail_checkpoint)
    with pytest.raises((RuntimeError, ValueError)):
        if failure == "transform":
            (root / "a.csv").write_bytes(b"a,b\n")
            server.structured_file_apply(
                "a.csv", [{"op": "not_an_operation"}], expected_sha256=sha256_bytes(b"a,b\n")
            )
        else:
            server.write_file(
                "a.txt",
                "x" * 5000 if failure == "validation" else "after",
                expected_sha256="0" * 64 if failure == "cas" else expected,
            )
    records = server.runtime.audit.list_operations()
    assert records
    operation = checked(server, records[0]["id"])
    assert operation["status"] in {"failed", "rejected"}
    assert operation["timings"]["status"] == "failed"
    assert operation["timings"]["failed_phase"] == wanted
    assert (root / "a.txt").read_bytes() == b"before"
    if failure == "recovery":
        assert operation["rollback_state"] == "failed_recovered"
        assert any(p["name"] == "rollback_recovery" for p in operation["timings"]["phases"])
        assert not server.workspace_recovery_required(server.runtime.settings)
