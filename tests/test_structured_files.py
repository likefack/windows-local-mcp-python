from __future__ import annotations

import base64
import importlib
import io
import sys
import zipfile
from pathlib import Path

import pytest
from docx import Document
from openpyxl import Workbook, load_workbook
from PIL import Image

from windows_local_mcp.util import sha256_bytes


def load_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(root).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "max_structured_file_bytes = 1048576",
                "max_transfer_chunk_bytes = 4096",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    sys.modules.pop("windows_local_mcp.server", None)
    return importlib.import_module("windows_local_mcp.server"), root


def docx_bytes() -> bytes:
    document = Document()
    document.add_heading("Heading", 1)
    document.add_paragraph("original text")
    table = document.add_table(rows=1, cols=2)
    table.cell(0, 0).text = "A"
    table.cell(0, 1).text = "B"
    output = io.BytesIO()
    document.save(output)
    return output.getvalue()


def xlsx_bytes() -> bytes:
    book = Workbook()
    sheet = book.active
    sheet.title = "Data"
    sheet.append(["Name", "Amount"])
    sheet.append(["A", 2])
    output = io.BytesIO()
    book.save(output)
    return output.getvalue()


def test_docx_xlsx_and_csv_use_the_checkpointed_local_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    (root / "report.docx").write_bytes(docx_bytes())
    before = sha256_bytes((root / "report.docx").read_bytes())
    result = server.structured_file_apply(
        "report.docx",
        [
            {"op": "paragraph_update", "index": 1, "text": "edited text", "format": {"run": {"font_size_pt": 10.5}}},
            {"op": "table_cell_set", "table": 0, "row": 0, "column": 1, "text": "updated"},
            {"op": "metadata_set", "values": {"title": "Updated"}},
        ],
        expected_sha256=before,
        reason="edit report",
    )
    assert result["execution_path"] == "broker_direct"
    assert result["rollback_state"] == "complete"
    record = server.runtime.audit.get_operation(result["operation_id"])
    assert record["tier"] == "broker"
    assert record["child_pid"] is None
    document = Document(root / "report.docx")
    assert document.paragraphs[1].text == "edited text"
    assert document.tables[0].cell(0, 1).text == "updated"
    assert document.core_properties.title == "Updated"

    (root / "table.xlsx").write_bytes(xlsx_bytes())
    result = server.structured_file_apply(
        "table.xlsx",
        [
            {"op": "cell_set", "sheet": "Data", "cell": "C2", "value": "=SUM(B2:B2)"},
            {"op": "format_range", "sheet": "Data", "range": "A1:C1", "format": {"font": {"bold": True}, "fill": "DDEEFF"}},
            {"op": "freeze_panes_set", "sheet": "Data", "cell": "A2"},
            {"op": "autofilter_set", "sheet": "Data", "range": "A1:C2"},
        ],
        expected_sha256=sha256_bytes((root / "table.xlsx").read_bytes()),
    )
    assert result["format"] == "xlsx"
    book = load_workbook(root / "table.xlsx", data_only=False)
    assert book["Data"]["C2"].value == "=SUM(B2:B2)"
    assert book["Data"]["A1"].font.bold is True
    assert book["Data"].freeze_panes == "A2"

    created = server.structured_file_apply(
        "new.csv", [{"op": "row_append", "values": ["name", "value"]}, {"op": "row_append", "values": ["A", "1"]}], reason="create csv"
    )
    assert created["before_bytes"] == 0
    inspected = server.structured_file_inspect("new.csv")
    assert inspected["preview"] == [["name", "value"], ["A", "1"]]
    processing = server.session_info()["structured_file_processing"]
    assert "chatgpt_container" in processing
    assert "broker_direct" in processing
    assert "external-process use alone does not require Codex Sandbox" in processing[
        "external_processing_policy"
    ]


def test_zip_image_and_transfer_boundaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("notes/a.txt", "hello")
    (root / "bundle.zip").write_bytes(archive.getvalue())
    inspected = server.structured_file_inspect("bundle.zip")
    assert inspected["entries"][0]["name"] == "notes/a.txt"
    server.structured_file_apply(
        "bundle.zip",
        [{"op": "entry_add", "name": "notes/b.txt", "text": "world"}],
        expected_sha256=sha256_bytes((root / "bundle.zip").read_bytes()),
    )
    with zipfile.ZipFile(root / "bundle.zip") as output:
        assert output.read("notes/b.txt") == b"world"
    archive_sha = sha256_bytes((root / "bundle.zip").read_bytes())
    extracted = server.zip_entry_extract(
        "bundle.zip", "notes/b.txt", "extracted.txt", expected_archive_sha256=archive_sha
    )
    assert extracted["operation"] == "entry_extract"
    assert (root / "extracted.txt").read_bytes() == b"world"
    assert base64.b64decode(server.zip_entry_read("bundle.zip", "notes/a.txt")["base64"]) == b"hello"
    with pytest.raises(ValueError, match="unsafe ZIP"):
        server.structured_file_apply(
            "bundle.zip",
            [{"op": "entry_add", "name": "../bad", "text": "x"}],
            expected_sha256=sha256_bytes((root / "bundle.zip").read_bytes()),
        )

    image = Image.new("RGB", (2000, 1000), color="red")
    image.save(root / "photo.jpg", exif=b"Exif\x00\x00test")
    result = server.structured_file_apply(
        "photo.jpg",
        [{"op": "resize", "width": 1200, "height": 600}, {"op": "metadata_remove"}, {"op": "quality", "value": 80}],
        expected_sha256=sha256_bytes((root / "photo.jpg").read_bytes()),
    )
    assert result["format"] == "image"
    assert server.structured_file_inspect("photo.jpg")["width"] == 1200

    (root / "download.csv").write_bytes(b"a,b\r\n1,2\r\n")
    download = server.structured_file_download_begin("download.csv", chunk_bytes=4096)
    chunk = server.structured_file_download_chunk(download["transfer_id"], 0)
    assert base64.b64decode(chunk["base64"]) == b"a,b\r\n1,2\r\n"
    payload = b"a,b\r\n3,4\r\n"
    upload = server.structured_file_upload_begin(
        "download.csv", len(payload), sha256_bytes(payload), expected_sha256=download["sha256"]
    )
    server.structured_file_upload_chunk(upload["transfer_id"], 0, base64.b64encode(payload).decode("ascii"))
    committed = server.structured_file_upload_commit(upload["transfer_id"], reason="return edited artifact")
    assert committed["execution_path"] == "transfer"
    assert (root / "download.csv").read_bytes() == payload


def test_transfer_rejects_stale_and_incomplete_uploads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    (root / "source.csv").write_bytes(b"a\n")
    stale = server.structured_file_download_begin("source.csv")
    (root / "source.csv").write_bytes(b"changed\n")
    with pytest.raises(RuntimeError, match="source changed during transfer"):
        server.structured_file_download_chunk(stale["transfer_id"], 0)

    payload = b"complete\n"
    upload = server.structured_file_upload_begin("new.tsv", len(payload), sha256_bytes(payload))
    with pytest.raises(RuntimeError, match="incomplete"):
        server.structured_file_upload_commit(upload["transfer_id"])


def test_existing_structured_edit_requires_source_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    (root / "existing.csv").write_bytes(b"a,b\n1,2\n")
    with pytest.raises(ValueError, match="expected_sha256 is required"):
        server.structured_file_apply(
            "existing.csv",
            [{"op": "cell_set", "row": 1, "column": 1, "value": "3"}],
        )
    assert (root / "existing.csv").read_bytes() == b"a,b\n1,2\n"


def test_binary_mutation_rejects_change_during_transform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "race.csv"
    target.write_bytes(b"original\n")
    before = sha256_bytes(target.read_bytes())

    def transform(source: bytes):
        assert source == b"original\n"
        target.write_bytes(b"manual change\n")
        return b"model edit\n", {"format": "csv"}

    with pytest.raises(RuntimeError, match="stale or concurrently modified"):
        server._atomic_binary_mutation(
            tool_name="test_race",
            path="race.csv",
            expected_sha256=before,
            reason="test",
            request_summary={},
            transform=transform,
            require_expected_for_existing=True,
        )
    assert target.read_bytes() == b"manual change\n"


def test_docx_run_formatting_is_scoped_and_section_size_is_inspectable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    document = Document()
    paragraph = document.add_paragraph()
    first = paragraph.add_run("first")
    second = paragraph.add_run("second")
    first.bold = False
    second.bold = False
    section = document.sections[0]
    section.header.paragraphs[0].text = "header text"
    output = io.BytesIO()
    document.save(output)
    path = root / "runs.docx"
    path.write_bytes(output.getvalue())

    server.structured_file_apply(
        "runs.docx",
        [
            {"op": "run_update", "paragraph": 0, "run": 0, "format": {"bold": True}},
            {"op": "section_set", "section": 0, "page_width_inches": 8.0, "page_height_inches": 10.0},
        ],
        expected_sha256=sha256_bytes(path.read_bytes()),
    )
    edited = Document(path)
    assert edited.paragraphs[0].runs[0].bold is True
    assert edited.paragraphs[0].runs[1].bold is False
    inspected = server.structured_file_inspect("runs.docx")
    assert inspected["sections"][0]["header"][0] == "header text"
    assert inspected["sections"][0]["page_width_inches"] == pytest.approx(8.0, rel=0.01)
    assert inspected["sections"][0]["page_height_inches"] == pytest.approx(10.0, rel=0.01)


def test_zip_preserves_directories_and_rejects_windows_collisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("notes/", b"")
        output.writestr("notes/a.txt", b"a")
    path = root / "paths.zip"
    path.write_bytes(archive.getvalue())

    server.structured_file_apply(
        "paths.zip",
        [{"op": "entry_add", "name": "notes/b.txt", "text": "b"}],
        expected_sha256=sha256_bytes(path.read_bytes()),
    )
    with zipfile.ZipFile(path) as updated:
        assert "notes/" in updated.namelist()
        assert updated.read("notes/b.txt") == b"b"

    with pytest.raises(ValueError, match="already exists"):
        server.structured_file_apply(
            "paths.zip",
            [{"op": "entry_add", "name": "NOTES/A.TXT", "text": "collision"}],
            expected_sha256=sha256_bytes(path.read_bytes()),
        )
    with pytest.raises(ValueError, match="file/directory path collision"):
        server.structured_file_apply(
            "paths.zip",
            [{"op": "entry_add", "name": "notes", "text": "file"}],
            expected_sha256=sha256_bytes(path.read_bytes()),
        )


def test_image_transform_preserves_metadata_and_rejects_unsafe_cases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    image = Image.new("RGB", (32, 32), color="blue")
    exif = Image.Exif()
    exif[0x010E] = "keep me"
    path = root / "metadata.jpg"
    image.save(path, exif=exif)

    server.structured_file_apply(
        "metadata.jpg",
        [{"op": "resize", "width": 16, "height": 16}],
        expected_sha256=sha256_bytes(path.read_bytes()),
    )
    with Image.open(path) as preserved:
        assert preserved.getexif().get(0x010E) == "keep me"

    with pytest.raises(ValueError, match="image pixel count exceeds"):
        server.structured_file_apply(
            "metadata.jpg",
            [{"op": "resize", "width": 100000, "height": 100000}],
            expected_sha256=sha256_bytes(path.read_bytes()),
        )

    first = Image.new("RGB", (10, 10), color="red")
    second = Image.new("RGB", (10, 10), color="green")
    gif_path = root / "animated.gif"
    first.save(gif_path, save_all=True, append_images=[second], loop=0, duration=100)
    with pytest.raises(ValueError, match="multi-frame image transformation is unsupported"):
        server.structured_file_apply(
            "animated.gif",
            [{"op": "resize", "width": 5, "height": 5}],
            expected_sha256=sha256_bytes(gif_path.read_bytes()),
        )
