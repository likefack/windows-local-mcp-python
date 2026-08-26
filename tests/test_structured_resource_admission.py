from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from windows_local_mcp import structured_files
from windows_local_mcp.config import Settings


def _settings(tmp_path: Path, *, elements: int = 100) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    return Settings(
        workspace_root=root,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=False,
        max_structured_elements=elements,
        max_structured_file_bytes=2 * 1024 * 1024,
        max_zip_entries=1000,
        max_zip_expanded_bytes=8 * 1024 * 1024,
    )


def _package(parts: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in parts.items():
            archive.writestr(name, payload)
    return output.getvalue()


def test_csv_cells_are_admitted_before_full_document_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    payload = ((",".join("x" for _ in range(101))) + "\n").encode()

    def fail_string_io(*_args, **_kwargs):
        raise AssertionError("full-document StringIO must not be reached")

    monkeypatch.setattr(structured_files.io, "StringIO", fail_string_io)
    with pytest.raises(structured_files.StructuredFileError, match="CSV cells exceed"):
        structured_files._parse_csv(payload, "csv", settings)


def test_csv_rows_are_admitted_incrementally_even_when_cells_are_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    payload = b"\n" * 101

    def fail_string_io(*_args, **_kwargs):
        raise AssertionError("full-document StringIO must not be reached")

    monkeypatch.setattr(structured_files.io, "StringIO", fail_string_io)
    with pytest.raises(structured_files.StructuredFileError, match="CSV rows exceed"):
        structured_files._parse_csv(payload, "csv", settings)


def test_csv_preflight_does_not_count_delimiters_inside_quoted_fields(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    quoted = ",".join("x" for _ in range(101))
    document = structured_files._parse_csv(f'"{quoted}"\n'.encode(), "csv", settings)
    assert document.rows == [[quoted]]


def test_docx_paragraph_budget_rejects_before_python_docx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    body = "".join("<w:p/>" for _ in range(101))
    payload = _package(
        {
            "word/document.xml": (
                f'<w:document xmlns:w="{structured_files._WORD_NS}"><w:body>{body}</w:body></w:document>'
            ).encode()
        }
    )

    monkeypatch.setattr(
        structured_files,
        "_docx_modules",
        lambda: (_ for _ in ()).throw(AssertionError("python-docx must not be reached")),
    )
    with pytest.raises(structured_files.StructuredFileError, match="DOCX paragraphs exceed"):
        structured_files._inspect_docx(payload, settings)


def test_xlsx_cell_budget_rejects_before_openpyxl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    cells = "".join(f'<c r="A{index}"/>' for index in range(1, 102))
    payload = _package(
        {
            "xl/worksheets/sheet1.xml": (
                f'<worksheet xmlns="{structured_files._SHEET_NS}"><sheetData><row r="1">{cells}</row></sheetData></worksheet>'
            ).encode()
        }
    )

    monkeypatch.setattr(
        structured_files,
        "_xlsx_modules",
        lambda: (_ for _ in ()).throw(AssertionError("openpyxl must not be reached")),
    )
    with pytest.raises(structured_files.StructuredFileError, match="XLSX cells exceed"):
        structured_files._inspect_xlsx(payload, settings)


def test_office_xml_element_budget_rejects_before_tree_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    runs = "".join("<w:r/>" for _ in range(50_001))
    payload = _package(
        {
            "word/styles.xml": (
                f'<w:styles xmlns:w="{structured_files._WORD_NS}">{runs}</w:styles>'
            ).encode()
        }
    )

    monkeypatch.setattr(
        structured_files,
        "_docx_modules",
        lambda: (_ for _ in ()).throw(AssertionError("python-docx must not be reached")),
    )
    with pytest.raises(structured_files.StructuredFileError, match="XML elements exceed"):
        structured_files._inspect_docx(payload, settings)


def test_malformed_office_xml_is_rejected_by_streaming_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    payload = _package(
        {
            "word/document.xml": (
                f'<w:document xmlns:w="{structured_files._WORD_NS}"><w:body><w:p>'
            ).encode()
        }
    )

    monkeypatch.setattr(
        structured_files,
        "_docx_modules",
        lambda: (_ for _ in ()).throw(AssertionError("python-docx must not be reached")),
    )
    with pytest.raises(structured_files.StructuredFileError, match="invalid DOCX XML part"):
        structured_files._inspect_docx(payload, settings)


def test_office_dtd_is_rejected_before_high_level_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    payload = _package(
        {
            "word/document.xml": (
                f'<!DOCTYPE w:document [<!ENTITY x "value">]>'
                f'<w:document xmlns:w="{structured_files._WORD_NS}"><w:body><w:p>&x;</w:p></w:body></w:document>'
            ).encode()
        }
    )

    monkeypatch.setattr(
        structured_files,
        "_docx_modules",
        lambda: (_ for _ in ()).throw(AssertionError("python-docx must not be reached")),
    )
    with pytest.raises(structured_files.StructuredFileError, match="DTD is unsupported"):
        structured_files._inspect_docx(payload, settings)
