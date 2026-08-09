"""Closed-world, broker-direct structured file transformations.

This module intentionally accepts declarative data only. It never evaluates user-supplied code,
loads a project-controlled helper, or invokes Office. The caller owns workspace path validation,
transactional replacement, and audit. A future external helper may be broker-directed when WLMCP
can close and verify its effective side effects; otherwise it belongs in Codex Sandbox. In either
case it should return an artifact to this boundary rather than writing the workspace itself.
"""

from __future__ import annotations

import base64
import csv
import io
import re
import zipfile
from copy import copy
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any

from .config import Settings
from .util import sha256_bytes

_FORMATS = {"docx", "xlsx", "csv", "tsv", "zip", "image"}
_EXTENSIONS = {
    "docx": {".docx"},
    "xlsx": {".xlsx"},
    "csv": {".csv"},
    "tsv": {".tsv", ".tab"},
    "zip": {".zip"},
    "image": {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"},
}
_ZIP_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


class StructuredFileError(ValueError):
    """A safe, user-actionable rejection of a structured file request."""


def infer_format(path: str, requested: str | None = None) -> str:
    suffix = PureWindowsPath(path).suffix.casefold()
    if requested is not None:
        kind = requested.casefold()
        if kind not in _FORMATS:
            raise StructuredFileError("format must be docx, xlsx, csv, tsv, zip, or image")
        if suffix not in _EXTENSIONS[kind]:
            raise StructuredFileError(f"path extension is not supported for {kind}")
        return kind
    for kind, extensions in _EXTENSIONS.items():
        if suffix in extensions:
            return kind
    raise StructuredFileError("unsupported structured file extension")


def _require_size(data: bytes, settings: Settings) -> None:
    if len(data) > settings.max_structured_file_bytes:
        raise StructuredFileError("structured file exceeds max_structured_file_bytes")


def _dependency(name: str) -> None:
    raise StructuredFileError(
        f"{name} support is unavailable; install the Windows Local MCP structured-file dependencies"
    )


def _docx_modules() -> tuple[Any, Any, Any, Any]:
    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.shared import Inches, Pt, RGBColor
    except ImportError:
        _dependency("DOCX")
    return Document, WD_ORIENT, WD_ALIGN_PARAGRAPH, (Inches, Pt, RGBColor)


def _xlsx_modules() -> tuple[Any, Any, Any, Any, Any, Any, Any, Any, Any]:
    try:
        from openpyxl import Workbook, load_workbook
        from openpyxl.chart import BarChart, LineChart, Reference
        from openpyxl.formatting.rule import CellIsRule
        from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
        from openpyxl.worksheet.datavalidation import DataValidation
    except ImportError:
        _dependency("XLSX")
    return (
        Workbook,
        load_workbook,
        BarChart,
        LineChart,
        Reference,
        CellIsRule,
        (Alignment, Border, Font, PatternFill, Side),
        DataValidation,
        None,
    )


def _image_module() -> Any:
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError:
        _dependency("image")
    return Image, UnidentifiedImageError


def _operation(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or not isinstance(raw.get("op"), str):
        raise StructuredFileError("each operation must be an object with a string op")
    return raw


def _text(value: Any, name: str = "text") -> str:
    if not isinstance(value, str):
        raise StructuredFileError(f"{name} must be a string")
    return value


def _index(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise StructuredFileError(f"{name} must be an integer >= {minimum}")
    return value


def _bounded(items: list[Any], settings: Settings, label: str) -> None:
    if len(items) > settings.max_structured_elements:
        raise StructuredFileError(f"{label} exceeds max_structured_elements")


def _docx_has_unsupported_features(data: bytes) -> list[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = {name.casefold() for name in archive.namelist()}
            document = archive.read("word/document.xml")
            word_xml = [
                archive.read(name)
                for name in archive.namelist()
                if name.casefold().startswith("word/")
                and name.casefold().endswith(".xml")
            ]
    except (KeyError, zipfile.BadZipFile) as error:
        raise StructuredFileError("invalid DOCX package") from error
    found: list[str] = []
    if any("vbaproject.bin" in name for name in names):
        found.append("VBA/macros")
    if any("activex" in name for name in names):
        found.append("ActiveX")
    if any("diagrams/" in name for name in names):
        found.append("SmartArt")
    if any("embeddings/" in name for name in names):
        found.append("embedded objects")
    if any("afchunk" in name for name in names):
        found.append("alternative-format chunks")
    for marker, label in (
        ("word/comments", "comments"),
        ("word/footnotes.xml", "footnotes"),
        ("word/endnotes.xml", "endnotes"),
        ("word/glossary/", "glossary document"),
    ):
        if any(marker in name for name in names):
            found.append(label)
    if any("_xmlsignatures/" in name for name in names):
        found.append("digital signatures")
    if b"<w:ins" in document or b"<w:del" in document or b"<w:move" in document:
        found.append("tracked changes")
    if any(b":dataBinding" in xml for xml in word_xml):
        found.append("custom XML data binding")
    return found


def _paragraph_info(paragraph: Any, index: int) -> dict[str, Any]:
    return {
        "index": index,
        "text": paragraph.text,
        "style": getattr(paragraph.style, "name", None),
        "runs": [
            {"index": run_index, "text": run.text, "bold": run.bold, "italic": run.italic}
            for run_index, run in enumerate(paragraph.runs)
        ],
    }


def _length_inches(value: Any) -> float | None:
    return None if value is None else float(value.inches)


def _inspect_docx(data: bytes, settings: Settings) -> dict[str, Any]:
    Document, _, _, _ = _docx_modules()
    unsupported = _docx_has_unsupported_features(data)
    document = Document(io.BytesIO(data))
    _bounded(document.paragraphs, settings, "DOCX paragraphs")
    tables: list[dict[str, Any]] = []
    for table_index, table in enumerate(document.tables):
        cells = sum(len(row.cells) for row in table.rows)
        if cells > settings.max_structured_elements:
            raise StructuredFileError("DOCX table exceeds max_structured_elements")
        tables.append(
            {
                "index": table_index,
                "rows": len(table.rows),
                "columns": len(table.columns),
                "preview": [[cell.text for cell in row.cells] for row in table.rows[:20]],
            }
        )
    sections = []
    for section_index, section in enumerate(document.sections):
        sections.append(
            {
                "index": section_index,
                "orientation": str(section.orientation),
                "page_width_inches": _length_inches(section.page_width),
                "page_height_inches": _length_inches(section.page_height),
                "margins_inches": {
                    "top": _length_inches(section.top_margin),
                    "bottom": _length_inches(section.bottom_margin),
                    "left": _length_inches(section.left_margin),
                    "right": _length_inches(section.right_margin),
                },
                "header": [paragraph.text for paragraph in section.header.paragraphs[:50]],
                "footer": [paragraph.text for paragraph in section.footer.paragraphs[:50]],
            }
        )
    props = document.core_properties
    return {
        "format": "docx",
        "paragraph_count": len(document.paragraphs),
        "paragraphs": [_paragraph_info(p, i) for i, p in enumerate(document.paragraphs[:200])],
        "table_count": len(document.tables),
        "tables": tables[:50],
        "section_count": len(document.sections),
        "sections": sections,
        "metadata": {key: getattr(props, key) for key in ("title", "subject", "author", "keywords", "comments")},
        "write_rejected_features": unsupported,
        "truncated": len(document.paragraphs) > 200 or len(document.tables) > 50,
    }


def _apply_docx_run_format(run: Any, spec: dict[str, Any]) -> None:
    if not isinstance(spec, dict):
        raise StructuredFileError("run formatting must be an object")
    _, _, _, units = _docx_modules()
    _, Pt, RGBColor = units
    if "font_name" in spec:
        run.font.name = _text(spec["font_name"], "font_name")
    if "font_size_pt" in spec:
        size = spec["font_size_pt"]
        if not isinstance(size, (int, float)) or size <= 0:
            raise StructuredFileError("font_size_pt must be a positive number")
        run.font.size = Pt(size)
    for key, attr in (("bold", "bold"), ("italic", "italic"), ("underline", "underline")):
        if key in spec:
            if not isinstance(spec[key], bool):
                raise StructuredFileError(f"{key} must be boolean")
            setattr(run.font, attr, spec[key])
    if "color" in spec:
        color = _text(spec["color"], "color")
        if not re.fullmatch(r"[0-9A-Fa-f]{6}", color):
            raise StructuredFileError("color must be six hexadecimal digits")
        run.font.color.rgb = RGBColor.from_string(color.upper())


def _apply_docx_format(paragraph: Any, spec: dict[str, Any]) -> None:
    _, _, WD_ALIGN_PARAGRAPH, units = _docx_modules()
    Inches, Pt, _ = units
    if "style" in spec:
        paragraph.style = _text(spec["style"], "style")
    fmt = paragraph.paragraph_format
    if "alignment" in spec:
        value = _text(spec["alignment"], "alignment").upper()
        if not hasattr(WD_ALIGN_PARAGRAPH, value):
            raise StructuredFileError("unsupported paragraph alignment")
        paragraph.alignment = getattr(WD_ALIGN_PARAGRAPH, value)
    for key, attr in (("left_indent_inches", "left_indent"), ("right_indent_inches", "right_indent"), ("first_line_indent_inches", "first_line_indent"), ("space_before_pt", "space_before"), ("space_after_pt", "space_after")):
        if key in spec:
            value = spec[key]
            if not isinstance(value, (int, float)):
                raise StructuredFileError(f"{key} must be a number")
            setattr(fmt, attr, Inches(value) if "indent" in key else Pt(value))
    if "line_spacing" in spec:
        value = spec["line_spacing"]
        if not isinstance(value, (int, float)):
            raise StructuredFileError("line_spacing must be a number")
        fmt.line_spacing = value
    run_spec = spec.get("run")
    if run_spec is not None:
        for run in paragraph.runs:
            _apply_docx_run_format(run, run_spec)


def _docx_paragraphs(document: Any) -> list[Any]:
    paragraphs = list(document.paragraphs)
    for table in document.tables:
        for row in table.rows:
            for cell in row.cells:
                paragraphs.extend(cell.paragraphs)
    for section in document.sections:
        paragraphs.extend(section.header.paragraphs)
        paragraphs.extend(section.footer.paragraphs)
    return paragraphs


def _paragraph_has_complex_inline(paragraph: Any) -> bool:
    xml = paragraph._p.xml
    return any(marker in xml for marker in ("<w:hyperlink", "<w:drawing", "<w:object", "<w:fldChar", "<w:instrText"))


def _cell_has_complex_inline(cell: Any) -> bool:
    return any(_paragraph_has_complex_inline(paragraph) for paragraph in cell.paragraphs)


def _require_docx_bounds(document: Any, settings: Settings) -> None:
    paragraphs = _docx_paragraphs(document)
    if len(paragraphs) > settings.max_structured_elements:
        raise StructuredFileError("DOCX paragraphs exceed max_structured_elements")
    cells = sum(len(row.cells) for table in document.tables for row in table.rows)
    if cells > settings.max_structured_elements:
        raise StructuredFileError("DOCX table cells exceed max_structured_elements")


def _replace_text_preserving_runs(paragraph: Any, search: str, replacement: str) -> int:
    runs = list(paragraph.runs)
    joined = "".join(run.text for run in runs)
    positions: list[int] = []
    start = 0
    while True:
        found = joined.find(search, start)
        if found < 0:
            break
        positions.append(found)
        start = found + len(search)
    for found in reversed(positions):
        end = found + len(search)
        cursor = 0
        first_index = last_index = -1
        first_offset = last_offset = 0
        for index, run in enumerate(runs):
            next_cursor = cursor + len(run.text)
            if first_index < 0 and found < next_cursor:
                first_index, first_offset = index, found - cursor
            if end <= next_cursor:
                last_index, last_offset = index, end - cursor
                break
            cursor = next_cursor
        if first_index < 0 or last_index < 0:
            continue
        if first_index == last_index:
            text = runs[first_index].text
            runs[first_index].text = text[:first_offset] + replacement + text[last_offset:]
        else:
            first_text = runs[first_index].text
            last_text = runs[last_index].text
            runs[first_index].text = first_text[:first_offset] + replacement
            for run in runs[first_index + 1 : last_index]:
                run.text = ""
            runs[last_index].text = last_text[last_offset:]
    return len(positions)


def _apply_docx_cell_format(cell: Any, spec: dict[str, Any]) -> None:
    if not isinstance(spec, dict):
        raise StructuredFileError("cell format must be an object")
    from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    if "vertical_alignment" in spec:
        name = _text(spec["vertical_alignment"], "vertical_alignment").upper()
        if not hasattr(WD_CELL_VERTICAL_ALIGNMENT, name):
            raise StructuredFileError("unsupported cell vertical alignment")
        cell.vertical_alignment = getattr(WD_CELL_VERTICAL_ALIGNMENT, name)
    if "shading" in spec:
        color = _text(spec["shading"], "shading")
        if not re.fullmatch(r"[0-9A-Fa-f]{6}", color):
            raise StructuredFileError("cell shading must be six hexadecimal digits")
        properties = cell._tc.get_or_add_tcPr()
        for existing in properties.findall(qn("w:shd")):
            properties.remove(existing)
        shading = OxmlElement("w:shd")
        shading.set(qn("w:fill"), color.upper())
        properties.append(shading)
    if "paragraph" in spec:
        paragraph_spec = spec["paragraph"]
        if not isinstance(paragraph_spec, dict):
            raise StructuredFileError("cell paragraph format must be an object")
        for paragraph in cell.paragraphs:
            _apply_docx_format(paragraph, paragraph_spec)


def _transform_docx(data: bytes, operations: list[Any], settings: Settings) -> bytes:
    unsupported = _docx_has_unsupported_features(data)
    if unsupported:
        raise StructuredFileError("DOCX write is unsupported with: " + ", ".join(unsupported))
    Document, WD_ORIENT, _, units = _docx_modules()
    Inches, _, _ = units
    document = Document(io.BytesIO(data))
    _require_docx_bounds(document, settings)
    for raw in operations:
        op = _operation(raw)
        name = op["op"]
        if name == "paragraph_append":
            paragraph = document.add_paragraph(_text(op.get("text", "")))
            _apply_docx_format(paragraph, op.get("format", {}))
        elif name == "paragraph_update":
            paragraph = document.paragraphs[_index(op.get("index"), "index")]
            if "text" in op:
                if _paragraph_has_complex_inline(paragraph) and not op.get("allow_inline_loss", False):
                    raise StructuredFileError(
                        "paragraph contains a hyperlink, field, image, or embedded object; "
                        "full-text replacement is unsupported without allow_inline_loss"
                    )
                # This explicit replacement intentionally replaces only the selected paragraph's runs.
                paragraph.clear()
                paragraph.add_run(_text(op["text"]))
            if "format" in op:
                if not isinstance(op["format"], dict):
                    raise StructuredFileError("format must be an object")
                _apply_docx_format(paragraph, op["format"])
        elif name == "paragraph_delete":
            paragraph = document.paragraphs[_index(op.get("index"), "index")]
            paragraph._element.getparent().remove(paragraph._element)
        elif name == "run_update":
            paragraph = document.paragraphs[_index(op.get("paragraph"), "paragraph")]
            run = paragraph.runs[_index(op.get("run"), "run")]
            if "text" in op:
                run.text = _text(op["text"])
            if "format" in op:
                _apply_docx_run_format(run, op["format"])
        elif name == "replace_text":
            search = _text(op.get("search"), "search")
            replacement = _text(op.get("replace"), "replace")
            if not search:
                raise StructuredFileError("search must not be empty")
            count = 0
            for paragraph in _docx_paragraphs(document):
                count += _replace_text_preserving_runs(paragraph, search, replacement)
            if op.get("require_match", False) and count == 0:
                raise StructuredFileError("replace_text found no match")
        elif name == "table_cell_set":
            table = document.tables[_index(op.get("table"), "table")]
            cell = table.cell(_index(op.get("row"), "row"), _index(op.get("column"), "column"))
            if _cell_has_complex_inline(cell) and not op.get("allow_inline_loss", False):
                raise StructuredFileError(
                    "table cell contains a hyperlink, field, image, or embedded object; "
                    "full-text replacement is unsupported without allow_inline_loss"
                )
            cell.text = _text(op.get("text", ""))
            if "format" in op:
                _apply_docx_cell_format(cell, op["format"])
        elif name == "table_row_add":
            table = document.tables[_index(op.get("table"), "table")]
            values = op.get("values", [])
            if not isinstance(values, list) or len(values) > len(table.columns):
                raise StructuredFileError("values must fit in the table columns")
            row = table.add_row()
            for cell, value in zip(row.cells, values, strict=False):
                cell.text = _text(value, "table value")
        elif name == "table_row_insert":
            table = document.tables[_index(op.get("table"), "table")]
            index = _index(op.get("row"), "row")
            if index > len(table.rows):
                raise StructuredFileError("table row index is outside the table")
            values = op.get("values", [])
            if not isinstance(values, list) or len(values) > len(table.columns):
                raise StructuredFileError("values must fit in the table columns")
            row = table.add_row()
            if index < len(table.rows) - 1:
                table.rows[index]._tr.addprevious(row._tr)
            for cell, value in zip(row.cells, values, strict=False):
                cell.text = _text(value, "table value")
        elif name == "table_row_delete":
            table = document.tables[_index(op.get("table"), "table")]
            if len(table.rows) <= 1:
                raise StructuredFileError("cannot delete the last table row")
            row = table.rows[_index(op.get("row"), "row")]
            row._tr.getparent().remove(row._tr)
        elif name == "table_column_add":
            table = document.tables[_index(op.get("table"), "table")]
            width = op.get("width_inches", 1.0)
            if not isinstance(width, (int, float)) or width <= 0:
                raise StructuredFileError("width_inches must be positive")
            column = table.add_column(Inches(width))
            values = op.get("values", [])
            if not isinstance(values, list) or len(values) > len(column.cells):
                raise StructuredFileError("column values must fit in the table rows")
            for index, cell in enumerate(column.cells):
                if index < len(values):
                    cell.text = _text(values[index], "table value")
        elif name == "table_column_delete":
            table = document.tables[_index(op.get("table"), "table")]
            if len(table.columns) <= 1:
                raise StructuredFileError("cannot delete the last table column")
            column = _index(op.get("column"), "column")
            if column >= len(table.columns):
                raise StructuredFileError("table column index is outside the table")
            for row in table.rows:
                row._tr.remove(row.cells[column]._tc)
            grid = table._tbl.tblGrid
            grid.remove(grid.gridCol_lst[column])
        elif name == "table_cell_format":
            table = document.tables[_index(op.get("table"), "table")]
            cell = table.cell(_index(op.get("row"), "row"), _index(op.get("column"), "column"))
            _apply_docx_cell_format(cell, op.get("format", {}))
        elif name == "table_add":
            rows = _index(op.get("rows"), "rows", minimum=1)
            columns = _index(op.get("columns"), "columns", minimum=1)
            if rows * columns > settings.max_structured_elements:
                raise StructuredFileError("new table exceeds max_structured_elements")
            table = document.add_table(rows=rows, cols=columns)
            if "style" in op:
                table.style = _text(op["style"], "style")
            values = op.get("values", [])
            if not isinstance(values, list):
                raise StructuredFileError("table values must be an array")
            for row_index, values_row in enumerate(values):
                if row_index >= rows or not isinstance(values_row, list) or len(values_row) > columns:
                    raise StructuredFileError("table values must fit the requested shape")
                for column_index, value in enumerate(values_row):
                    table.cell(row_index, column_index).text = _text(value, "table value")
        elif name in {"header_footer_append", "header_footer_set"}:
            section = document.sections[_index(op.get("section", 0), "section")]
            area = _text(op.get("area", "header"), "area")
            if area not in {"header", "footer"}:
                raise StructuredFileError("area must be header or footer")
            container = getattr(section, area)
            if name == "header_footer_append":
                container.add_paragraph(_text(op.get("text", "")))
            else:
                index = _index(op.get("paragraph", 0), "paragraph")
                if index >= len(container.paragraphs):
                    raise StructuredFileError("header/footer paragraph index is outside the section")
                paragraph = container.paragraphs[index]
                if _paragraph_has_complex_inline(paragraph) and not op.get("allow_inline_loss", False):
                    raise StructuredFileError("header/footer paragraph contains unsupported inline content")
                paragraph.clear()
                paragraph.add_run(_text(op.get("text", "")))
                if "format" in op:
                    _apply_docx_format(paragraph, op["format"])
        elif name == "style_update":
            style = document.styles[_text(op.get("style"), "style")]
            if "run" in op:
                _apply_docx_run_format(style, op["run"])
            paragraph_values = op.get("paragraph")
            if paragraph_values is not None:
                if not isinstance(paragraph_values, dict):
                    raise StructuredFileError("style paragraph format must be an object")
                _, _, alignments, _style_units = _docx_modules()
                style_format = style.paragraph_format
                if "alignment" in paragraph_values:
                    value = _text(paragraph_values["alignment"], "alignment").upper()
                    if not hasattr(alignments, value):
                        raise StructuredFileError("unsupported paragraph alignment")
                    style_format.alignment = getattr(alignments, value)
                for key, attr in (
                    ("left_indent_inches", "left_indent"),
                    ("right_indent_inches", "right_indent"),
                    ("first_line_indent_inches", "first_line_indent"),
                    ("space_before_pt", "space_before"),
                    ("space_after_pt", "space_after"),
                ):
                    if key in paragraph_values:
                        value = paragraph_values[key]
                        if not isinstance(value, (int, float)):
                            raise StructuredFileError(f"{key} must be a number")
                        setattr(
                            style_format,
                            attr,
                            Inches(value) if "indent" in key else units[1](value),
                        )
        elif name == "metadata_set":
            values = op.get("values")
            if not isinstance(values, dict):
                raise StructuredFileError("metadata values must be an object")
            allowed = {"title", "subject", "author", "keywords", "comments", "category"}
            for key, value in values.items():
                if key not in allowed:
                    raise StructuredFileError(f"unsupported metadata field: {key}")
                setattr(document.core_properties, key, _text(value, key))
        elif name == "section_set":
            section = document.sections[_index(op.get("section", 0), "section")]
            if "orientation" in op:
                orientation = _text(op["orientation"], "orientation").upper()
                if orientation not in {"PORTRAIT", "LANDSCAPE"}:
                    raise StructuredFileError("orientation must be portrait or landscape")
                section.orientation = getattr(WD_ORIENT, orientation)
                section.page_width, section.page_height = section.page_height, section.page_width
            for key, attr in (("page_width_inches", "page_width"), ("page_height_inches", "page_height"), ("top_margin_inches", "top_margin"), ("bottom_margin_inches", "bottom_margin"), ("left_margin_inches", "left_margin"), ("right_margin_inches", "right_margin")):
                if key in op:
                    value = op[key]
                    if not isinstance(value, (int, float)) or value < 0:
                        raise StructuredFileError(f"{key} must be a non-negative number")
                    setattr(section, attr, Inches(value))
        else:
            raise StructuredFileError(f"unsupported DOCX operation: {name}")
        _require_docx_bounds(document, settings)
    output = io.BytesIO()
    document.save(output)
    return output.getvalue()


def _xlsx_unsupported(data: bytes) -> list[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            archive_names = archive.namelist()
            names = {name.casefold() for name in archive_names}
    except zipfile.BadZipFile as error:
        raise StructuredFileError("invalid XLSX package") from error
    blocked = []
    for marker, label in (
        ("vbaproject.bin", "VBA/macros"),
        ("activex", "ActiveX"),
        ("connections.xml", "external data connections"),
        ("slicer", "slicers"),
        ("threadedcomments", "threaded comments"),
        ("persons/", "threaded-comment persons"),
        ("richdata/", "rich data"),
        ("ctrlprops/", "form controls"),
        ("pivottable", "pivot tables"),
        ("pivotcache", "pivot caches"),
        ("embeddings/", "embedded objects"),
        ("customxml/", "custom XML"),
        ("_xmlsignatures/", "digital signatures"),
    ):
        if any(marker in name for name in names):
            blocked.append(label)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in archive_names:
                if not name.casefold().endswith(".xml"):
                    continue
                if re.search(
                    rb"<(?:[A-Za-z0-9_]+:)?extLst\b", archive.read(name)
                ):
                    blocked.append("unsupported extension lists")
                    break
    except (KeyError, zipfile.BadZipFile) as error:
        raise StructuredFileError("invalid XLSX package") from error
    return blocked


def _sheet_cell_count(sheet: Any) -> int:
    return max(1, sheet.max_row) * max(1, sheet.max_column)


def _xlsx_range_bounds(
    value: Any, settings: Settings, label: str = "range"
) -> tuple[str, tuple[int, int, int, int]]:
    from openpyxl.utils.cell import range_boundaries

    reference = _text(value, label)
    try:
        min_col, min_row, max_col, max_row = range_boundaries(reference)
    except (TypeError, ValueError) as error:
        raise StructuredFileError(f"invalid XLSX {label}") from error
    if None in {min_col, min_row, max_col, max_row}:
        raise StructuredFileError(f"XLSX {label} must be an explicit A1 range")
    assert min_col is not None and min_row is not None
    assert max_col is not None and max_row is not None
    if min_col < 1 or min_row < 1 or max_col > 16384 or max_row > 1048576:
        raise StructuredFileError(f"XLSX {label} is outside worksheet limits")
    cells = (max_col - min_col + 1) * (max_row - min_row + 1)
    if cells > settings.max_structured_elements:
        raise StructuredFileError(f"XLSX {label} exceeds max_structured_elements")
    return reference, (min_col, min_row, max_col, max_row)


def _require_xlsx_extent(sheet: Any, bounds: tuple[int, int, int, int], settings: Settings) -> None:
    _min_col, _min_row, max_col, max_row = bounds
    if max(max_col, sheet.max_column) * max(max_row, sheet.max_row) > settings.max_structured_elements:
        raise StructuredFileError("XLSX edit would exceed max_structured_elements")


def _inspect_xlsx(data: bytes, settings: Settings, range_ref: str | None = None) -> dict[str, Any]:
    _, load_workbook, *_ = _xlsx_modules()
    book = load_workbook(io.BytesIO(data), read_only=True, data_only=False, keep_links=True)
    try:
        sheets = []
        total = 0
        for sheet in book.worksheets:
            cells = _sheet_cell_count(sheet)
            total += cells
            if total > settings.max_structured_elements:
                raise StructuredFileError("XLSX cells exceed max_structured_elements")
            preview_range = range_ref if range_ref and sheet.title == book.active.title else f"A1:{sheet.cell(min(sheet.max_row, 20), min(sheet.max_column, 20)).coordinate}"
            try:
                preview_range, _ = _xlsx_range_bounds(
                    preview_range, settings, "preview range"
                )
                rows = [[cell.value for cell in row] for row in sheet[preview_range]]
            except ValueError as error:
                raise StructuredFileError("invalid XLSX range") from error
            sheets.append({"name": sheet.title, "state": sheet.sheet_state, "max_row": sheet.max_row, "max_column": sheet.max_column, "preview_range": preview_range, "values": rows})
        return {"format": "xlsx", "sheets": sheets, "write_rejected_features": _xlsx_unsupported(data)}
    finally:
        book.close()


def _xlsx_cell_format(cell: Any, spec: dict[str, Any], styles: Any) -> None:
    Alignment, Border, _Font, PatternFill, Side = styles
    if "font" in spec:
        values = spec["font"]
        if not isinstance(values, dict):
            raise StructuredFileError("font must be an object")
        allowed = {"name", "size", "bold", "italic", "underline", "color"}
        if set(values) - allowed:
            raise StructuredFileError("unsupported font option")
        font = copy(cell.font)
        for key, value in values.items():
            setattr(font, key, value)
        cell.font = font
    if "fill" in spec:
        color = _text(spec["fill"], "fill")
        if not re.fullmatch(r"[0-9A-Fa-f]{6}", color):
            raise StructuredFileError("fill must be six hexadecimal digits")
        cell.fill = PatternFill("solid", fgColor=color.upper())
    if "alignment" in spec:
        values = spec["alignment"]
        if not isinstance(values, dict):
            raise StructuredFileError("alignment must be an object")
        cell.alignment = Alignment(**values)
    if "number_format" in spec:
        cell.number_format = _text(spec["number_format"], "number_format")
    if "border" in spec:
        color = _text(spec["border"], "border")
        side = Side(style="thin", color=color)
        cell.border = Border(left=side, right=side, top=side, bottom=side)


def _transform_xlsx(data: bytes, operations: list[Any], settings: Settings) -> bytes:
    unsupported = _xlsx_unsupported(data)
    if unsupported:
        raise StructuredFileError("XLSX write is unsupported with: " + ", ".join(unsupported))
    Workbook, load_workbook, BarChart, LineChart, Reference, CellIsRule, styles, DataValidation, _ = _xlsx_modules()
    del Workbook
    book = load_workbook(io.BytesIO(data), data_only=False, keep_links=True)
    try:
        if sum(_sheet_cell_count(sheet) for sheet in book.worksheets) > settings.max_structured_elements:
            raise StructuredFileError("XLSX cells exceed max_structured_elements")
        for raw in operations:
            op = _operation(raw)
            name = op["op"]
            if name == "sheet_add":
                title = _text(op.get("title"), "title")
                book.create_sheet(title)
            elif name == "sheet_remove":
                sheet = book[_text(op.get("sheet"), "sheet")]
                if len(book.worksheets) == 1:
                    raise StructuredFileError("cannot remove the last worksheet")
                book.remove(sheet)
            elif name == "sheet_rename":
                book[_text(op.get("sheet"), "sheet")].title = _text(op.get("title"), "title")
            elif name == "sheet_copy":
                copied = book.copy_worksheet(book[_text(op.get("sheet"), "sheet")])
                if "title" in op:
                    copied.title = _text(op["title"], "title")
            elif name == "sheet_move":
                sheet = book[_text(op.get("sheet"), "sheet")]
                position = _index(op.get("position"), "position")
                if position >= len(book.worksheets):
                    raise StructuredFileError("sheet position is outside the workbook")
                current = book.index(sheet)
                book.move_sheet(sheet, offset=position - current)
            else:
                sheet = book[_text(op.get("sheet"), "sheet")]
                if name == "cell_set":
                    cell_ref, bounds = _xlsx_range_bounds(op.get("cell"), settings, "cell")
                    if bounds[0] != bounds[2] or bounds[1] != bounds[3]:
                        raise StructuredFileError("cell must identify exactly one XLSX cell")
                    _require_xlsx_extent(sheet, bounds, settings)
                    cell = sheet[cell_ref]
                    cell.value = op.get("value")
                    if "format" in op:
                        _xlsx_cell_format(cell, op["format"], styles)
                elif name == "range_set":
                    range_ref, bounds = _xlsx_range_bounds(op.get("range"), settings)
                    _require_xlsx_extent(sheet, bounds, settings)
                    start = sheet[range_ref]
                    values = op.get("values")
                    if not isinstance(values, list) or not all(isinstance(row, list) for row in values):
                        raise StructuredFileError("values must be a two-dimensional array")
                    rows = list(start) if isinstance(start, tuple) else ((start,),)
                    if len(values) != len(rows) or any(len(value_row) != len(cells) for value_row, cells in zip(values, rows, strict=False)):
                        raise StructuredFileError("values shape must match range")
                    for value_row, cells in zip(values, rows, strict=False):
                        for value, cell in zip(value_row, cells, strict=False):
                            cell.value = value
                elif name == "range_clear":
                    range_ref, bounds = _xlsx_range_bounds(op.get("range"), settings)
                    _require_xlsx_extent(sheet, bounds, settings)
                    for row in sheet[range_ref]:
                        for cell in row:
                            cell.value = None
                elif name in {"range_copy", "range_fill"}:
                    from openpyxl.formula.translate import Translator
                    _, source_bounds = _xlsx_range_bounds(op.get("source"), settings, "source")
                    _, target_bounds = _xlsx_range_bounds(op.get("target"), settings, "target")
                    source_min_col, source_min_row, source_max_col, source_max_row = source_bounds
                    target_min_col, target_min_row, target_max_col, target_max_row = target_bounds
                    _require_xlsx_extent(sheet, target_bounds, settings)
                    source_rows = source_max_row - source_min_row + 1
                    source_cols = source_max_col - source_min_col + 1
                    target_rows = target_max_row - target_min_row + 1
                    target_cols = target_max_col - target_min_col + 1
                    if name == "range_copy" and (source_rows, source_cols) != (target_rows, target_cols):
                        raise StructuredFileError("range_copy source and target shapes must match")
                    copy_format = bool(op.get("copy_format", True))
                    for row_offset in range(target_rows):
                        for column_offset in range(target_cols):
                            source_row = source_min_row + (row_offset % source_rows)
                            source_column = source_min_col + (column_offset % source_cols)
                            source_cell = sheet.cell(source_row, source_column)
                            target_cell = sheet.cell(target_min_row + row_offset, target_min_col + column_offset)
                            value = source_cell.value
                            if isinstance(value, str) and value.startswith("="):
                                value = Translator(value, origin=source_cell.coordinate).translate_formula(target_cell.coordinate)
                            target_cell.value = value
                            if copy_format:
                                target_cell._style = copy(source_cell._style)
                                target_cell.number_format = source_cell.number_format
                                target_cell.protection = copy(source_cell.protection)
                elif name in {"rows_insert", "rows_delete", "columns_insert", "columns_delete"}:
                    index = _index(op.get("index"), "index", minimum=1)
                    amount = _index(op.get("amount", 1), "amount", minimum=1)
                    if amount > settings.max_structured_elements:
                        raise StructuredFileError("row or column amount exceeds max_structured_elements")
                    projected_rows = sheet.max_row + amount if name == "rows_insert" else sheet.max_row
                    projected_columns = sheet.max_column + amount if name == "columns_insert" else sheet.max_column
                    if projected_rows * projected_columns > settings.max_structured_elements:
                        raise StructuredFileError("XLSX edit would exceed max_structured_elements")
                    getattr(sheet, name.replace("rows_", "").replace("columns_", "") + ("_rows" if name.startswith("rows") else "_cols"))(index, amount)
                elif name == "merge":
                    range_ref, bounds = _xlsx_range_bounds(op.get("range"), settings)
                    _require_xlsx_extent(sheet, bounds, settings)
                    sheet.merge_cells(range_ref)
                elif name == "unmerge":
                    range_ref, _ = _xlsx_range_bounds(op.get("range"), settings)
                    sheet.unmerge_cells(range_ref)
                elif name == "format_range":
                    spec = op.get("format")
                    if not isinstance(spec, dict):
                        raise StructuredFileError("format must be an object")
                    range_ref, bounds = _xlsx_range_bounds(op.get("range"), settings)
                    _require_xlsx_extent(sheet, bounds, settings)
                    for row in sheet[range_ref]:
                        for cell in row:
                            _xlsx_cell_format(cell, spec, styles)
                elif name == "dimensions_set":
                    if "row" in op:
                        dimension = sheet.row_dimensions[_index(op["row"], "row", minimum=1)]
                    elif "column" in op:
                        dimension = sheet.column_dimensions[_text(op["column"], "column")]
                    else:
                        raise StructuredFileError("dimensions_set needs row or column")
                    if "size" in op:
                        if not isinstance(op["size"], (int, float)) or op["size"] <= 0:
                            raise StructuredFileError("size must be positive")
                        dimension.height = op["size"] if "row" in op else None
                        dimension.width = op["size"] if "column" in op else None
                    if "hidden" in op:
                        if not isinstance(op["hidden"], bool):
                            raise StructuredFileError("hidden must be boolean")
                        dimension.hidden = op["hidden"]
                elif name == "freeze_panes_set":
                    cell_ref, bounds = _xlsx_range_bounds(op.get("cell"), settings, "cell")
                    if bounds[0] != bounds[2] or bounds[1] != bounds[3]:
                        raise StructuredFileError("freeze pane must identify one cell")
                    sheet.freeze_panes = cell_ref
                elif name == "autofilter_set":
                    range_ref, _ = _xlsx_range_bounds(op.get("range"), settings)
                    sheet.auto_filter.ref = range_ref
                elif name == "table_add":
                    from openpyxl.worksheet.table import Table, TableStyleInfo
                    range_ref, bounds = _xlsx_range_bounds(op.get("range"), settings)
                    _require_xlsx_extent(sheet, bounds, settings)
                    table = Table(displayName=_text(op.get("name"), "name"), ref=range_ref)
                    table.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True)
                    sheet.add_table(table)
                elif name == "validation_add":
                    validation = DataValidation(type=_text(op.get("type", "list"), "type"), formula1=_text(op.get("formula1"), "formula1"), allow_blank=bool(op.get("allow_blank", True)))
                    sheet.add_data_validation(validation)
                    range_ref, _ = _xlsx_range_bounds(op.get("range"), settings)
                    validation.add(range_ref)
                elif name == "conditional_cell_is":
                    color = _text(op.get("fill"), "fill")
                    rule = CellIsRule(operator=_text(op.get("operator"), "operator"), formula=[_text(op.get("formula"), "formula")], fill=styles[3]("solid", fgColor=color))
                    range_ref, _ = _xlsx_range_bounds(op.get("range"), settings)
                    sheet.conditional_formatting.add(range_ref, rule)
                elif name == "chart_add":
                    chart_type = _text(op.get("type", "bar"), "type")
                    if chart_type not in {"bar", "line"}:
                        raise StructuredFileError("chart type must be bar or line")
                    chart = BarChart() if chart_type == "bar" else LineChart()
                    _data_range, bounds = _xlsx_range_bounds(
                        op.get("data_range"), settings, "data range"
                    )
                    min_col, min_row, max_col, max_row = bounds
                    data_ref = Reference(
                        sheet,
                        min_col=min_col,
                        min_row=min_row,
                        max_col=max_col,
                        max_row=max_row,
                    )
                    chart.add_data(data_ref, titles_from_data=bool(op.get("titles_from_data", True)))
                    anchor, anchor_bounds = _xlsx_range_bounds(
                        op.get("anchor", "E2"), settings, "anchor"
                    )
                    if anchor_bounds[0] != anchor_bounds[2] or anchor_bounds[1] != anchor_bounds[3]:
                        raise StructuredFileError("chart anchor must identify one cell")
                    sheet.add_chart(chart, anchor)
                elif name == "page_setup_set":
                    values = op.get("values")
                    if not isinstance(values, dict):
                        raise StructuredFileError("page setup values must be an object")
                    for key in ("orientation", "paperSize", "fitToWidth", "fitToHeight"):
                        if key in values:
                            setattr(sheet.page_setup, key, values[key])
                else:
                    raise StructuredFileError(f"unsupported XLSX operation: {name}")
            if sum(_sheet_cell_count(item) for item in book.worksheets) > settings.max_structured_elements:
                raise StructuredFileError("XLSX cells exceed max_structured_elements")
        output = io.BytesIO()
        book.save(output)
        return output.getvalue()
    finally:
        book.close()


@dataclass
class CsvDocument:
    rows: list[list[str]]
    encoding: str
    codec: str
    bom: bytes
    dialect: csv.Dialect
    newline: str
    final_newline: bool


def _parse_csv(data: bytes, kind: str, settings: Settings) -> CsvDocument:
    if len(data) > settings.max_structured_file_bytes:
        _require_size(data, settings)
    if data.startswith(b"\xef\xbb\xbf"):
        encoding, codec, bom = "utf-8-sig", "utf-8", b"\xef\xbb\xbf"
    elif data.startswith(b"\xff\xfe"):
        encoding, codec, bom = "utf-16-le", "utf-16-le", b"\xff\xfe"
    elif data.startswith(b"\xfe\xff"):
        encoding, codec, bom = "utf-16-be", "utf-16-be", b"\xfe\xff"
    else:
        encoding, codec, bom = "utf-8", "utf-8", b""
    try:
        text = data[len(bom) :].decode(codec)
    except UnicodeDecodeError as error:
        raise StructuredFileError("CSV/TSV encoding is unsupported or invalid") from error
    without_crlf = text.replace("\r\n", "")
    if "\r" in without_crlf or ("\r\n" in text and "\n" in without_crlf):
        raise StructuredFileError("CSV/TSV contains mixed or ambiguous newline sequences")
    sample = text[:8192]
    if kind == "tsv":
        if "\t" not in sample and any(marker in sample for marker in (",", ";", "|")):
            raise StructuredFileError("TSV delimiter identity is ambiguous")
        dialect = csv.excel_tab
    else:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error as error:
            if any(marker in sample for marker in (",", ";", "\t", "|")):
                raise StructuredFileError("CSV delimiter identity is ambiguous") from error
            dialect = csv.excel  # A delimiter-free document is an unambiguous single column.
    rows = list(csv.reader(io.StringIO(text, newline=""), dialect))
    _bounded(rows, settings, "CSV rows")
    if sum(len(row) for row in rows) > settings.max_structured_elements:
        raise StructuredFileError("CSV cells exceed max_structured_elements")
    newline = "\r\n" if "\r\n" in text else "\n"
    return CsvDocument(rows, encoding, codec, bom, dialect, newline, text.endswith(("\r\n", "\n")))


def _inspect_csv(data: bytes, kind: str, settings: Settings) -> dict[str, Any]:
    document = _parse_csv(data, kind, settings)
    return {"format": kind, "encoding": document.encoding, "delimiter": document.dialect.delimiter, "quotechar": document.dialect.quotechar, "doublequote": document.dialect.doublequote, "escapechar": document.dialect.escapechar, "newline": document.newline, "final_newline": document.final_newline, "rows": len(document.rows), "columns": max((len(row) for row in document.rows), default=0), "preview": document.rows[:200], "truncated": len(document.rows) > 200}


def _require_csv_bounds(document: CsvDocument, settings: Settings) -> None:
    _bounded(document.rows, settings, "CSV rows")
    if sum(len(row) for row in document.rows) > settings.max_structured_elements:
        raise StructuredFileError("CSV cells exceed max_structured_elements")


def _transform_csv(data: bytes, kind: str, operations: list[Any], settings: Settings) -> bytes:
    document = _parse_csv(data, kind, settings) if data else CsvDocument([], "utf-8", "utf-8", b"", csv.excel_tab if kind == "tsv" else csv.excel, "\n", True)
    for raw in operations:
        op = _operation(raw)
        name = op["op"]
        if name == "cell_set":
            row = _index(op.get("row"), "row")
            column = _index(op.get("column"), "column")
            if row >= settings.max_structured_elements or column >= settings.max_structured_elements:
                raise StructuredFileError("CSV cell index exceeds max_structured_elements")
            existing_length = len(document.rows[row]) if row < len(document.rows) else 0
            current_cells = sum(len(item) for item in document.rows)
            if current_cells - existing_length + max(existing_length, column + 1) > settings.max_structured_elements:
                raise StructuredFileError("CSV edit would exceed max_structured_elements")
            while len(document.rows) <= row:
                document.rows.append([])
            while len(document.rows[row]) <= column:
                document.rows[row].append("")
            document.rows[row][column] = _text(op.get("value", ""), "value")
        elif name == "row_append":
            values = op.get("values")
            if not isinstance(values, list):
                raise StructuredFileError("values must be an array")
            if len(values) > settings.max_structured_elements:
                raise StructuredFileError("CSV row exceeds max_structured_elements")
            if sum(len(row) for row in document.rows) + len(values) > settings.max_structured_elements:
                raise StructuredFileError("CSV edit would exceed max_structured_elements")
            document.rows.append([_text(value, "value") for value in values])
        elif name == "row_insert":
            row = _index(op.get("row"), "row")
            if row > len(document.rows):
                raise StructuredFileError("row_insert index is outside the document")
            values = op.get("values", [])
            if not isinstance(values, list):
                raise StructuredFileError("values must be an array")
            if len(values) > settings.max_structured_elements:
                raise StructuredFileError("CSV row exceeds max_structured_elements")
            if sum(len(item) for item in document.rows) + len(values) > settings.max_structured_elements:
                raise StructuredFileError("CSV edit would exceed max_structured_elements")
            document.rows.insert(row, [_text(value, "value") for value in values])
        elif name == "row_set":
            row = _index(op.get("row"), "row")
            values = op.get("values")
            if not isinstance(values, list):
                raise StructuredFileError("values must be an array")
            if len(values) > settings.max_structured_elements:
                raise StructuredFileError("CSV row exceeds max_structured_elements")
            if (
                sum(len(item) for item in document.rows)
                - len(document.rows[row])
                + len(values)
                > settings.max_structured_elements
            ):
                raise StructuredFileError("CSV edit would exceed max_structured_elements")
            document.rows[row] = [_text(value, "value") for value in values]
        elif name == "row_delete":
            del document.rows[_index(op.get("row"), "row")]
        elif name == "column_insert":
            column = _index(op.get("column"), "column")
            if column >= settings.max_structured_elements:
                raise StructuredFileError("CSV column index exceeds max_structured_elements")
            if sum(len(row) for row in document.rows) + len(document.rows) > settings.max_structured_elements:
                raise StructuredFileError("CSV edit would exceed max_structured_elements")
            value = _text(op.get("default", ""), "default")
            for row in document.rows:
                row.insert(min(column, len(row)), value)
        elif name == "column_delete":
            column = _index(op.get("column"), "column")
            if column >= settings.max_structured_elements:
                raise StructuredFileError("CSV column index exceeds max_structured_elements")
            for row in document.rows:
                if column < len(row):
                    del row[column]
        elif name == "column_append":
            values = op.get("values", [])
            if not isinstance(values, list) or len(values) > len(document.rows):
                raise StructuredFileError("column values must fit the existing rows")
            if sum(len(row) for row in document.rows) + len(document.rows) > settings.max_structured_elements:
                raise StructuredFileError("CSV edit would exceed max_structured_elements")
            for index, row in enumerate(document.rows):
                row.append(_text(values[index], "value") if index < len(values) else "")
        else:
            raise StructuredFileError(f"unsupported CSV operation: {name}")
        _require_csv_bounds(document, settings)
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, document.dialect, lineterminator=document.newline)
    writer.writerows(document.rows)
    rendered = stream.getvalue()
    if not document.final_newline and rendered.endswith(document.newline):
        rendered = rendered[: -len(document.newline)]
    output = document.bom + rendered.encode(document.codec)
    _require_size(output, settings)
    return output


def _safe_zip_name(name: str) -> str:
    candidate = name.replace("\\", "/")
    path = PureWindowsPath(candidate)
    if not candidate or candidate.startswith(("/", "\\")) or path.is_absolute() or ":" in candidate:
        raise StructuredFileError("ZIP entry path must be relative and not use ADS")
    parts = [part for part in candidate.split("/") if part]
    if not parts or any(part in {".", ".."} or part.endswith((" ", ".")) for part in parts):
        raise StructuredFileError("unsafe ZIP entry path")
    if any(part.split(".", 1)[0].upper() in _ZIP_RESERVED for part in parts):
        raise StructuredFileError("ZIP entry uses a Windows reserved device name")
    return "/".join(parts)


def _validate_zip_paths(paths: list[tuple[str, bool]]) -> None:
    seen: dict[str, bool] = {}
    files: set[str] = set()
    normalized: list[tuple[str, bool]] = []
    for name, is_directory in paths:
        safe = _safe_zip_name(name)
        folded = safe.casefold()
        if folded in seen and seen[folded] != is_directory:
            raise StructuredFileError("ZIP contains a file/directory path collision")
        if folded in seen:
            raise StructuredFileError("ZIP contains duplicate or colliding entry names")
        seen[folded] = is_directory
        normalized.append((safe, is_directory))
        if not is_directory:
            files.add(folded)
    for name, _ in normalized:
        parts = name.casefold().split("/")
        for end in range(1, len(parts)):
            if "/".join(parts[:end]) in files:
                raise StructuredFileError("ZIP contains a file/directory path collision")


def _zip_entries(data: bytes, settings: Settings) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        raise StructuredFileError("invalid ZIP archive") from error
    entries = archive.infolist()
    if len(entries) > settings.max_zip_entries:
        archive.close()
        raise StructuredFileError("ZIP entry count exceeds max_zip_entries")
    try:
        _validate_zip_paths([(info.filename, info.is_dir()) for info in entries])
    except Exception:
        archive.close()
        raise
    expanded = sum(info.file_size for info in entries)
    if expanded > settings.max_zip_expanded_bytes:
        archive.close()
        raise StructuredFileError("ZIP expanded size exceeds max_zip_expanded_bytes")
    if any(info.file_size > settings.max_zip_expanded_bytes for info in entries):
        archive.close()
        raise StructuredFileError("ZIP entry expanded size exceeds max_zip_expanded_bytes")
    if any(info.flag_bits & 0x1 for info in entries):
        archive.close()
        raise StructuredFileError("encrypted ZIP entries are unsupported")
    return archive, entries


def _inspect_zip(data: bytes, settings: Settings) -> dict[str, Any]:
    archive, entries = _zip_entries(data, settings)
    try:
        return {"format": "zip", "entry_count": len(entries), "expanded_bytes": sum(info.file_size for info in entries), "entries": [{"name": _safe_zip_name(info.filename), "compressed_bytes": info.compress_size, "bytes": info.file_size, "is_directory": info.is_dir()} for info in entries[:500]], "truncated": len(entries) > 500}
    finally:
        archive.close()


def read_zip_entry(data: bytes, name: str, settings: Settings) -> bytes:
    """Return one prevalidated entry without writing it anywhere."""
    safe_name = _safe_zip_name(name)
    archive, entries = _zip_entries(data, settings)
    try:
        matches = [info for info in entries if not info.is_dir() and _safe_zip_name(info.filename).casefold() == safe_name.casefold()]
        if len(matches) != 1:
            raise StructuredFileError("ZIP entry was not found")
        payload = archive.read(matches[0])
        if len(payload) != matches[0].file_size:
            raise StructuredFileError("ZIP entry size verification failed")
        return payload
    finally:
        archive.close()


def read_zip_entries(
    data: bytes, names: list[str] | None, settings: Settings
) -> dict[str, bytes]:
    """Return a fully validated, bounded set of files for transactional extraction."""
    archive, entries = _zip_entries(data, settings)
    try:
        requested = None if names is None else {_safe_zip_name(name).casefold() for name in names}
        result: dict[str, bytes] = {}
        for info in entries:
            if info.is_dir():
                continue
            safe = _safe_zip_name(info.filename)
            if requested is not None and safe.casefold() not in requested:
                continue
            payload = archive.read(info)
            if len(payload) != info.file_size:
                raise StructuredFileError("ZIP entry size verification failed")
            result[safe] = payload
        if requested is not None and {name.casefold() for name in result} != requested:
            raise StructuredFileError("one or more ZIP entries were not found")
        return result
    finally:
        archive.close()


def _zip_payload(op: dict[str, Any]) -> bytes:
    if "text" in op:
        return _text(op["text"], "text").encode("utf-8")
    if "base64" in op:
        try:
            return base64.b64decode(_text(op["base64"], "base64"), validate=True)
        except ValueError as error:
            raise StructuredFileError("base64 must be valid") from error
    raise StructuredFileError("ZIP entry operation needs text or base64")


def _matching_zip_key(entries: dict[str, tuple[zipfile.ZipInfo | None, bytes]], name: str) -> str | None:
    folded = name.casefold()
    for existing in entries:
        if existing.casefold() == folded:
            return existing
    return None


def _transform_zip(data: bytes, operations: list[Any], settings: Settings) -> bytes:
    entries: dict[str, tuple[zipfile.ZipInfo | None, bytes]] = {}
    directories: list[zipfile.ZipInfo] = []
    if data:
        archive, infos = _zip_entries(data, settings)
        try:
            for info in infos:
                if info.is_dir():
                    directories.append(copy(info))
                else:
                    entries[_safe_zip_name(info.filename)] = (info, archive.read(info))
        finally:
            archive.close()
    for raw in operations:
        op = _operation(raw)
        name = op["op"]
        if name in {"entry_add", "entry_replace"}:
            entry = _safe_zip_name(_text(op.get("name"), "name"))
            existing = _matching_zip_key(entries, entry)
            if name == "entry_add":
                if existing is not None:
                    raise StructuredFileError("ZIP entry already exists")
                entries[entry] = (None, _zip_payload(op))
            else:
                if existing is None:
                    raise StructuredFileError("ZIP entry does not exist")
                entries[existing] = (None, _zip_payload(op))
        elif name == "entry_delete":
            entry = _safe_zip_name(_text(op.get("name"), "name"))
            existing = _matching_zip_key(entries, entry)
            if existing is None:
                raise StructuredFileError("ZIP entry does not exist")
            del entries[existing]
        else:
            raise StructuredFileError(f"unsupported ZIP operation: {name}")
    _validate_zip_paths(
        [(info.filename, True) for info in directories] + [(name, False) for name in entries]
    )
    if len(entries) + len(directories) > settings.max_zip_entries or sum(len(value[1]) for value in entries.values()) > settings.max_zip_expanded_bytes:
        raise StructuredFileError("resulting ZIP exceeds configured limits")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as archive:
        for info in directories:
            archive.writestr(copy(info), b"")
        for name, (info, payload) in sorted(entries.items()):
            if info is not None:
                clone = copy(info)
                clone.filename = name
                archive.writestr(clone, payload)
            else:
                archive.writestr(name, payload)
    result = output.getvalue()
    verified, _ = _zip_entries(result, settings)
    verified.close()
    return result


def _inspect_image(data: bytes, settings: Settings) -> dict[str, Any]:
    Image, UnidentifiedImageError = _image_module()
    Image.MAX_IMAGE_PIXELS = settings.max_image_pixels
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.verify()
        with Image.open(io.BytesIO(data)) as image:
            pixels = image.width * image.height
            if pixels > settings.max_image_pixels:
                raise StructuredFileError("image pixel count exceeds max_image_pixels")
            if pixels * 8 > settings.max_image_decoded_bytes:
                raise StructuredFileError("decoded image exceeds max_image_decoded_bytes")
            metadata = {str(key): str(value)[:500] for key, value in image.info.items() if key.casefold() not in {"exif", "icc_profile"}}
            return {"format": "image", "image_format": image.format, "width": image.width, "height": image.height, "mode": image.mode, "frame_count": getattr(image, "n_frames", 1), "metadata": metadata, "metadata_policy": {"default": "preserve EXIF, ICC, and DPI when the destination encoder supports them", "metadata_remove": "remove EXIF; ICC and DPI are also omitted"}}
    except UnidentifiedImageError as error:
        raise StructuredFileError("unsupported or corrupt image") from error


def _require_image_pixels(width: int, height: int, settings: Settings) -> None:
    if width <= 0 or height <= 0 or width * height > settings.max_image_pixels:
        raise StructuredFileError("image pixel count exceeds max_image_pixels")
    if width * height * 8 > settings.max_image_decoded_bytes:
        raise StructuredFileError("decoded image exceeds max_image_decoded_bytes")


def _transform_image(data: bytes, operations: list[Any], settings: Settings) -> tuple[bytes, str | None]:
    Image, UnidentifiedImageError = _image_module()
    Image.MAX_IMAGE_PIXELS = settings.max_image_pixels
    try:
        image = Image.open(io.BytesIO(data))
    except UnidentifiedImageError as error:
        raise StructuredFileError("unsupported or corrupt image") from error
    try:
        _require_image_pixels(image.width, image.height, settings)
        if getattr(image, "n_frames", 1) != 1:
            raise StructuredFileError(
                "multi-frame image transformation is unsupported; use the container processing path"
            )
        source_format = image.format
        source_exif = image.info.get("exif")
        source_icc = image.info.get("icc_profile")
        source_dpi = image.info.get("dpi")
        output_format: str | None = None
        quality: int | None = None
        strip_metadata = False
        for raw in operations:
            op = _operation(raw)
            name = op["op"]
            if name == "resize":
                width, height = _index(op.get("width"), "width", minimum=1), _index(op.get("height"), "height", minimum=1)
                _require_image_pixels(width, height, settings)
                image = image.resize((width, height))
            elif name == "thumbnail":
                width, height = _index(op.get("max_width"), "max_width", minimum=1), _index(op.get("max_height"), "max_height", minimum=1)
                image.thumbnail((width, height))
            elif name == "crop":
                box = op.get("box")
                if not isinstance(box, list) or len(box) != 4:
                    raise StructuredFileError("crop box must be [left, top, right, bottom]")
                left, top, right, bottom = tuple(_index(value, "crop coordinate") for value in box)
                if not (left < right <= image.width and top < bottom <= image.height):
                    raise StructuredFileError("crop box must stay within the source image")
                image = image.crop((left, top, right, bottom))
            elif name == "rotate":
                angle = op.get("degrees")
                if not isinstance(angle, (int, float)):
                    raise StructuredFileError("degrees must be a number")
                image = image.rotate(angle, expand=bool(op.get("expand", True)))
            elif name == "flip":
                direction = _text(op.get("direction"), "direction")
                if direction == "horizontal":
                    image = image.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
                elif direction == "vertical":
                    image = image.transpose(Image.Transpose.FLIP_TOP_BOTTOM)
                else:
                    raise StructuredFileError("flip direction must be horizontal or vertical")
            elif name == "convert":
                output_format = _text(op.get("format"), "format").upper()
                if output_format not in {"PNG", "JPEG", "WEBP", "GIF", "BMP", "TIFF"}:
                    raise StructuredFileError("unsupported image output format")
            elif name == "quality":
                quality = _index(op.get("value"), "quality", minimum=1)
                if quality > 100:
                    raise StructuredFileError("quality must be <= 100")
            elif name == "metadata_remove":
                strip_metadata = True
            else:
                raise StructuredFileError(f"unsupported image operation: {name}")
            _require_image_pixels(image.width, image.height, settings)
        output_format = output_format or source_format or "PNG"
        if output_format == "JPEG" and image.mode not in {"RGB", "L"}:
            image = image.convert("RGB")
        output = io.BytesIO()
        kwargs: dict[str, Any] = {}
        if quality is not None and output_format in {"JPEG", "WEBP"}:
            kwargs["quality"] = quality
        if strip_metadata:
            kwargs["exif"] = b""
        else:
            if isinstance(source_exif, bytes):
                kwargs["exif"] = source_exif
            if isinstance(source_icc, bytes):
                kwargs["icc_profile"] = source_icc
            if isinstance(source_dpi, tuple) and len(source_dpi) == 2:
                kwargs["dpi"] = source_dpi
        image.save(output, format=output_format, **kwargs)
        return output.getvalue(), output_format
    finally:
        image.close()


def inspect(data: bytes, path: str, settings: Settings, *, format: str | None = None, range_ref: str | None = None) -> dict[str, Any]:
    _require_size(data, settings)
    kind = infer_format(path, format)
    if kind == "docx": result = _inspect_docx(data, settings)
    elif kind == "xlsx": result = _inspect_xlsx(data, settings, range_ref)
    elif kind in {"csv", "tsv"}: result = _inspect_csv(data, kind, settings)
    elif kind == "zip": result = _inspect_zip(data, settings)
    else: result = _inspect_image(data, settings)
    result.update(bytes=len(data), sha256=sha256_bytes(data))
    return result


def transform(data: bytes, path: str, operations: list[Any], settings: Settings, *, format: str | None = None) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(operations, list) or not operations:
        raise StructuredFileError("operations must be a non-empty array")
    if len(operations) > min(settings.max_structured_elements, 1000):
        raise StructuredFileError("operations exceed the bounded processing limit")
    _require_size(data, settings)
    kind = infer_format(path, format)
    if kind == "docx": output, extra = _transform_docx(data, operations, settings), {}
    elif kind == "xlsx": output, extra = _transform_xlsx(data, operations, settings), {}
    elif kind in {"csv", "tsv"}: output, extra = _transform_csv(data, kind, operations, settings), {}
    elif kind == "zip": output, extra = _transform_zip(data, operations, settings), {}
    else:
        output, image_format = _transform_image(data, operations, settings)
        format_extensions = {
            "PNG": {".png"}, "JPEG": {".jpg", ".jpeg"}, "WEBP": {".webp"},
            "GIF": {".gif"}, "BMP": {".bmp"}, "TIFF": {".tif", ".tiff"},
        }
        if image_format is not None and PureWindowsPath(path).suffix.casefold() not in format_extensions[image_format]:
            raise StructuredFileError(
                "image conversion would not match the target extension; use a matching output path"
            )
        extra = {"image_format": image_format}
    _require_size(output, settings)
    return output, {"format": kind, "operations": [str(_operation(item)["op"]) for item in operations], **extra}
