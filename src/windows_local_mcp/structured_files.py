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
    except (KeyError, zipfile.BadZipFile) as error:
        raise StructuredFileError("invalid DOCX package") from error
    found: list[str] = []
    if any("vbaproject.bin" in name for name in names):
        found.append("VBA/macros")
    if any("activex" in name for name in names):
        found.append("ActiveX")
    if any("diagrams/" in name for name in names):
        found.append("SmartArt")
    if b"<w:ins" in document or b"<w:del" in document or b"<w:move" in document:
        found.append("tracked changes")
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
    props = document.core_properties
    return {
        "format": "docx",
        "paragraph_count": len(document.paragraphs),
        "paragraphs": [_paragraph_info(p, i) for i, p in enumerate(document.paragraphs[:200])],
        "table_count": len(document.tables),
        "tables": tables[:50],
        "sections": len(document.sections),
        "metadata": {key: getattr(props, key) for key in ("title", "subject", "author", "keywords", "comments")},
        "write_rejected_features": unsupported,
        "truncated": len(document.paragraphs) > 200 or len(document.tables) > 50,
    }


def _apply_docx_format(paragraph: Any, spec: dict[str, Any]) -> None:
    _, _, WD_ALIGN_PARAGRAPH, units = _docx_modules()
    Inches, Pt, RGBColor = units
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
        if not isinstance(run_spec, dict):
            raise StructuredFileError("run formatting must be an object")
        for run in paragraph.runs:
            if "font_name" in run_spec:
                run.font.name = _text(run_spec["font_name"], "font_name")
            if "font_size_pt" in run_spec:
                size = run_spec["font_size_pt"]
                if not isinstance(size, (int, float)) or size <= 0:
                    raise StructuredFileError("font_size_pt must be a positive number")
                run.font.size = Pt(size)
            for key, attr in (("bold", "bold"), ("italic", "italic"), ("underline", "underline")):
                if key in run_spec:
                    if not isinstance(run_spec[key], bool):
                        raise StructuredFileError(f"{key} must be boolean")
                    setattr(run.font, attr, run_spec[key])
            if "color" in run_spec:
                color = _text(run_spec["color"], "color")
                if not re.fullmatch(r"[0-9A-Fa-f]{6}", color):
                    raise StructuredFileError("color must be six hexadecimal digits")
                run.font.color.rgb = RGBColor.from_string(color.upper())


def _transform_docx(data: bytes, operations: list[Any], settings: Settings) -> bytes:
    unsupported = _docx_has_unsupported_features(data)
    if unsupported:
        raise StructuredFileError("DOCX write is unsupported with: " + ", ".join(unsupported))
    Document, WD_ORIENT, _, units = _docx_modules()
    Inches, _, _ = units
    document = Document(io.BytesIO(data))
    for raw in operations:
        op = _operation(raw)
        name = op["op"]
        if name == "paragraph_append":
            paragraph = document.add_paragraph(_text(op.get("text", "")))
            _apply_docx_format(paragraph, op.get("format", {}))
        elif name == "paragraph_update":
            paragraph = document.paragraphs[_index(op.get("index"), "index")]
            if "text" in op:
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
            _apply_docx_format(paragraph, {"run": op.get("format", {})})
        elif name == "replace_text":
            search = _text(op.get("search"), "search")
            replacement = _text(op.get("replace"), "replace")
            if not search:
                raise StructuredFileError("search must not be empty")
            count = 0
            for paragraph in document.paragraphs:
                for run in paragraph.runs:
                    if search in run.text:
                        run.text = run.text.replace(search, replacement)
                        count += 1
            if op.get("require_match", False) and count == 0:
                raise StructuredFileError("replace_text found no match")
        elif name == "table_cell_set":
            table = document.tables[_index(op.get("table"), "table")]
            cell = table.cell(_index(op.get("row"), "row"), _index(op.get("column"), "column"))
            cell.text = _text(op.get("text", ""))
        elif name == "table_row_add":
            table = document.tables[_index(op.get("table"), "table")]
            values = op.get("values", [])
            if not isinstance(values, list) or len(values) > len(table.columns):
                raise StructuredFileError("values must fit in the table columns")
            row = table.add_row()
            for cell, value in zip(row.cells, values, strict=False):
                cell.text = _text(value, "table value")
        elif name == "header_footer_append":
            section = document.sections[_index(op.get("section", 0), "section")]
            area = _text(op.get("area", "header"), "area")
            if area not in {"header", "footer"}:
                raise StructuredFileError("area must be header or footer")
            getattr(section, area).add_paragraph(_text(op.get("text", "")))
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
            for key, attr in (("top_margin_inches", "top_margin"), ("bottom_margin_inches", "bottom_margin"), ("left_margin_inches", "left_margin"), ("right_margin_inches", "right_margin")):
                if key in op:
                    value = op[key]
                    if not isinstance(value, (int, float)) or value < 0:
                        raise StructuredFileError(f"{key} must be a non-negative number")
                    setattr(section, attr, Inches(value))
        else:
            raise StructuredFileError(f"unsupported DOCX operation: {name}")
    output = io.BytesIO()
    document.save(output)
    return output.getvalue()


def _xlsx_unsupported(data: bytes) -> list[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = {name.casefold() for name in archive.namelist()}
    except zipfile.BadZipFile as error:
        raise StructuredFileError("invalid XLSX package") from error
    blocked = []
    for marker, label in (("vbaproject.bin", "VBA/macros"), ("activex", "ActiveX"), ("connections.xml", "external data connections"), ("slicer", "slicers")):
        if any(marker in name for name in names):
            blocked.append(label)
    return blocked


def _sheet_cell_count(sheet: Any) -> int:
    return max(1, sheet.max_row) * max(1, sheet.max_column)


def _inspect_xlsx(data: bytes, settings: Settings, range_ref: str | None = None) -> dict[str, Any]:
    _, load_workbook, *_ = _xlsx_modules()
    book = load_workbook(io.BytesIO(data), read_only=True, data_only=False, keep_links=False)
    sheets = []
    total = 0
    for sheet in book.worksheets:
        cells = _sheet_cell_count(sheet)
        total += cells
        if total > settings.max_structured_elements:
            raise StructuredFileError("XLSX cells exceed max_structured_elements")
        preview_range = range_ref if range_ref and sheet.title == book.active.title else f"A1:{sheet.cell(min(sheet.max_row, 20), min(sheet.max_column, 20)).coordinate}"
        try:
            rows = [[cell.value for cell in row] for row in sheet[preview_range]]
        except ValueError as error:
            raise StructuredFileError("invalid XLSX range") from error
        sheets.append({"name": sheet.title, "state": sheet.sheet_state, "max_row": sheet.max_row, "max_column": sheet.max_column, "preview_range": preview_range, "values": rows})
    return {"format": "xlsx", "sheets": sheets, "write_rejected_features": _xlsx_unsupported(data)}


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
    book = load_workbook(io.BytesIO(data), data_only=False, keep_links=False)
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
        else:
            sheet = book[_text(op.get("sheet"), "sheet")]
            if name == "cell_set":
                cell = sheet[_text(op.get("cell"), "cell")]
                cell.value = op.get("value")
                if "format" in op:
                    _xlsx_cell_format(cell, op["format"], styles)
            elif name == "range_set":
                start = sheet[_text(op.get("range"), "range")]
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
                for row in sheet[_text(op.get("range"), "range")]:
                    for cell in row:
                        cell.value = None
            elif name in {"rows_insert", "rows_delete", "columns_insert", "columns_delete"}:
                index = _index(op.get("index"), "index", minimum=1)
                amount = _index(op.get("amount", 1), "amount", minimum=1)
                getattr(sheet, name.replace("rows_", "").replace("columns_", "") + ("_rows" if name.startswith("rows") else "_cols"))(index, amount)
            elif name == "merge":
                sheet.merge_cells(_text(op.get("range"), "range"))
            elif name == "unmerge":
                sheet.unmerge_cells(_text(op.get("range"), "range"))
            elif name == "format_range":
                spec = op.get("format")
                if not isinstance(spec, dict):
                    raise StructuredFileError("format must be an object")
                for row in sheet[_text(op.get("range"), "range")]:
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
                sheet.freeze_panes = _text(op.get("cell"), "cell")
            elif name == "autofilter_set":
                sheet.auto_filter.ref = _text(op.get("range"), "range")
            elif name == "table_add":
                from openpyxl.worksheet.table import Table, TableStyleInfo
                table = Table(displayName=_text(op.get("name"), "name"), ref=_text(op.get("range"), "range"))
                table.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True)
                sheet.add_table(table)
            elif name == "validation_add":
                validation = DataValidation(type=_text(op.get("type", "list"), "type"), formula1=_text(op.get("formula1"), "formula1"), allow_blank=bool(op.get("allow_blank", True)))
                sheet.add_data_validation(validation)
                validation.add(_text(op.get("range"), "range"))
            elif name == "conditional_cell_is":
                color = _text(op.get("fill"), "fill")
                rule = CellIsRule(operator=_text(op.get("operator"), "operator"), formula=[_text(op.get("formula"), "formula")], fill=styles[3]("solid", fgColor=color))
                sheet.conditional_formatting.add(_text(op.get("range"), "range"), rule)
            elif name == "chart_add":
                chart_type = _text(op.get("type", "bar"), "type")
                if chart_type not in {"bar", "line"}:
                    raise StructuredFileError("chart type must be bar or line")
                chart = BarChart() if chart_type == "bar" else LineChart()
                data_ref = Reference(sheet, range_string=_text(op.get("data_range"), "data_range"))
                chart.add_data(data_ref, titles_from_data=bool(op.get("titles_from_data", True)))
                sheet.add_chart(chart, _text(op.get("anchor", "E2"), "anchor"))
            elif name == "page_setup_set":
                values = op.get("values")
                if not isinstance(values, dict):
                    raise StructuredFileError("page setup values must be an object")
                for key in ("orientation", "paperSize", "fitToWidth", "fitToHeight"):
                    if key in values:
                        setattr(sheet.page_setup, key, values[key])
            else:
                raise StructuredFileError(f"unsupported XLSX operation: {name}")
    output = io.BytesIO()
    book.save(output)
    return output.getvalue()


@dataclass
class CsvDocument:
    rows: list[list[str]]
    encoding: str
    dialect: csv.Dialect
    newline: str


def _parse_csv(data: bytes, kind: str, settings: Settings) -> CsvDocument:
    if len(data) > settings.max_structured_file_bytes:
        _require_size(data, settings)
    encoding = "utf-8-sig" if data.startswith(b"\xef\xbb\xbf") else "utf-8"
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError as error:
        raise StructuredFileError("CSV/TSV must be valid UTF-8 or UTF-8 with BOM") from error
    sample = text[:8192]
    if kind == "tsv":
        dialect = csv.excel_tab
    else:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text, newline=""), dialect))
    _bounded(rows, settings, "CSV rows")
    if sum(len(row) for row in rows) > settings.max_structured_elements:
        raise StructuredFileError("CSV cells exceed max_structured_elements")
    newline = "\r\n" if "\r\n" in text else "\n"
    return CsvDocument(rows, encoding, dialect, newline)


def _inspect_csv(data: bytes, kind: str, settings: Settings) -> dict[str, Any]:
    document = _parse_csv(data, kind, settings)
    return {"format": kind, "encoding": document.encoding, "delimiter": document.dialect.delimiter, "rows": len(document.rows), "columns": max((len(row) for row in document.rows), default=0), "preview": document.rows[:200], "truncated": len(document.rows) > 200}


def _transform_csv(data: bytes, kind: str, operations: list[Any], settings: Settings) -> bytes:
    document = _parse_csv(data, kind, settings) if data else CsvDocument([], "utf-8", csv.excel_tab if kind == "tsv" else csv.excel, "\n")
    for raw in operations:
        op = _operation(raw)
        name = op["op"]
        if name == "cell_set":
            row = _index(op.get("row"), "row")
            column = _index(op.get("column"), "column")
            while len(document.rows) <= row:
                document.rows.append([])
            while len(document.rows[row]) <= column:
                document.rows[row].append("")
            document.rows[row][column] = _text(op.get("value", ""), "value")
        elif name == "row_append":
            values = op.get("values")
            if not isinstance(values, list):
                raise StructuredFileError("values must be an array")
            document.rows.append([_text(value, "value") for value in values])
        elif name == "row_delete":
            del document.rows[_index(op.get("row"), "row")]
        elif name == "column_insert":
            column = _index(op.get("column"), "column")
            value = _text(op.get("default", ""), "default")
            for row in document.rows:
                row.insert(min(column, len(row)), value)
        elif name == "column_delete":
            column = _index(op.get("column"), "column")
            for row in document.rows:
                if column < len(row):
                    del row[column]
        else:
            raise StructuredFileError(f"unsupported CSV operation: {name}")
    _bounded(document.rows, settings, "CSV rows")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, document.dialect, lineterminator=document.newline)
    writer.writerows(document.rows)
    output = stream.getvalue().encode(document.encoding)
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


def _zip_entries(data: bytes, settings: Settings) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        raise StructuredFileError("invalid ZIP archive") from error
    entries = archive.infolist()
    if len(entries) > settings.max_zip_entries:
        archive.close()
        raise StructuredFileError("ZIP entry count exceeds max_zip_entries")
    names = [_safe_zip_name(info.filename) for info in entries if not info.is_dir()]
    if len(names) != len({name.casefold() for name in names}):
        archive.close()
        raise StructuredFileError("ZIP contains duplicate or colliding entry names")
    expanded = sum(info.file_size for info in entries)
    if expanded > settings.max_zip_expanded_bytes:
        archive.close()
        raise StructuredFileError("ZIP expanded size exceeds max_zip_expanded_bytes")
    if any(info.file_size > settings.max_zip_expanded_bytes for info in entries):
        archive.close()
        raise StructuredFileError("ZIP entry expanded size exceeds max_zip_expanded_bytes")
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
        matches = [info for info in entries if not info.is_dir() and _safe_zip_name(info.filename) == safe_name]
        if len(matches) != 1:
            raise StructuredFileError("ZIP entry was not found")
        payload = archive.read(matches[0])
        if len(payload) != matches[0].file_size:
            raise StructuredFileError("ZIP entry size verification failed")
        return payload
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


def _transform_zip(data: bytes, operations: list[Any], settings: Settings) -> bytes:
    entries: dict[str, tuple[zipfile.ZipInfo | None, bytes]] = {}
    if data:
        archive, infos = _zip_entries(data, settings)
        try:
            for info in infos:
                if not info.is_dir():
                    entries[_safe_zip_name(info.filename)] = (info, archive.read(info))
        finally:
            archive.close()
    for raw in operations:
        op = _operation(raw)
        name = op["op"]
        if name in {"entry_add", "entry_replace"}:
            entry = _safe_zip_name(_text(op.get("name"), "name"))
            if name == "entry_add" and entry in entries:
                raise StructuredFileError("ZIP entry already exists")
            entries[entry] = (None, _zip_payload(op))
        elif name == "entry_delete":
            entry = _safe_zip_name(_text(op.get("name"), "name"))
            if entry not in entries:
                raise StructuredFileError("ZIP entry does not exist")
            del entries[entry]
        else:
            raise StructuredFileError(f"unsupported ZIP operation: {name}")
    if len(entries) > settings.max_zip_entries or sum(len(value[1]) for value in entries.values()) > settings.max_zip_expanded_bytes:
        raise StructuredFileError("resulting ZIP exceeds configured limits")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as archive:
        for name, (info, payload) in sorted(entries.items()):
            if info is not None:
                clone = copy(info)
                clone.filename = name
                archive.writestr(clone, payload)
            else:
                archive.writestr(name, payload)
    return output.getvalue()


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
            metadata = {str(key): str(value)[:500] for key, value in image.info.items() if key.casefold() not in {"exif", "icc_profile"}}
            return {"format": "image", "image_format": image.format, "width": image.width, "height": image.height, "mode": image.mode, "frame_count": getattr(image, "n_frames", 1), "metadata": metadata}
    except UnidentifiedImageError as error:
        raise StructuredFileError("unsupported or corrupt image") from error


def _transform_image(data: bytes, operations: list[Any], settings: Settings) -> tuple[bytes, str | None]:
    Image, UnidentifiedImageError = _image_module()
    Image.MAX_IMAGE_PIXELS = settings.max_image_pixels
    try:
        image = Image.open(io.BytesIO(data))
    except UnidentifiedImageError as error:
        raise StructuredFileError("unsupported or corrupt image") from error
    try:
        if image.width * image.height > settings.max_image_pixels:
            raise StructuredFileError("image pixel count exceeds max_image_pixels")
        source_format = image.format
        output_format: str | None = None
        quality: int | None = None
        strip_metadata = False
        for raw in operations:
            op = _operation(raw)
            name = op["op"]
            if name == "resize":
                width, height = _index(op.get("width"), "width", minimum=1), _index(op.get("height"), "height", minimum=1)
                image = image.resize((width, height))
            elif name == "thumbnail":
                width, height = _index(op.get("max_width"), "max_width", minimum=1), _index(op.get("max_height"), "max_height", minimum=1)
                image.thumbnail((width, height))
            elif name == "crop":
                box = op.get("box")
                if not isinstance(box, list) or len(box) != 4:
                    raise StructuredFileError("crop box must be [left, top, right, bottom]")
                image = image.crop(tuple(_index(value, "crop coordinate") for value in box))
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
        output_format = output_format or source_format or "PNG"
        if output_format == "JPEG" and image.mode not in {"RGB", "L"}:
            image = image.convert("RGB")
        output = io.BytesIO()
        kwargs: dict[str, Any] = {}
        if quality is not None and output_format in {"JPEG", "WEBP"}:
            kwargs["quality"] = quality
        if strip_metadata:
            kwargs["exif"] = b""
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
