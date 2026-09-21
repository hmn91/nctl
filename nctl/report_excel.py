"""Stream Nessus CSV exports into consistently formatted Excel workbooks."""

from __future__ import annotations

import csv
import posixpath
import re
import threading
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
import xlsxwriter
from xlsxwriter.exceptions import XlsxWriterException
from xlsxwriter.utility import xl_rowcol_to_cell

from .client import NctlError
from .report_groups import group_for_finding


EXCEL_CELL_LIMIT = 32767
EXCEL_ROW_LIMIT = 1_048_576
MERGED_FIRST_COLUMNS = (
    "Source", "Group", "Name", "Risk", "Host", "Location", "Description",
    "Solution", "Plugin Output", "See Also", "CVE",
)
_MERGED_CONSUMED = {
    "source", "group", "name", "risk", "host", "protocol", "port",
    "location", "synopsis", "description", "solution", "plugin output",
    "see also", "cve",
}
_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PACKAGE_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_STRUCTURED_LINE = re.compile(
    r"^(?:\s+|[-*•▪‣]\s+|\d+[.)]\s+|[A-Za-z][.)]\s+|https?://\S+$)", re.I
)
_SHORT_HEADING = re.compile(r"^.{1,80}:$")
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_HTTP_LOCAL = threading.local()


def _csv_header(reader: Any, path: Path) -> list[str]:
    header = next((row for row in reader if row), [])
    if not header or any(not name.strip() for name in header) or len(set(header)) != len(header):
        raise NctlError(f"CSV {path} không có header hợp lệ hoặc có cột trùng tên.")
    return header


def _value(row: dict[str, str], name: str) -> str:
    wanted = name.casefold()
    return next((value for key, value in row.items() if key.casefold() == wanted), "")


def _join_nonempty(first: str, second: str, separator: str) -> str:
    return separator.join(value for value in (first, second) if value)


def reflow_narrative(value: str) -> str:
    """Remove web soft wraps while retaining paragraphs and structured blocks."""
    normalized = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    normalized = normalized.replace("\u00ad", "")
    if not normalized.strip():
        return ""
    blocks = re.split(r"\n[ \t]*\n+", normalized.strip("\n"))
    result: list[str] = []
    for block in blocks:
        lines = [line.rstrip() for line in block.split("\n")]
        nonempty = [line for line in lines if line.strip()]
        if not nonempty:
            continue
        if any(_STRUCTURED_LINE.match(line) or _SHORT_HEADING.match(line.strip()) for line in nonempty):
            result.append("\n".join(lines).strip("\n"))
            continue
        paragraph = ""
        for line in nonempty:
            cleaned = re.sub(r"[ \t]+", " ", line.strip())
            if not paragraph:
                paragraph = cleaned
            elif paragraph.endswith("-") and cleaned[:1].islower():
                paragraph += cleaned
            else:
                paragraph += " " + cleaned
        result.append(paragraph)
    return "\n\n".join(result)


def _xlsx_text(element: ET.Element) -> str:
    return "".join(node.text or "" for node in element.iter(f"{{{_SHEET_NS}}}t"))


def _xlsx_column(reference: str) -> int:
    letters = "".join(character for character in reference if character.isalpha())
    if not letters:
        raise NctlError(f"Địa chỉ cell Excel không hợp lệ: {reference!r}.")
    result = 0
    for letter in letters.upper():
        result = result * 26 + ord(letter) - 64
    return result - 1


def _xlsx_rows(path: Path) -> Iterator[list[str]]:
    try:
        with zipfile.ZipFile(path) as archive:
            workbook = ET.fromstring(archive.read("xl/workbook.xml"))
            first_sheet = workbook.find(f".//{{{_SHEET_NS}}}sheet")
            if first_sheet is None:
                raise NctlError(f"Excel {path} không có worksheet.")
            relation_id = first_sheet.attrib.get(f"{{{_REL_NS}}}id")
            relationships = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
            target = next((
                item.attrib.get("Target", "") for item in relationships
                if item.attrib.get("Id") == relation_id
            ), "")
            if not target:
                raise NctlError(f"Không tìm thấy worksheet đầu tiên trong Excel {path}.")
            sheet_path = (
                target.lstrip("/") if target.startswith("/")
                else posixpath.normpath(posixpath.join("xl", target))
            )
            shared: list[str] = []
            if "xl/sharedStrings.xml" in archive.namelist():
                with archive.open("xl/sharedStrings.xml") as shared_file:
                    for _, element in ET.iterparse(shared_file, events=("end",)):
                        if element.tag == f"{{{_SHEET_NS}}}si":
                            shared.append(_xlsx_text(element))
                            element.clear()
            with archive.open(sheet_path) as sheet_file:
                for _, element in ET.iterparse(sheet_file, events=("end",)):
                    if element.tag != f"{{{_SHEET_NS}}}row":
                        continue
                    values: dict[int, str] = {}
                    for cell in element.findall(f"{{{_SHEET_NS}}}c"):
                        column = _xlsx_column(cell.attrib.get("r", ""))
                        cell_type = cell.attrib.get("t")
                        if cell_type == "inlineStr":
                            value = _xlsx_text(cell)
                        else:
                            value_node = cell.find(f"{{{_SHEET_NS}}}v")
                            raw = value_node.text if value_node is not None and value_node.text else ""
                            if cell_type == "s" and raw:
                                try:
                                    value = shared[int(raw)]
                                except (IndexError, ValueError) as exc:
                                    raise NctlError(
                                        f"Excel {path} tham chiếu shared string không hợp lệ."
                                    ) from exc
                            elif cell_type == "b":
                                value = "TRUE" if raw == "1" else "FALSE"
                            else:
                                value = raw
                        values[column] = value
                    if values:
                        yield [values.get(index, "") for index in range(max(values) + 1)]
                    element.clear()
    except (KeyError, ET.ParseError, zipfile.BadZipFile) as exc:
        raise NctlError(f"Không đọc được Excel {path}: {exc}") from exc


def _table_rows(path: Path) -> Iterator[list[str]]:
    if path.suffix.casefold() == ".xlsx":
        yield from _xlsx_rows(path)
        return
    try:
        with path.open(encoding="utf-8-sig", newline="") as input_file:
            yield from csv.reader(input_file, strict=True)
    except (csv.Error, UnicodeError) as exc:
        raise NctlError(f"Không đọc được CSV {path}: {exc}") from exc


def _table_header(path: Path) -> list[str]:
    header = next((row for row in _table_rows(path) if any(row)), [])
    if not header or any(not name.strip() for name in header) or len(set(header)) != len(header):
        raise NctlError(f"File {path} không có header hợp lệ hoặc có cột trùng tên.")
    return header


def _fit_row(row: list[str], header: Sequence[str], path: Path, row_number: int) -> list[str]:
    if len(row) < len(header):
        return [*row, *([""] * (len(header) - len(row)))]
    if len(row) > len(header):
        if any(row[len(header):]):
            raise NctlError(
                f"File {path}, dòng {row_number}: số ô dữ liệu lớn hơn số cột header."
            )
        return row[:len(header)]
    return row


def merged_columns(headers: Sequence[Sequence[str]]) -> list[str]:
    columns = list(MERGED_FIRST_COLUMNS)
    known = {name.casefold() for name in columns}
    for header in headers:
        for name in header:
            folded = name.casefold()
            if folded not in _MERGED_CONSUMED and folded not in known:
                columns.append(name)
                known.add(folded)
    return columns


def merged_row(original: dict[str, str], source: str, columns: Sequence[str]) -> list[str]:
    protocol = _value(original, "Protocol")
    port = _value(original, "Port")
    synopsis = reflow_narrative(_value(original, "Synopsis"))
    description = reflow_narrative(_value(original, "Description"))
    values = {
        "Source": _value(original, "Source") or source,
        "Group": _value(original, "Group") or group_for_finding(original),
        "Name": _value(original, "Name"),
        "Risk": _value(original, "Risk"),
        "Host": _value(original, "Host"),
        "Location": (
            _join_nonempty(protocol, port, "/") if protocol or port
            else _value(original, "Location")
        ),
        "Description": (
            _join_nonempty(synopsis, description, "\n\n") if synopsis
            else description
        ),
        "Solution": reflow_narrative(_value(original, "Solution")),
        "Plugin Output": _value(original, "Plugin Output"),
        "See Also": _value(original, "See Also"),
        "CVE": _value(original, "CVE"),
    }
    original_by_name = {name.casefold(): value for name, value in original.items()}
    return [values.get(name, original_by_name.get(name.casefold(), "")) for name in columns]


def _clean_excel_value(value: Any) -> tuple[str, int | None]:
    cleaned = _ILLEGAL_XML.sub("", str(value or ""))
    if len(cleaned) > EXCEL_CELL_LIMIT:
        return cleaned[:EXCEL_CELL_LIMIT], len(cleaned)
    return cleaned, None


def _write_workbook(
    destination: Path, columns: Sequence[str], rows: Iterator[Sequence[Any]],
    *, existing_truncations: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    partial = destination.with_suffix(destination.suffix + ".part")
    row_count = 0
    truncated_details: list[dict[str, Any]] = []
    prior_truncations: dict[tuple[int, str], dict[str, Any]] = {}
    for detail in existing_truncations or []:
        match = re.search(r"(\d+)$", str(detail.get("cell", "")))
        column = str(detail.get("column", ""))
        if match and column:
            prior_truncations[(int(match.group(1)), column)] = detail
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with xlsxwriter.Workbook(str(partial), {"constant_memory": True}) as workbook:
            worksheet = workbook.add_worksheet("Report")
            cell_format = workbook.add_format({"valign": "top", "text_wrap": False})
            header_format = workbook.add_format({
                "bold": True, "valign": "top", "text_wrap": False,
            })
            truncated_format = workbook.add_format({
                "bold": True, "font_color": "#9C0006", "bg_color": "#FFF2CC",
                "valign": "top", "text_wrap": False,
            })
            for column, name in enumerate(columns):
                worksheet.write_string(0, column, name, header_format)
            for row_number, row in enumerate(rows, 1):
                if row_number >= EXCEL_ROW_LIMIT:
                    raise NctlError(
                        f"Excel chỉ hỗ trợ tối đa {EXCEL_ROW_LIMIT:,} dòng trên một sheet."
                    )
                if len(row) != len(columns):
                    raise NctlError("Số ô dữ liệu khác số cột khi tạo Excel.")
                for column, value in enumerate(row):
                    cleaned, original_length = _clean_excel_value(value)
                    current_format = cell_format
                    prior_detail = prior_truncations.get((row_number + 1, columns[column]))
                    if original_length is not None or prior_detail is not None:
                        truncated_details.append({
                            "cell": xl_rowcol_to_cell(row_number, column),
                            "column": columns[column],
                            "original_length": (
                                original_length if original_length is not None
                                else int(prior_detail["original_length"])
                            ),
                            "saved_length": (
                                EXCEL_CELL_LIMIT if prior_detail is None
                                else int(prior_detail.get("saved_length", EXCEL_CELL_LIMIT))
                            ),
                        })
                        current_format = truncated_format
                    worksheet.write_string(row_number, column, cleaned, current_format)
                row_count += 1
            if columns:
                worksheet.autofilter(0, 0, row_count, len(columns) - 1)
                worksheet.freeze_panes(1, 0)
        partial.replace(destination)
    except XlsxWriterException as exc:
        raise NctlError(f"Không tạo được Excel {destination}: {exc}") from exc
    finally:
        if partial.exists():
            partial.unlink()
    return {
        "rows": row_count,
        "truncated_cells": len(truncated_details),
        "truncated_details": truncated_details,
    }


def _extract_nessus_urls(value: str) -> list[str]:
    urls: list[str] = []
    for match in _URL.finditer(str(value or "")):
        url = match.group(0).rstrip(".,;)]}")
        parsed = urlsplit(url)
        host = (parsed.hostname or "").casefold()
        if (host == "nessus.org" or host.endswith(".nessus.org")) and parsed.path.rstrip("/") == "/u":
            urls.append(url)
    return urls


def _shortener_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit(("https", "api.tenable.com", "/v1/u", parsed.query, ""))


def _http_session() -> requests.Session:
    session = getattr(_HTTP_LOCAL, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "nctl-reference-resolver/2.6",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        })
        _HTTP_LOCAL.session = session
    return session


def resolve_nessus_reference(url: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Resolve one Nessus short URL and reject a redirect from its target."""
    endpoint = _shortener_url(url)
    try:
        with _http_session().get(
            endpoint, allow_redirects=False, stream=True, timeout=timeout,
        ) as short_response:
            if short_response.status_code not in _REDIRECT_STATUSES:
                return {
                    "source_url": url, "status": "shortener_not_redirect",
                    "http_status": short_response.status_code,
                }
            location = short_response.headers.get("Location", "").strip()
            if not location:
                return {"source_url": url, "status": "missing_location"}
            target = urljoin(endpoint, location)
        with _http_session().get(
            target, allow_redirects=False, stream=True, timeout=timeout,
        ) as target_response:
            if target_response.status_code in _REDIRECT_STATUSES:
                return {
                    "source_url": url, "target_url": target,
                    "status": "target_redirects_again",
                    "http_status": target_response.status_code,
                }
            if not 200 <= target_response.status_code < 300:
                return {
                    "source_url": url, "target_url": target,
                    "status": "target_unavailable",
                    "http_status": target_response.status_code,
                }
        return {"source_url": url, "target_url": target, "status": "resolved"}
    except requests.RequestException as exc:
        return {
            "source_url": url, "status": "request_error",
            "error": f"{type(exc).__name__}: {exc}",
        }


def resolve_references_xlsx(
    source: Path,
    destination: Path,
    *,
    existing_truncations: Sequence[dict[str, Any]] | None = None,
    timeout: float = 10.0,
    workers: int = 16,
    resolver: Callable[[str], dict[str, Any]] | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Create a second merged workbook with validated final URLs in References."""
    if workers < 1:
        raise NctlError("Số worker resolve URL phải lớn hơn 0.")
    first_pass = iter(_xlsx_rows(source))
    header = next((row for row in first_pass if any(row)), [])
    if not header:
        raise NctlError(f"Excel {source} không có header hợp lệ.")
    see_also_index = next(
        (index for index, name in enumerate(header) if name.casefold() == "see also"), None
    )
    # Different legacy schemes/hosts can point at the same Tenable short key.
    # Resolve each canonical shortener endpoint only once.
    ordered_urls: dict[str, str] = {}
    occurrences = 0
    if see_also_index is not None:
        for row in first_pass:
            value = row[see_also_index] if see_also_index < len(row) else ""
            urls = _extract_nessus_urls(value)
            occurrences += len(urls)
            for url in urls:
                ordered_urls.setdefault(_shortener_url(url), url)

    resolve_one = resolver or (lambda url: resolve_nessus_reference(url, timeout=timeout))
    results: dict[str, dict[str, Any]] = {}
    total = len(ordered_urls)
    if total:
        with ThreadPoolExecutor(max_workers=min(workers, total)) as executor:
            futures = {
                executor.submit(resolve_one, url): canonical
                for canonical, url in ordered_urls.items()
            }
            for completed, future in enumerate(as_completed(futures), 1):
                canonical = futures[future]
                url = ordered_urls[canonical]
                try:
                    results[canonical] = future.result()
                except Exception as exc:  # Keep one resolver failure from aborting the workbook.
                    results[canonical] = {
                        "source_url": url, "status": "resolver_error",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                if progress is not None and (completed == total or completed % 25 == 0):
                    progress(completed, total)

    source_references_index = next(
        (index for index, name in enumerate(header) if name.casefold() == "references"), None
    )
    columns = [name for name in header if name.casefold() != "references"]
    output_see_also_index = next(
        (index for index, name in enumerate(columns) if name.casefold() == "see also"), None
    )
    references_index = (
        output_see_also_index + 1 if output_see_also_index is not None
        else next((i for i, name in enumerate(columns) if name.casefold() == "cve"), len(columns))
    )
    columns.insert(references_index, "References")

    def rows() -> Iterator[list[str]]:
        table_rows = iter(_xlsx_rows(source))
        current_header = next((row for row in table_rows if any(row)), [])
        if current_header != header:
            raise NctlError(f"Header Excel {source} đã thay đổi trong lúc resolve URL.")
        for row_number, row in enumerate(table_rows, 2):
            if not any(row) or row == header:
                continue
            row = _fit_row(row, header, source, row_number)
            links: dict[str, None] = {}
            if source_references_index is not None:
                for link in str(row[source_references_index] or "").splitlines():
                    if link.strip():
                        links.setdefault(link.strip(), None)
            if see_also_index is not None:
                for url in _extract_nessus_urls(row[see_also_index]):
                    result = results.get(_shortener_url(url), {})
                    if result.get("status") == "resolved" and result.get("target_url"):
                        links.setdefault(str(result["target_url"]), None)
            if source_references_index is not None:
                del row[source_references_index]
            row.insert(references_index, "\n".join(links))
            yield row

    workbook_result = _write_workbook(
        destination, columns, rows(), existing_truncations=existing_truncations,
    )
    status_counts = Counter(result.get("status", "unknown") for result in results.values())
    return {
        **workbook_result,
        "urls_found": occurrences,
        "unique_urls": total,
        "resolved_urls": status_counts.get("resolved", 0),
        "rejected_urls": total - status_counts.get("resolved", 0),
        "status_counts": dict(sorted(status_counts.items())),
        "resolution_details": [results[canonical] for canonical in ordered_urls],
    }


def export_scan_xlsx(source: Path, destination: Path) -> dict[str, Any]:
    """Preserve the Nessus column order and append Group in a per-scan workbook."""
    previous_limit = csv.field_size_limit()
    csv.field_size_limit(2**31 - 1)
    group_counts: dict[str, int] = {}
    try:
        with source.open(encoding="utf-8-sig", newline="") as input_file:
            reader = csv.reader(input_file, strict=True)
            header = _csv_header(reader, source)
            if "Group" in header:
                raise NctlError(f"CSV {source} đã có cột Group.")
            columns = [*header, "Group"]

            def rows() -> Iterator[list[str]]:
                for row in reader:
                    if not row or row == header:
                        continue
                    if len(row) != len(header):
                        raise NctlError(
                            f"CSV {source}, dòng {reader.line_num}: số ô khác số cột header."
                        )
                    group = group_for_finding(dict(zip(header, row)))
                    group_counts[group] = group_counts.get(group, 0) + 1
                    yield [*row, group]

            result = _write_workbook(destination, columns, rows())
    except (csv.Error, UnicodeError) as exc:
        raise NctlError(f"Không đọc được CSV {source} để tạo Excel: {exc}") from exc
    finally:
        csv.field_size_limit(previous_limit)
    return {
        **result,
        "groups": len(group_counts),
        "review_rows": sum(
            count for name, count in group_counts.items() if name.startswith("Cần xem lại / ")
        ),
    }


def merge_scan_xlsx(
    paths: Sequence[Path], destination: Path, scan_names: Sequence[str],
    *, statistics: list[dict[str, Any]] | None = None,
    file_names: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Merge raw exports into one normalized workbook and consolidate CVEs per scan."""
    if not paths:
        raise NctlError("Không có file report thành công để gộp.")
    if len(scan_names) != len(paths):
        raise NctlError("Mỗi file report phải có tên scan tương ứng để ghi cột Source.")
    if file_names is not None and len(file_names) != len(paths):
        raise NctlError("Mỗi file report phải có tên hiển thị tương ứng.")
    previous_limit = csv.field_size_limit()
    csv.field_size_limit(2**31 - 1)
    try:
        headers: list[list[str]] = []
        for path in paths:
            headers.append(_table_header(path))
        columns = merged_columns(headers)
        cve_index = columns.index("CVE")

        def rows() -> Iterator[list[str]]:
            for file_index, (path, header, scan_name) in enumerate(zip(paths, headers, scan_names)):
                groups: dict[tuple[str, ...], tuple[list[str], dict[str, None]]] = {}
                input_rows = 0
                duplicates_removed = 0
                table_rows = iter(_table_rows(path))
                current_header = next((row for row in table_rows if any(row)), [])
                if current_header != header:
                    raise NctlError(f"Header file {path} đã thay đổi trong lúc gộp.")
                for row_number, raw_row in enumerate(table_rows, 2):
                    if not any(raw_row) or raw_row == header:
                        continue
                    raw_row = _fit_row(raw_row, header, path, row_number)
                    input_rows += 1
                    row = merged_row(dict(zip(header, raw_row)), scan_name, columns)
                    key = tuple(value for index, value in enumerate(row) if index != cve_index)
                    if key in groups:
                        duplicates_removed += 1
                    else:
                        groups[key] = (row, {})
                    for cve in re.split(r"[\s,;]+", row[cve_index].strip()):
                        if cve:
                            groups[key][1].setdefault(cve, None)
                for row, cves in groups.values():
                    row[cve_index] = "; ".join(cves)
                    yield row
                if statistics is not None:
                    statistics.append({
                        "file": file_names[file_index] if file_names else path.name,
                        "scan_name": scan_name,
                        "input_rows": input_rows,
                        "unique_rows": len(groups),
                        "duplicates_removed": duplicates_removed,
                    })

        return _write_workbook(destination, columns, rows())
    except (csv.Error, UnicodeError) as exc:
        raise NctlError(f"Không đọc được file đầu vào để gộp Excel: {exc}") from exc
    finally:
        csv.field_size_limit(previous_limit)
