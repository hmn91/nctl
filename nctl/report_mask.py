"""Reversible masking for Excel reports without exposing the token map."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import secrets
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .client import NctlError


_SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_XML_NS = "http://www.w3.org/XML/1998/namespace"
_MC_NS = "http://schemas.openxmlformats.org/markup-compatibility/2006"
_CANONICAL_PREFIXES = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships": "r",
    _MC_NS: "mc",
    "http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac": "x14ac",
    "http://schemas.microsoft.com/office/spreadsheetml/2014/revision": "xr",
    "http://schemas.microsoft.com/office/spreadsheetml/2015/revision2": "xr2",
    "http://schemas.microsoft.com/office/spreadsheetml/2016/revision3": "xr3",
}
_CANONICAL_URIS = {prefix: uri for uri, prefix in _CANONICAL_PREFIXES.items()}
_MASK_COLUMNS = {"host": "Host", "location": "Location"}
_PLUGIN_OUTPUT = "plugin output"
_AAD = b"nctl-mask-map-v1"
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_READABLE_TOKEN_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_READABLE_TOKEN_PATTERN = re.compile(
    r"\[\[(?:HOST|LOCATION):(?:[0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{2}\]\]"
)

ET.register_namespace("", _SHEET_NS)


def _namespace_map(data: bytes) -> dict[str, str]:
    namespaces: dict[str, str] = {}
    try:
        for _, item in ET.iterparse(io.BytesIO(data), events=("start-ns",)):
            prefix, uri = item
            namespaces.setdefault(prefix or "", uri)
    except ET.ParseError as exc:
        raise NctlError(f"Namespace XML trong worksheet không hợp lệ: {exc}") from exc
    return namespaces


def _prepare_worksheet_xml(root: ET.Element, namespaces: dict[str, str]) -> bytes:
    serialized_prefixes: dict[str, str] = {}
    for prefix, uri in namespaces.items():
        output_prefix = _CANONICAL_PREFIXES.get(uri, prefix)
        if output_prefix and not re.fullmatch(r"ns\d+", output_prefix):
            ET.register_namespace(output_prefix, uri)
            serialized_prefixes[uri] = output_prefix

    used_uris: set[str] = set()
    for element in root.iter():
        for qualified_name in (element.tag, *element.attrib):
            if isinstance(qualified_name, str) and qualified_name.startswith("{"):
                used_uris.add(qualified_name[1:].split("}", 1)[0])

    ignorable_key = f"{{{_MC_NS}}}Ignorable"
    ignorable = root.attrib.get(ignorable_key, "").split()
    if ignorable:
        retained: list[str] = []
        for prefix in ignorable:
            uri = namespaces.get(prefix) or _CANONICAL_URIS.get(prefix)
            output_prefix = serialized_prefixes.get(uri or "")
            if uri in used_uris and output_prefix and output_prefix not in retained:
                retained.append(output_prefix)
        if retained:
            root.set(ignorable_key, " ".join(retained))
        else:
            root.attrib.pop(ignorable_key, None)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def default_masked_path(source: Path) -> Path:
    return source.with_name(f"{source.stem}_masked.xlsx")


def default_mapping_path(source: Path) -> Path:
    return source.with_suffix(".mask.enc")


def default_unmasked_path(source: Path) -> Path:
    stem = source.stem
    if stem.casefold().endswith("_masked"):
        stem = stem[:-len("_masked")]
    return source.with_name(f"{stem}_unmasked.xlsx")


def _validate_source(path: Path) -> None:
    if not path.is_file() or path.suffix.casefold() != ".xlsx":
        raise NctlError(f"Không phải file .xlsx hợp lệ: {path}")


def _validate_new_output(path: Path, *other_paths: Path) -> None:
    resolved = path.resolve()
    if any(resolved == other.resolve() for other in other_paths):
        raise NctlError(f"File output phải khác file input/mapping: {path}")
    if path.exists():
        raise NctlError(f"File output đã tồn tại: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)


def _temporary_path(destination: Path) -> Path:
    with tempfile.NamedTemporaryFile(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp", delete=False,
    ) as output:
        return Path(output.name)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _column_index(reference: str) -> int:
    letters = "".join(character for character in reference if character.isalpha())
    if not letters:
        raise NctlError(f"Địa chỉ cell Excel không hợp lệ: {reference!r}.")
    result = 0
    for letter in letters.upper():
        result = result * 26 + ord(letter) - 64
    return result - 1


def _xlsx_text(element: ET.Element) -> str:
    return "".join(node.text or "" for node in element.iter(f"{{{_SHEET_NS}}}t"))


def _shared_strings(archive: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    try:
        root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    except ET.ParseError as exc:
        raise NctlError(f"Shared strings trong Excel không hợp lệ: {exc}") from exc
    return [_xlsx_text(item) for item in root.findall(f"{{{_SHEET_NS}}}si")]


def _cell_value(cell: ET.Element, shared: list[str]) -> str:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        return _xlsx_text(cell)
    node = cell.find(f"{{{_SHEET_NS}}}v")
    raw = node.text if node is not None and node.text is not None else ""
    if cell_type == "s" and raw:
        try:
            return shared[int(raw)]
        except (IndexError, ValueError) as exc:
            raise NctlError("Excel tham chiếu shared string không hợp lệ.") from exc
    if cell_type == "b":
        return "TRUE" if raw == "1" else "FALSE"
    return raw


def _set_cell_value(cell: ET.Element, value: str) -> None:
    for child in list(cell):
        cell.remove(child)
    if value == "":
        # Keep the cell node (and therefore its style) but store no value at all.
        # In particular, do not leave an empty shared-string reference such as
        # t="s"><v>15</v>, because simplistic XLSX readers can misread 15 as the
        # cell value instead of resolving sharedStrings.xml entry 15 to "".
        cell.attrib.pop("t", None)
        return
    cell.set("t", "inlineStr")
    inline = ET.SubElement(cell, f"{{{_SHEET_NS}}}is")
    text = ET.SubElement(inline, f"{{{_SHEET_NS}}}t")
    if value[:1].isspace() or value[-1:].isspace():
        text.set(f"{{{_XML_NS}}}space", "preserve")
    text.text = value


def _cell_shared_index(cell: ET.Element) -> int | None:
    if cell.attrib.get("t") != "s":
        return None
    node = cell.find(f"{{{_SHEET_NS}}}v")
    try:
        return int(node.text) if node is not None and node.text is not None else None
    except ValueError as exc:
        raise NctlError("Excel tham chiếu shared string không hợp lệ.") from exc


def _scrub_shared_strings(data: bytes, indices: set[int]) -> bytes:
    if not indices:
        return data
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise NctlError(f"Shared strings trong Excel không hợp lệ: {exc}") from exc
    items = root.findall(f"{{{_SHEET_NS}}}si")
    for index in indices:
        if not 0 <= index < len(items):
            raise NctlError("Excel tham chiếu shared string không hợp lệ.")
        for node in items[index].iter(f"{{{_SHEET_NS}}}t"):
            node.text = ""
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _worksheet_entries(names: list[str]) -> list[str]:
    return sorted(
        name for name in names
        if name.startswith("xl/worksheets/") and name.endswith(".xml")
        and "/_rels/" not in name
    )


def _rewrite_xlsx(
    source: Path,
    destination: Path,
    transform_sheet: Callable[[str, ET.Element, list[str]], None],
    *,
    scrub_shared_indices: set[int] | None = None,
) -> None:
    try:
        with zipfile.ZipFile(source) as input_archive:
            shared = _shared_strings(input_archive)
            sheet_entries = _worksheet_entries(input_archive.namelist())
            if not sheet_entries:
                raise NctlError(f"Excel {source} không có worksheet.")
            transformed_roots: dict[str, tuple[ET.Element, dict[str, str]]] = {}
            for sheet_entry in sheet_entries:
                sheet_data = input_archive.read(sheet_entry)
                namespaces = _namespace_map(sheet_data)
                try:
                    root = ET.fromstring(sheet_data)
                except ET.ParseError as exc:
                    raise NctlError(
                        f"Worksheet {sheet_entry} không hợp lệ: {exc}"
                    ) from exc
                transform_sheet(sheet_entry, root, shared)
                transformed_roots[sheet_entry] = (root, namespaces)
            # Normalize empty shared strings to truly blank cells. A shared string can
            # also be referenced by a non-sensitive cell (even a header), so convert
            # references to scrubbed slots to inline strings before scrubbing them.
            for root, _ in transformed_roots.values():
                for cell in root.findall(f".//{{{_SHEET_NS}}}c"):
                    shared_index = _cell_shared_index(cell)
                    if shared_index is None:
                        continue
                    if not 0 <= shared_index < len(shared):
                        raise NctlError("Excel tham chiếu shared string không hợp lệ.")
                    if shared[shared_index] == "":
                        _set_cell_value(cell, "")
                    elif shared_index in (scrub_shared_indices or set()):
                        _set_cell_value(cell, shared[shared_index])
            transformed_sheets = {
                name: _prepare_worksheet_xml(root, namespaces)
                for name, (root, namespaces) in transformed_roots.items()
            }
            with zipfile.ZipFile(destination, "w") as output_archive:
                for item in input_archive.infolist():
                    data = input_archive.read(item.filename)
                    if item.filename in transformed_sheets:
                        data = transformed_sheets[item.filename]
                    elif item.filename == "xl/sharedStrings.xml":
                        data = _scrub_shared_strings(data, scrub_shared_indices or set())
                    output_archive.writestr(item, data)
    except zipfile.BadZipFile as exc:
        raise NctlError(f"Không đọc được Excel {source}: {exc}") from exc


def _derive_encryption_key(password: str, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
    ).derive(password.encode("utf-8"))


def _encrypt_mapping(payload: dict[str, Any], password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_encryption_key(password, salt)
    plaintext = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _AAD)
    envelope = {
        "format": "nctl-mask-map",
        "version": 1,
        "cipher": "AES-256-GCM",
        "kdf": {"name": "scrypt", "n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P},
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def _decode_b64(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise NctlError(f"Mapping thiếu trường {field} hợp lệ.")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise NctlError(f"Mapping có trường {field} không hợp lệ.") from exc


def _decrypt_mapping(path: Path, password: str) -> dict[str, Any]:
    if not path.is_file():
        raise NctlError(f"Không tìm thấy file mapping: {path}")
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(envelope, dict)
            or envelope.get("format") != "nctl-mask-map"
            or envelope.get("version") != 1
            or envelope.get("cipher") != "AES-256-GCM"
            or envelope.get("kdf") != {
                "name": "scrypt", "n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P,
            }
        ):
            raise NctlError(f"File mapping không đúng định dạng nctl: {path}")
        salt = _decode_b64(envelope.get("salt"), "salt")
        nonce = _decode_b64(envelope.get("nonce"), "nonce")
        ciphertext = _decode_b64(envelope.get("ciphertext"), "ciphertext")
        plaintext = AESGCM(_derive_encryption_key(password, salt)).decrypt(
            nonce, ciphertext, _AAD,
        )
        payload = json.loads(plaintext.decode("utf-8"))
    except NctlError:
        raise
    except InvalidTag as exc:
        raise NctlError("Sai mật khẩu mask hoặc file mapping đã bị thay đổi.") from exc
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise NctlError(f"Không đọc được file mapping {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("format_version") != 1:
        raise NctlError(f"Nội dung mapping không hợp lệ: {path}")
    return payload


def _token_for(kind: str, existing: dict[str, dict[str, str]]) -> str:
    for _ in range(100):
        random_part = "".join(secrets.choice(_READABLE_TOKEN_ALPHABET) for _ in range(26))
        grouped = "-".join(
            random_part[index:index + 4] for index in range(0, len(random_part), 4)
        )
        token = f"[[{kind.upper()}:{grouped}]]"
        if token not in existing:
            return token
    raise NctlError("Không thể tạo token mask ngẫu nhiên duy nhất.")


def mask_workbook(
    source: Path, destination: Path, mapping_path: Path, password: str,
) -> dict[str, Any]:
    """Mask Host/Location and blank Plugin Output while preserving its column."""
    source = Path(source).expanduser()
    destination = Path(destination).expanduser()
    mapping_path = Path(mapping_path).expanduser()
    _validate_source(source)
    if not password:
        raise NctlError("Mật khẩu mask không được để trống.")
    _validate_new_output(destination, source, mapping_path)
    _validate_new_output(mapping_path, source, destination)

    tokens: dict[str, dict[str, str]] = {}
    values_to_tokens: dict[tuple[str, str], str] = {}
    scrub_shared_indices: set[int] = set()
    statistics = {
        "sheets": 0,
        "host_cells": 0,
        "location_cells": 0,
        "plugin_output_cells_cleared": 0,
        "columns_found": set(),
    }

    def transform(sheet_name: str, root: ET.Element, shared: list[str]) -> None:
        del sheet_name
        rows = root.findall(f".//{{{_SHEET_NS}}}sheetData/{{{_SHEET_NS}}}row")
        header_position = None
        column_kinds: dict[int, str] = {}
        for position, row in enumerate(rows):
            cells = row.findall(f"{{{_SHEET_NS}}}c")
            headers = {
                _column_index(cell.attrib.get("r", "")): _cell_value(cell, shared).strip().casefold()
                for cell in cells
            }
            if not any(headers.values()):
                continue
            for column, header in headers.items():
                if header in _MASK_COLUMNS:
                    column_kinds[column] = header
                    statistics["columns_found"].add(_MASK_COLUMNS[header])
                elif header == _PLUGIN_OUTPUT:
                    column_kinds[column] = _PLUGIN_OUTPUT
                    statistics["columns_found"].add("Plugin Output")
            header_position = position
            break
        if header_position is None or not column_kinds:
            return
        statistics["sheets"] += 1
        for row in rows[header_position + 1:]:
            for cell in row.findall(f"{{{_SHEET_NS}}}c"):
                column = _column_index(cell.attrib.get("r", ""))
                kind = column_kinds.get(column)
                if kind is None:
                    continue
                value = _cell_value(cell, shared)
                if kind == _PLUGIN_OUTPUT:
                    if value:
                        shared_index = _cell_shared_index(cell)
                        if shared_index is not None:
                            scrub_shared_indices.add(shared_index)
                        _set_cell_value(cell, "")
                        statistics["plugin_output_cells_cleared"] += 1
                    continue
                if not value:
                    continue
                shared_index = _cell_shared_index(cell)
                if shared_index is not None:
                    scrub_shared_indices.add(shared_index)
                display_kind = _MASK_COLUMNS[kind]
                key = (display_kind, value)
                token = values_to_tokens.get(key)
                if token is None:
                    token = _token_for(display_kind, tokens)
                    values_to_tokens[key] = token
                    tokens[token] = {"kind": display_kind, "value": value}
                _set_cell_value(cell, token)
                statistics[f"{kind}_cells"] += 1

    masked_temporary = _temporary_path(destination)
    mapping_temporary = _temporary_path(mapping_path)
    created: list[Path] = []
    try:
        _rewrite_xlsx(
            source, masked_temporary, transform,
            scrub_shared_indices=scrub_shared_indices,
        )
        if not statistics["columns_found"]:
            raise NctlError(
                f"Excel {source} không có cột Host, Location hoặc Plugin Output để mask."
            )
        payload = {
            "format_version": 1,
            "created_at": datetime.now().astimezone().isoformat(),
            "source_file": source.name,
            "masked_file": destination.name,
            "masked_sha256": _sha256(masked_temporary),
            "tokens": tokens,
        }
        mapping_temporary.write_bytes(_encrypt_mapping(payload, password))
        mapping_temporary.replace(mapping_path)
        created.append(mapping_path)
        masked_temporary.replace(destination)
        created.append(destination)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    finally:
        masked_temporary.unlink(missing_ok=True)
        mapping_temporary.unlink(missing_ok=True)

    return {
        "file": destination.name,
        "mapping_file": mapping_path.name,
        "source_file": source.name,
        "sheets": statistics["sheets"],
        "columns_found": sorted(statistics["columns_found"]),
        "host_cells": statistics["host_cells"],
        "location_cells": statistics["location_cells"],
        "plugin_output_cells_cleared": statistics["plugin_output_cells_cleared"],
        "tokens": len(tokens),
    }


def unmask_workbook(
    source: Path, destination: Path, mapping_path: Path, password: str,
) -> dict[str, Any]:
    """Replace known Host/Location tokens; intentionally leave Plugin Output unchanged."""
    source = Path(source).expanduser()
    destination = Path(destination).expanduser()
    mapping_path = Path(mapping_path).expanduser()
    _validate_source(source)
    if not password:
        raise NctlError("Mật khẩu mask không được để trống.")
    _validate_new_output(destination, source, mapping_path)
    payload = _decrypt_mapping(mapping_path, password)
    raw_tokens = payload.get("tokens")
    if not isinstance(raw_tokens, dict):
        raise NctlError(f"Mapping không có danh sách token hợp lệ: {mapping_path}")
    replacements: dict[str, str] = {}
    token_kinds: dict[str, str] = {}
    for token, detail in raw_tokens.items():
        if (
            not isinstance(token, str)
            or _READABLE_TOKEN_PATTERN.fullmatch(token) is None
            or not isinstance(detail, dict)
            or detail.get("kind") not in {"Host", "Location"}
            or not isinstance(detail.get("value"), str)
        ):
            raise NctlError(f"Mapping chứa token không hợp lệ: {mapping_path}")
        kind = str(detail["kind"])
        if not token.startswith(f"[[{kind.upper()}:"):
            raise NctlError(f"Mapping chứa token sai loại dữ liệu: {mapping_path}")
        replacements[token] = detail["value"]
        token_kinds[token] = kind
    pattern = re.compile("|".join(re.escape(token) for token in replacements)) if replacements else None
    statistics = {"cells": 0, "host_tokens": 0, "location_tokens": 0}
    scrub_shared_indices: set[int] = set()

    def transform(sheet_name: str, root: ET.Element, shared: list[str]) -> None:
        del sheet_name
        if pattern is None:
            return
        for cell in root.findall(f".//{{{_SHEET_NS}}}sheetData//{{{_SHEET_NS}}}c"):
            value = _cell_value(cell, shared)
            matches = list(pattern.finditer(value))
            if not matches:
                continue
            shared_index = _cell_shared_index(cell)
            if shared_index is not None:
                scrub_shared_indices.add(shared_index)
            unmasked_value = pattern.sub(lambda match: replacements[match.group(0)], value)
            _set_cell_value(cell, unmasked_value)
            statistics["cells"] += 1
            for match in matches:
                key = "host_tokens" if token_kinds[match.group(0)] == "Host" else "location_tokens"
                statistics[key] += 1

    temporary = _temporary_path(destination)
    try:
        _rewrite_xlsx(
            source, temporary, transform,
            scrub_shared_indices=scrub_shared_indices,
        )
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "file": destination.name,
        "source_file": source.name,
        "mapping_file": mapping_path.name,
        "cells": statistics["cells"],
        "host_tokens": statistics["host_tokens"],
        "location_tokens": statistics["location_tokens"],
        "plugin_output": "unchanged",
        "source_matches_original_masked": payload.get("masked_sha256") == _sha256(source),
    }
