from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .client import NctlClient, NctlError
from .helptext import OVERVIEW, TOPICS
from .report_excel import export_scan_xlsx, merge_scan_xlsx, resolve_references_xlsx


DEFAULT_URL = "https://127.0.0.1:11127"
# Preserve the historical DB secret so existing backups remain restorable.
DEFAULT_DB_PASSWORD = "NessusDB@2026"
TERMINAL_SCAN_STATES = {"completed", "canceled", "cancelled", "aborted", "stopped", "empty", "imported"}


def _load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NctlError(f"Không đọc được config {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise NctlError(f"Config {path} phải là một JSON object.")
    return value


def _setting(args: argparse.Namespace, config: dict[str, Any], name: str, default: Any = None) -> Any:
    cli_value = getattr(args, name, None)
    if cli_value is not None:
        return cli_value
    env_name = f"NCTL_{name.upper()}"
    if os.getenv(env_name) is not None:
        return os.environ[env_name]
    return config.get(name, default)


def _make_client(args: argparse.Namespace, config: dict[str, Any]) -> NctlClient:
    url = str(_setting(args, config, "url", DEFAULT_URL))
    access_key = _setting(args, config, "access_key")
    secret_key = _setting(args, config, "secret_key")
    username = _setting(args, config, "username")
    password = _setting(args, config, "password")

    if not (access_key and secret_key):
        if not username:
            if args.non_interactive:
                raise NctlError("Thiếu NCTL_USERNAME trong chế độ non-interactive.")
            username = input("Tên đăng nhập máy chủ: ").strip()
        if not password:
            if args.non_interactive:
                raise NctlError("Thiếu NCTL_PASSWORD trong chế độ non-interactive.")
            password = getpass.getpass("Mật khẩu đăng nhập máy chủ: ")

    verify_value = _setting(args, config, "verify_tls", False)
    if isinstance(verify_value, str):
        lowered = verify_value.lower()
        verify_tls: bool | str = (
            lowered in {"1", "true", "yes", "on"} if lowered in {"0", "1", "true", "false", "yes", "no", "on", "off"} else verify_value
        )
    else:
        verify_tls = bool(verify_value)
    cli_http_timeout = getattr(args, "http_timeout", None)
    timeout = float(
        cli_http_timeout
        if cli_http_timeout is not None
        else os.getenv("NCTL_TIMEOUT", config.get("timeout", 60))
    )
    return NctlClient(
        url,
        username=username,
        password=password,
        access_key=access_key,
        secret_key=secret_key,
        verify_tls=verify_tls,
        timeout=timeout,
    )


def _db_password(args: argparse.Namespace, config: dict[str, Any], action: str) -> str:
    default = str(
        os.getenv("NCTL_DB_PASSWORD")
        or config.get("default_db_password")
        or DEFAULT_DB_PASSWORD
    )
    if args.non_interactive:
        return default
    entered = getpass.getpass(
        f"Mật khẩu dùng chung cho lượt {action} (Enter = mật khẩu mặc định): "
    )
    return entered or default


def _folder_id(
    client: NctlClient, value: str | int, *, create_missing: bool = False
) -> int:
    text = str(value).strip()
    folders = client.list_folders()
    if text.isdigit():
        folder_id = int(text)
        if any(int(f.get("id", -1)) == folder_id for f in folders):
            return folder_id
        raise NctlError(f"Không tìm thấy folder ID {folder_id}.")
    matches = [f for f in folders if str(f.get("name", "")).casefold() == text.casefold()]
    if len(matches) == 1:
        return int(matches[0]["id"])
    if len(matches) > 1:
        raise NctlError(f"Có nhiều folder cùng tên {text!r}; hãy dùng folder ID.")
    if create_missing:
        return client.create_folder(text)
    raise NctlError(f"Không tìm thấy folder {text!r}.")


def _folder_record(client: NctlClient, value: str | int) -> dict[str, Any]:
    folder_id = _folder_id(client, value)
    for folder in client.list_folders():
        if int(folder.get("id", -1)) == folder_id:
            return folder
    raise NctlError(f"Không tìm thấy folder ID {folder_id}.")


def _is_trash_folder(folder: dict[str, Any]) -> bool:
    return (
        str(folder.get("type", "")).casefold() == "trash"
        or str(folder.get("name", "")).strip().casefold() == "trash"
    )


def _trash_folder_ids(folders: Sequence[dict[str, Any]]) -> set[int]:
    ids: set[int] = set()
    for folder in folders:
        if not _is_trash_folder(folder):
            continue
        try:
            ids.add(int(folder["id"]))
        except (KeyError, TypeError, ValueError):
            continue
    return ids


def _scan_in_folders(scan: dict[str, Any], folder_ids: set[int]) -> bool:
    try:
        return int(scan.get("folder_id", -1)) in folder_ids
    except (TypeError, ValueError):
        return False


def _merge_scans(*groups: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[int] = set()
    for group in groups:
        for scan in group:
            try:
                scan_id = int(scan["id"])
            except (KeyError, TypeError, ValueError):
                continue
            if scan_id not in seen:
                seen.add(scan_id)
                merged.append(scan)
    return merged


def _scans_in_folder(client: NctlClient, folder_id: int) -> list[dict[str, Any]]:
    data = client.list_scans(folder_id)
    scans: list[dict[str, Any]] = []
    for item in data.get("scans") or []:
        scan = dict(item)
        if scan.get("folder_id") is None:
            scan["folder_id"] = folder_id
        scans.append(scan)
    return scans


def _history_list(details: dict[str, Any]) -> list[dict[str, Any]]:
    value = details.get("history") or []
    return [item for item in value if isinstance(item, dict) and item.get("history_id") is not None]


def _history_id(item: dict[str, Any]) -> int:
    return int(item["history_id"])


def _latest_history(histories: list[dict[str, Any]]) -> dict[str, Any]:
    def key(item: dict[str, Any]) -> tuple[int, int]:
        modified = item.get("last_modification_date") or item.get("creation_date") or 0
        try:
            modified_int = int(modified)
        except (TypeError, ValueError):
            modified_int = 0
        return modified_int, _history_id(item)

    return max(histories, key=key)


def _fmt_time(value: Any) -> str:
    try:
        return datetime.fromtimestamp(int(value)).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "-"


def cmd_status(client: NctlClient, _: argparse.Namespace, __: dict[str, Any]) -> int:
    props = client.server_properties()
    version = props.get("server_version") or props.get("nessus_ui_version") or "?"
    print(f"Kết nối thành công: {client.url}")
    print(f"Phiên bản máy chủ: {version}")
    return 0


def cmd_folders(client: NctlClient, _: argparse.Namespace, __: dict[str, Any]) -> int:
    print(f"{'ID':>6}  {'TYPE':<10}  NAME")
    for folder in client.list_folders():
        print(f"{str(folder.get('id', '-')):>6}  {str(folder.get('type', '-')):<10}  {folder.get('name', '-')}")
    return 0


def cmd_scans(client: NctlClient, args: argparse.Namespace, _: dict[str, Any]) -> int:
    folder_id = _folder_id(client, args.folder) if args.folder else None
    data = client.list_scans(folder_id)
    folders = {int(f["id"]): str(f.get("name", "-")) for f in data.get("folders", []) if f.get("id") is not None}
    rows: list[dict[str, Any]] = []
    for scan in data.get("scans") or []:
        scan_id = int(scan["id"])
        details = client.scan_details(scan_id)
        histories = _history_list(details)
        row = {
            "id": scan_id,
            "name": scan.get("name", "-"),
            "folder_id": scan.get("folder_id"),
            "folder": folders.get(int(scan.get("folder_id", -1)), "-"),
            "status": scan.get("status") or details.get("info", {}).get("status") or "-",
            "history_count": len(histories),
            "last_modified": scan.get("last_modification_date"),
        }
        rows.append(row)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    print(f"{'ID':>6}  {'HISTORY':>7}  {'STATUS':<12}  {'FOLDER':<20}  {'MODIFIED':<19}  NAME")
    for row in rows:
        print(
            f"{row['id']:>6}  {row['history_count']:>7}  {str(row['status']):<12.12}  "
            f"{str(row['folder']):<20.20}  {_fmt_time(row['last_modified']):<19}  {row['name']}"
        )
    print(f"Tổng: {len(rows)} scan")
    return 0


def _selected_scans(client: NctlClient, args: argparse.Namespace) -> list[dict[str, Any]]:
    include_trash = bool(getattr(args, "include_trash", False))
    folders = client.list_folders()
    trash_folder_ids = _trash_folder_ids(folders)

    if args.folder is not None:
        folder = _folder_record(client, args.folder)
        if _is_trash_folder(folder) and not include_trash:
            raise NctlError(
                "Folder Trash bị bỏ qua khi backup; thêm --include-trash để backup folder này."
            )
        folder_id = int(folder["id"])
        return _scans_in_folder(client, folder_id)

    data = client.list_scans()
    scans = list(data.get("scans") or [])
    if include_trash:
        trash_groups = [
            _scans_in_folder(client, folder_id)
            for folder_id in sorted(trash_folder_ids)
        ]
        scans = _merge_scans(scans, *trash_groups)
    else:
        scans = [scan for scan in scans if not _scan_in_folders(scan, trash_folder_ids)]

    if args.all:
        return scans
    raw_ids: list[str] = []
    if args.scan is not None:
        raw_ids.append(str(args.scan))
    if args.scans:
        raw_ids.extend(re.split(r"[\s,]+", args.scans.strip()))
    try:
        ids = {int(item) for item in raw_ids if item}
    except ValueError as exc:
        raise NctlError("Danh sách scan ID chỉ được chứa số, phân cách bởi dấu phẩy.") from exc
    selected = [scan for scan in scans if int(scan.get("id", -1)) in ids]
    missing = ids - {int(scan["id"]) for scan in selected}
    if missing:
        raise NctlError(f"Không tìm thấy scan ID: {', '.join(map(str, sorted(missing)))}")
    return selected


def _safe_name(value: Any, limit: int = 80, fallback: str = "scan") -> str:
    text = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", str(value)).strip(" ._")
    return (text or fallback)[:limit]


def _report_scans(client: NctlClient, args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.folder is not None or args.folders:
        values = [args.folder] if args.folder is not None else [
            value.strip() for item in args.folders for value in item.split(",")
            if value.strip()
        ]
        if not values:
            raise NctlError("Danh sách folder không được rỗng.")
        folder_ids = list(dict.fromkeys(_folder_id(client, value) for value in values))
        return _merge_scans(*(_scans_in_folder(client, fid) for fid in folder_ids))
    # Match backup's default for --all; explicit IDs can also select Trash scans.
    selection = argparse.Namespace(**vars(args))
    selection.include_trash = args.include_trash or not args.all
    selected = _selected_scans(client, selection)
    if not args.all and not selected:
        raise NctlError("Danh sách scan ID không được rỗng.")
    return _merge_scans(selected)


def _csv_header(reader: Any, path: Path) -> list[str]:
    header = next((row for row in reader if row), [])
    if not header or any(not name.strip() for name in header) or len(set(header)) != len(header):
        raise NctlError(f"CSV {path} không có header hợp lệ hoặc có cột trùng tên.")
    return header


def _merge_csv_files(
    paths: Sequence[Path], destination: Path, scan_names: Sequence[str],
    *, statistics: list[dict[str, Any]] | None = None,
) -> int:
    """Group records per input by all non-CVE cells, retaining each distinct CVE."""
    if not paths:
        raise NctlError("Không có file CSV thành công để gộp.")
    if len(scan_names) != len(paths):
        raise NctlError("Mỗi file CSV phải có tên scan tương ứng để ghi cột Source.")
    if any(path.resolve() == destination.resolve() for path in paths):
        raise NctlError("File CSV gộp phải khác các file nguồn.")
    previous_limit = csv.field_size_limit()
    csv.field_size_limit(2**31 - 1)  # Plugin output can exceed csv's 128 KiB default.
    partial = destination.with_suffix(destination.suffix + ".part")
    count = 0
    try:
        columns: list[str] = ["Source"]
        headers: list[list[str]] = []
        known: set[str] = {"Source"}
        for path in paths:
            with path.open(encoding="utf-8-sig", newline="") as source:
                header = _csv_header(csv.reader(source, strict=True), path)
            if "Source" in header:
                raise NctlError(f"CSV {path} đã có cột Source; không thể thêm cột tên scan.")
            headers.append(header)
            for name in header:
                if name not in known:
                    columns.append(name)
                    known.add(name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with partial.open("w", encoding="utf-8-sig", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(columns)
            positions = {name: index for index, name in enumerate(columns)}
            for path, header, scan_name in zip(paths, headers, scan_names):
                with path.open(encoding="utf-8-sig", newline="") as source:
                    reader = csv.reader(source, strict=True)
                    if _csv_header(reader, path) != header:
                        raise NctlError(f"Header CSV {path} đã thay đổi trong lúc gộp.")
                    indices = [positions[name] for name in header]
                    cve_index = header.index("CVE") if "CVE" in header else None
                    groups: dict[tuple[str, ...], tuple[list[str], dict[str, None]]] = {}
                    input_rows = 0
                    duplicates_removed = 0
                    for row in reader:
                        if not row or row == header:
                            continue
                        if len(row) != len(header):
                            raise NctlError(
                                f"CSV {path}, dòng {reader.line_num}: số ô khác số cột header."
                            )
                        input_rows += 1
                        row_key = tuple(value for index, value in enumerate(row) if index != cve_index)
                        if row_key in groups:
                            duplicates_removed += 1
                        else:
                            merged_row = [""] * len(columns)
                            merged_row[0] = scan_name
                            for index, value in zip(indices, row):
                                merged_row[index] = value
                            groups[row_key] = (merged_row, {})
                        if cve_index is not None:
                            cves = groups[row_key][1]
                            for cve in re.split(r"[\s,;]+", row[cve_index].strip()):
                                if cve:
                                    cves.setdefault(cve, None)
                    for merged_row, cves in groups.values():
                        if cve_index is not None:
                            merged_row[positions["CVE"]] = "; ".join(cves)
                        writer.writerow(merged_row)
                        count += 1
                    if statistics is not None:
                        statistics.append({
                            "file": path.name, "scan_name": scan_name,
                            "input_rows": input_rows, "unique_rows": len(groups),
                            "duplicates_removed": duplicates_removed,
                        })
        partial.replace(destination)
    except (csv.Error, UnicodeError) as exc:
        raise NctlError(f"Không đọc được CSV để gộp: {exc}") from exc
    finally:
        csv.field_size_limit(previous_limit)
        if partial.exists():
            partial.unlink()
    return count


def cmd_report(client: NctlClient, args: argparse.Namespace, _: dict[str, Any]) -> int:
    if not (0 <= args.poll_interval < float("inf")) or not (0 < args.export_timeout < float("inf")):
        raise NctlError("--poll-interval phải >= 0 và --export-timeout phải > 0 (số hữu hạn).")
    selected = _report_scans(client, args)
    if not selected:
        print("Không có scan trong phạm vi đã chọn.")
        return 0
    auto_merge = len(selected) >= 2
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")
    report_dir = Path(args.output).expanduser() / f"nctl-report-{stamp}"
    report_dir.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, Any] = {
        "created_at": datetime.now().astimezone().isoformat(),
        "server_url": client.url,
        "format": "xlsx", "history_mode": "latest", "columns": "all",
        "files": [], "errors": [],
    }
    manifest_path = report_dir / "manifest.json"
    _write_manifest(manifest_path, manifest)
    exported: list[Path] = []
    raw_exports: list[Path] = []
    scan_names: list[str] = []
    print(f"Xuất Excel đầy đủ cột cho {len(selected)} scan vào {report_dir}")
    if auto_merge and not args.merge:
        print("Tự động bật merge vì phạm vi thực tế có từ 2 scan trở lên.")
    for index, scan in enumerate(selected, 1):
        scan_id = int(scan["id"])
        destination = report_dir / f"scan-{scan_id}_{_safe_name(scan.get('name') or 'scan')}.xlsx"
        raw_destination = destination.with_suffix(".csv.raw")
        print(f"[{index}/{len(selected)}] Scan {scan_id}: {scan.get('name', '-')}")
        try:
            client.export_csv(
                scan_id, raw_destination,
                poll_interval=args.poll_interval, export_timeout=args.export_timeout,
            )
            group_stats = export_scan_xlsx(raw_destination, destination)
            exported.append(destination)
            raw_exports.append(raw_destination)
            scan_name = str(scan.get("name") or f"scan-{scan_id}")
            scan_names.append(scan_name)
            manifest["files"].append({
                "scan_id": scan_id, "scan_name": scan_name, "file": destination.name,
                **group_stats,
            })
            print(
                f"  Group: {group_stats['rows']} dòng, {group_stats['groups']} nhóm; "
                f"{group_stats['review_rows']} dòng cần xem lại; "
                f"{group_stats['truncated_cells']} ô vượt giới hạn Excel đã được rút gọn."
            )
            for detail in group_stats["truncated_details"]:
                print(
                    f"  CẢNH BÁO {destination.name}: ô {detail['cell']} "
                    f"({detail['column']}) dài {detail['original_length']} ký tự; "
                    f"đã giữ {detail['saved_length']} ký tự và highlight ô."
                )
        except (NctlError, OSError) as exc:
            manifest["errors"].append({"scan_id": scan_id, "error": str(exc)})
            print(f"LỖI scan {scan_id}: {exc}", file=sys.stderr)
        if raw_destination not in raw_exports:
            try:
                raw_destination.unlink(missing_ok=True)
            except OSError as exc:
                manifest["errors"].append({
                    "scan_id": scan_id, "stage": "cleanup", "error": str(exc),
                })
        _write_manifest(manifest_path, manifest)
    if args.merge or auto_merge:
        try:
            merged = report_dir / "merged.xlsx"
            statistics: list[dict[str, Any]] = []
            merge_result = merge_scan_xlsx(
                raw_exports, merged, scan_names, statistics=statistics,
                file_names=[path.name for path in exported],
            )
            row_count = merge_result["rows"]
            input_rows = sum(item["input_rows"] for item in statistics)
            duplicates_removed = sum(item["duplicates_removed"] for item in statistics)
            manifest["merged"] = {
                "file": merged.name, "rows": row_count, "scans": len(exported),
                "automatic": auto_merge and not args.merge,
                "input_rows": input_rows, "duplicates_removed": duplicates_removed,
                "truncated_cells": merge_result["truncated_cells"],
                "truncated_details": merge_result["truncated_details"],
                "group_by": "all_columns_except_cve", "cve_separator": "; ",
                "files": statistics,
            }
            print("Quy tắc unique: so sánh mọi cột ngoài CVE trong từng CSV; gom các CVE vào một ô.")
            for item in statistics:
                print(
                    f"  Unique {item['file']}: đọc {item['input_rows']} dòng dữ liệu; "
                    f"loại {item['duplicates_removed']} dòng trùng; giữ {item['unique_rows']} dòng unique."
                )
            print(
                f"Tổng gộp {len(exported)} report: đọc {input_rows} dòng dữ liệu; "
                f"loại {duplicates_removed} dòng trùng; giữ {row_count} dòng unique vào {merged}; "
                f"{merge_result['truncated_cells']} ô vượt giới hạn Excel đã được rút gọn."
            )
            for detail in merge_result["truncated_details"]:
                print(
                    f"  CẢNH BÁO {merged.name}: ô {detail['cell']} "
                    f"({detail['column']}) dài {detail['original_length']} ký tự; "
                    f"đã giữ {detail['saved_length']} ký tự và highlight ô."
                )
            resolved = report_dir / "merged_resolved.xlsx"
            print(f"Resolve URL nessus.org và tạo {resolved.name}...")
            try:
                resolved_result = resolve_references_xlsx(
                    merged,
                    resolved,
                    existing_truncations=merge_result["truncated_details"],
                    progress=lambda completed, total: print(
                        f"  Resolve URL: {completed}/{total}"
                    ),
                )
            except (NctlError, OSError) as exc:
                manifest["errors"].append({
                    "stage": "resolve_references", "file": resolved.name, "error": str(exc),
                })
                print(
                    f"LỖI tạo {resolved.name} sau khi đã tạo thành công {merged.name}: {exc}",
                    file=sys.stderr,
                )
            else:
                manifest["resolved"] = {
                    "file": resolved.name,
                    "rows": resolved_result["rows"],
                    "source_file": merged.name,
                    "references_column_after": "See Also",
                    "urls_found": resolved_result["urls_found"],
                    "unique_urls": resolved_result["unique_urls"],
                    "resolved_urls": resolved_result["resolved_urls"],
                    "rejected_urls": resolved_result["rejected_urls"],
                    "status_counts": resolved_result["status_counts"],
                    "resolution_details": resolved_result["resolution_details"],
                    "truncated_cells": resolved_result["truncated_cells"],
                    "truncated_details": resolved_result["truncated_details"],
                }
                print(
                    f"Đã tạo {resolved}: tìm thấy {resolved_result['urls_found']} URL nessus.org "
                    f"({resolved_result['unique_urls']} URL unique), resolve thành công "
                    f"{resolved_result['resolved_urls']}, bỏ qua {resolved_result['rejected_urls']}."
                )
                for detail in resolved_result["truncated_details"]:
                    print(
                        f"  CẢNH BÁO {resolved.name}: ô {detail['cell']} "
                        f"({detail['column']}) dài {detail['original_length']} ký tự; "
                        f"đã giữ {detail['saved_length']} ký tự và highlight ô."
                    )
        except (NctlError, OSError) as exc:
            manifest["errors"].append({"stage": "merge", "error": str(exc)})
            print(f"LỖI gộp Excel: {exc}", file=sys.stderr)
        _write_manifest(manifest_path, manifest)
    for raw_destination in raw_exports:
        try:
            raw_destination.unlink(missing_ok=True)
        except OSError as exc:
            manifest["errors"].append({
                "stage": "cleanup", "file": raw_destination.name, "error": str(exc),
            })
    _write_manifest(manifest_path, manifest)
    errors = len(manifest["errors"])
    print(f"Hoàn tất: {len(exported)}/{len(selected)} Excel; {errors} lỗi. Chi tiết: {manifest_path}")
    return 2 if errors else 0


def cmd_merge_files(
    _: NctlClient | None, args: argparse.Namespace, __: dict[str, Any],
) -> int:
    if args.folder is not None and args.folder_option is not None:
        raise NctlError("Chỉ truyền thư mục một lần: dạng positional hoặc --folder.")
    folder_value = args.folder_option if args.folder_option is not None else args.folder
    if folder_value is None:
        raise NctlError("Cần truyền thư mục chứa file CSV/XLSX để merge.")
    folder = Path(folder_value).expanduser().resolve()
    if not folder.is_dir():
        raise NctlError(f"Không tìm thấy thư mục đầu vào: {folder}")
    destination = (
        Path(args.output).expanduser().resolve()
        if args.output is not None else folder / "merged.xlsx"
    )
    if not destination.suffix:
        destination = destination.with_suffix(".xlsx")
    elif destination.suffix.casefold() != ".xlsx":
        raise NctlError("File output của lệnh merge phải có đuôi .xlsx.")
    resolved_destination = destination.with_name(f"{destination.stem}_resolved.xlsx")
    excluded_outputs = {destination.resolve(), resolved_destination.resolve()}
    candidates = sorted(
        (
            path for path in folder.iterdir()
            if path.is_file() and path.suffix.casefold() in {".csv", ".xlsx"}
            and path.resolve() not in excluded_outputs
        ),
        key=lambda path: path.name.casefold(),
    )
    if not candidates:
        raise NctlError(f"Thư mục {folder} không có file .csv hoặc .xlsx để merge.")
    source_names = [path.stem for path in candidates]
    statistics: list[dict[str, Any]] = []
    print(f"Merge offline {len(candidates)} file từ {folder}")
    for path in candidates:
        print(f"  - {path.name}")
    result = merge_scan_xlsx(
        candidates, destination, source_names, statistics=statistics,
        file_names=[path.name for path in candidates],
    )
    input_rows = sum(item["input_rows"] for item in statistics)
    duplicates_removed = sum(item["duplicates_removed"] for item in statistics)
    manifest_path = destination.with_suffix(".manifest.json")
    manifest = {
        "created_at": datetime.now().astimezone().isoformat(),
        "mode": "offline_merge", "format": "xlsx",
        "source_folder": str(folder), "output": str(destination),
        "source_fallback": "input_file_stem",
        "files": statistics,
        "rows": result["rows"], "input_rows": input_rows,
        "duplicates_removed": duplicates_removed,
        "truncated_cells": result["truncated_cells"],
        "truncated_details": result["truncated_details"],
        "group_by": "all_columns_except_cve", "cve_separator": "; ",
    }
    _write_manifest(manifest_path, manifest)
    for item in statistics:
        print(
            f"  Unique {item['file']}: đọc {item['input_rows']} dòng dữ liệu; "
            f"loại {item['duplicates_removed']} dòng trùng; giữ {item['unique_rows']} dòng unique."
        )
    for detail in result["truncated_details"]:
        print(
            f"  CẢNH BÁO {destination.name}: ô {detail['cell']} "
            f"({detail['column']}) dài {detail['original_length']} ký tự; "
            f"đã giữ {detail['saved_length']} ký tự và highlight ô."
        )
    print(
        f"Hoàn tất: đọc {input_rows} dòng; loại {duplicates_removed} dòng trùng; "
        f"ghi {result['rows']} dòng vào {destination}."
    )
    print(f"Resolve URL nessus.org và tạo {resolved_destination.name}...")
    try:
        resolved_result = resolve_references_xlsx(
            destination,
            resolved_destination,
            existing_truncations=result["truncated_details"],
            progress=lambda completed, total: print(
                f"  Resolve URL: {completed}/{total}"
            ),
        )
    except (NctlError, OSError) as exc:
        manifest["resolved_error"] = str(exc)
        _write_manifest(manifest_path, manifest)
        raise NctlError(
            f"Đã tạo {destination}, nhưng không tạo được {resolved_destination}: {exc}"
        ) from exc
    manifest["resolved"] = {
        "output": str(resolved_destination),
        "rows": resolved_result["rows"],
        "source_file": destination.name,
        "references_column_after": "See Also",
        "urls_found": resolved_result["urls_found"],
        "unique_urls": resolved_result["unique_urls"],
        "resolved_urls": resolved_result["resolved_urls"],
        "rejected_urls": resolved_result["rejected_urls"],
        "status_counts": resolved_result["status_counts"],
        "resolution_details": resolved_result["resolution_details"],
        "truncated_cells": resolved_result["truncated_cells"],
        "truncated_details": resolved_result["truncated_details"],
    }
    _write_manifest(manifest_path, manifest)
    for detail in resolved_result["truncated_details"]:
        print(
            f"  CẢNH BÁO {resolved_destination.name}: ô {detail['cell']} "
            f"({detail['column']}) dài {detail['original_length']} ký tự; "
            f"đã giữ {detail['saved_length']} ký tự và highlight ô."
        )
    print(
        f"Đã tạo {resolved_destination}: tìm thấy {resolved_result['urls_found']} URL nessus.org "
        f"({resolved_result['unique_urls']} URL unique), resolve thành công "
        f"{resolved_result['resolved_urls']}, bỏ qua {resolved_result['rejected_urls']}. "
        f"Manifest: {manifest_path}"
    )
    return 0


def _backup_folder_layout(
    folders: list[dict[str, Any]], scans: list[dict[str, Any]]
) -> tuple[dict[int | None, Path], list[dict[str, Any]]]:
    """Map máy chủ quét' flat folder model to safe, unique local directories."""
    records: dict[int, dict[str, Any]] = {}
    for folder in folders:
        try:
            records[int(folder["id"])] = folder
        except (KeyError, TypeError, ValueError):
            continue
    for scan in scans:
        try:
            folder_id = int(scan["folder_id"])
        except (KeyError, TypeError, ValueError):
            continue
        records.setdefault(
            folder_id,
            {"id": folder_id, "name": f"folder-{folder_id}", "type": "unknown"},
        )

    layout: dict[int | None, Path] = {}
    manifest_folders: list[dict[str, Any]] = []
    used_names: dict[str, int] = {}
    for folder_id, folder in sorted(records.items()):
        folder_name = str(folder.get("name") or f"folder-{folder_id}")
        local_name = _safe_name(folder_name, limit=100, fallback=f"folder-{folder_id}")
        collision_key = local_name.casefold()
        if collision_key in used_names and used_names[collision_key] != folder_id:
            local_name = f"{local_name}__folder-{folder_id}"
            collision_key = local_name.casefold()
        used_names[collision_key] = folder_id
        relative_path = Path(local_name)
        layout[folder_id] = relative_path
        manifest_folders.append(
            {
                "folder_id": folder_id,
                "folder_name": folder_name,
                "folder_type": folder.get("type"),
                "path": relative_path.as_posix(),
            }
        )

    if any(scan.get("folder_id") is None for scan in scans):
        unfiled = Path("_unfiled")
        layout[None] = unfiled
        manifest_folders.append(
            {
                "folder_id": None,
                "folder_name": None,
                "folder_type": "unknown",
                "path": unfiled.as_posix(),
            }
        )
    return layout, manifest_folders


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    temporary = path.with_suffix(".json.part")
    temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def cmd_backup(client: NctlClient, args: argparse.Namespace, config: dict[str, Any]) -> int:
    password = _db_password(args, config, "backup")
    selected = _selected_scans(client, args)
    include_trash = bool(getattr(args, "include_trash", False))
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    backup_dir = Path(args.output).expanduser() / f"nctl-backup-{stamp}"
    backup_dir.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, Any] = {
        "format_version": 2,
        "created_at": datetime.now().astimezone().isoformat(),
        "server_url": client.url,
        "history_mode": args.history,
        "preserve_folders": bool(args.all),
        "include_trash": include_trash,
        "files": [],
        "errors": [],
    }
    folder_layout: dict[int | None, Path] = {}
    if args.all:
        folders = client.list_folders()
        if not include_trash:
            folders = [folder for folder in folders if not _is_trash_folder(folder)]
        folder_layout, manifest["folders"] = _backup_folder_layout(
            folders, selected
        )
        for relative_folder in folder_layout.values():
            (backup_dir / relative_folder).mkdir(parents=True, exist_ok=True)
    manifest_path = backup_dir / "manifest.json"
    _write_manifest(manifest_path, manifest)

    jobs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for scan in selected:
        scan_id = int(scan["id"])
        try:
            histories = _history_list(client.scan_details(scan_id))
            if not histories:
                manifest["errors"].append({"scan_id": scan_id, "error": "Scan chưa có history"})
                continue
            if args.history == "latest":
                histories = [_latest_history(histories)]
            elif args.history != "all":
                wanted = int(args.history)
                histories = [h for h in histories if _history_id(h) == wanted]
                if not histories:
                    manifest["errors"].append({"scan_id": scan_id, "error": f"Không có history {wanted}"})
                    continue
            jobs.extend((scan, history) for history in histories)
        except (NctlError, ValueError) as exc:
            manifest["errors"].append({"scan_id": scan_id, "error": str(exc)})

    print(f"Backup {len(jobs)} history của {len(selected)} scan vào {backup_dir}")
    for index, (scan, history) in enumerate(jobs, 1):
        scan_id = int(scan["id"])
        hid = _history_id(history)
        filename = f"scan-{scan_id}_history-{hid}_{_safe_name(scan.get('name'))}.db"
        try:
            scan_folder_id: int | None = int(scan["folder_id"])
        except (KeyError, TypeError, ValueError):
            scan_folder_id = None
        relative_destination = (
            folder_layout.get(
                scan_folder_id,
                Path("_unfiled" if scan_folder_id is None else f"folder-{scan_folder_id}"),
            )
            / filename
            if args.all
            else Path(filename)
        )
        destination = backup_dir / relative_destination
        print(
            f"[{index}/{len(jobs)}] Scan {scan_id}, history {hid}: "
            f"{scan.get('name')} -> {relative_destination}"
        )
        try:
            client.export_db(
                scan_id,
                hid,
                password,
                destination,
                poll_interval=args.poll_interval,
                export_timeout=args.export_timeout,
            )
            manifest["files"].append(
                {
                    "file": relative_destination.as_posix(),
                    "bytes": destination.stat().st_size,
                    "scan_id": scan_id,
                    "scan_name": scan.get("name"),
                    "folder_id": scan.get("folder_id"),
                    "history_id": hid,
                    "history_uuid": history.get("uuid"),
                    "status": history.get("status"),
                }
            )
        except (NctlError, OSError) as exc:
            print(f"  LỖI: {exc}", file=sys.stderr)
            manifest["errors"].append({"scan_id": scan_id, "history_id": hid, "error": str(exc)})
        _write_manifest(manifest_path, manifest)

    print(f"Hoàn tất: {len(manifest['files'])} thành công, {len(manifest['errors'])} lỗi.")
    print(f"Manifest: {manifest_path}")
    return 1 if manifest["errors"] else 0


def _db_files(values: Sequence[str]) -> list[Path]:
    return [path for path, _ in _restore_items(values)]


def _manifest_folder_names(root: Path) -> dict[str, str]:
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        return {}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NctlError(f"Không đọc được manifest {manifest_path}: {exc}") from exc
    mappings: dict[str, str] = {}
    for item in manifest.get("folders") or []:
        if not isinstance(item, dict) or not item.get("path") or not item.get("folder_name"):
            continue
        key = Path(str(item["path"])).as_posix().casefold().strip("/")
        mappings[key] = str(item["folder_name"])
    return mappings


def _restore_items(
    values: Sequence[str], *, root_files_to_input_folder: bool = True
) -> list[tuple[Path, str | None]]:
    found: list[tuple[Path, str | None]] = []
    for value in values:
        path = Path(value).expanduser()
        if path.is_dir():
            input_folder_name = path.resolve().name
            if root_files_to_input_folder and not input_folder_name:
                raise NctlError(
                    f"Không xác định được tên folder từ đường dẫn {path}; hãy dùng --folder."
                )
            manifest_names = _manifest_folder_names(path)
            for db_path in sorted(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file() and candidate.suffix.casefold() == ".db"
            ):
                relative_parent = db_path.parent.relative_to(path)
                if relative_parent == Path("."):
                    folder_name = input_folder_name if root_files_to_input_folder else None
                else:
                    manifest_key = relative_parent.as_posix().casefold().strip("/")
                    folder_name = manifest_names.get(manifest_key) or " - ".join(
                        relative_parent.parts
                    )
                found.append((db_path, folder_name))
        elif path.is_file() and path.suffix.casefold() == ".db":
            found.append((path, None))
        else:
            raise NctlError(f"Không phải file .db hoặc thư mục hợp lệ: {path}")
    unique: list[tuple[Path, str | None]] = []
    seen: set[Path] = set()
    for path, folder_name in found:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append((path, folder_name))
    if not unique:
        raise NctlError("Không tìm thấy file .db để restore.")
    return unique


def _folder_name_cache(folders: list[dict[str, Any]]) -> dict[str, list[int]]:
    cache: dict[str, list[int]] = {}
    for folder in folders:
        try:
            folder_id = int(folder["id"])
        except (KeyError, TypeError, ValueError):
            continue
        name = str(folder.get("name") or "").strip()
        if name:
            cache.setdefault(name.casefold(), []).append(folder_id)
    return cache


def _ensure_restore_folder(
    client: NctlClient, folder_name: str, cache: dict[str, list[int]]
) -> int:
    key = folder_name.casefold()
    matches = cache.get(key, [])
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise NctlError(
            f"Có nhiều folder máy chủ quét cùng tên {folder_name!r}; không thể tự chọn folder đích."
        )
    folder_id = client.create_folder(folder_name)
    cache[key] = [folder_id]
    print(f"Đã tạo folder máy chủ quét ID {folder_id}: {folder_name}")
    return folder_id


class RestoreCheckpointError(NctlError):
    """Import succeeded but resume state could not be persisted; stop the batch."""


def _restore_checkpoint(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "completed": {}}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or state.get("version") != 1 or not isinstance(state.get("completed"), dict):
            raise ValueError("checkpoint không hợp lệ")
        return state
    except (OSError, ValueError) as exc:
        raise NctlError(f"Không đọc được checkpoint {path}: {exc}; không tự bỏ qua lỗi này.") from exc


def _save_restore_checkpoint(path: Path, state: dict[str, Any]) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".nctl-restore-", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            json.dump(state, output, ensure_ascii=False, indent=2)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _restore_key(path: Path, client: NctlClient, folder_id: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    # Scope to account too: scan/folder IDs can differ between users.
    account = client.username or client.session.headers.get("X-ApiKeys", "")
    identity = [str(client.url).rstrip("/").lower(), str(account), folder_id,
                path.name, digest.hexdigest()]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode("utf-8")).hexdigest()


def cmd_restore(client: NctlClient, args: argparse.Namespace, config: dict[str, Any]) -> int:
    items = _restore_items(
        args.paths, root_files_to_input_folder=args.folder is None
    )
    if args.flat:
        items = [(path, None) for path, _ in items]
    if args.flat and args.folder is None:
        raise NctlError("--flat cần --folder để xác định folder đích.")
    if args.create_folder and args.folder is None:
        raise NctlError("--create-folder chỉ dùng khi đã chỉ định --folder.")
    # Validate all state before making any changes on the server.
    checkpoints = {path.resolve().parent / ".nctl-restore.json" for path, _ in items}
    states = {path: _restore_checkpoint(path) for path in checkpoints}
    if args.folder is not None:
        folder_id = _folder_id(client, args.folder, create_missing=args.create_folder)
        target_folder_name = str(args.folder).strip()
    elif any(folder_name is None for _, folder_name in items):
        folder_id = _folder_id(client, "My Scans")
        target_folder_name = "My Scans"
    else:
        folder_id = None
        target_folder_name = ""
    password = _db_password(args, config, "restore")
    folder_cache = _folder_name_cache(client.list_folders())
    if target_folder_name and not target_folder_name.isdigit() and folder_id is not None:
        folder_cache.setdefault(target_folder_name.casefold(), [folder_id])
    failures = 0
    skipped = 0
    successful = 0
    child_folder_count = len({name.casefold() for _, name in items if name})
    print(
        f"Restore {len(items)} file; folder gốc ID {folder_id if folder_id is not None else '-'}; "
        f"folder con cần ánh xạ: {child_folder_count}"
    )
    for index, (path, child_folder_name) in enumerate(items, 1):
        target_folder_id = folder_id
        try:
            if child_folder_name:
                target_folder_id = _ensure_restore_folder(
                    client, child_folder_name, folder_cache
                )
            if target_folder_id is None:
                raise NctlError(f"Không xác định được folder đích cho {path}.")
            print(
                f"[{index}/{len(items)}] {path} -> "
                f"{child_folder_name or target_folder_name} (folder ID {target_folder_id})"
            )
            checkpoint_path = path.resolve().parent / ".nctl-restore.json"
            state = states[checkpoint_path]
            key = _restore_key(path, client, target_folder_id)
            if not getattr(args, "force", False) and key in state["completed"]:
                skipped += 1
                print("  SKIP - đã import thành công (checkpoint)")
                continue
            result = client.import_db(path, target_folder_id, password)
            imported = result.get("scan") if isinstance(result.get("scan"), dict) else result
            state["completed"][key] = {"file": path.name, "scan_id": imported.get("id"),
                                       "completed_at": datetime.now().isoformat()}
            try:
                _save_restore_checkpoint(checkpoint_path, state)
            except OSError as exc:
                raise RestoreCheckpointError(
                    f"ĐÃ IMPORT scan {imported.get('id', '?')} nhưng không lưu được checkpoint "
                    f"{checkpoint_path}: {exc}. Dừng restore; kiểm tra scan trước khi chạy lại để tránh trùng."
                ) from exc
            successful += 1
            print(f"  OK - scan ID: {imported.get('id', '?')}")
        except RestoreCheckpointError:
            raise
        except (NctlError, OSError) as exc:
            failures += 1
            print(f"  LỖI: {exc}", file=sys.stderr)
    print(f"Hoàn tất: {successful} thành công, {skipped} bỏ qua, {failures} lỗi.")
    return 1 if failures else 0


def _delete_selection(
    client: NctlClient, args: argparse.Namespace
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    folder: dict[str, Any] | None = None
    if args.folder is not None:
        folder = _folder_record(client, args.folder)
        folder_id = int(folder["id"])
        return _scans_in_folder(client, folder_id), folder

    data = client.list_scans()
    scans = list(data.get("scans") or [])
    if getattr(args, "permanent", False):
        folders = client.list_folders()
        trash_groups = [
            _scans_in_folder(client, folder_id)
            for folder_id in sorted(_trash_folder_ids(folders))
        ]
        scans = _merge_scans(scans, *trash_groups)
    if args.all:
        return scans, None

    raw_ids: list[str] = []
    if args.scan is not None:
        raw_ids.append(str(args.scan))
    if args.scans:
        raw_ids.extend(re.split(r"[\s,]+", args.scans.strip()))
    try:
        ids = {int(item) for item in raw_ids if item}
    except ValueError as exc:
        raise NctlError("Danh sách scan ID chỉ được chứa số, phân cách bởi dấu phẩy.") from exc
    selected = [scan for scan in scans if int(scan.get("id", -1)) in ids]
    missing = ids - {int(scan["id"]) for scan in selected}
    if missing:
        raise NctlError(f"Không tìm thấy scan ID: {', '.join(map(str, sorted(missing)))}")
    return selected, None


def _confirm_delete_password(
    client: NctlClient, args: argparse.Namespace, config: dict[str, Any]
) -> None:
    if args.non_interactive:
        raise NctlError(
            "Lệnh delete không hỗ trợ --non-interactive; phải nhập lại mật khẩu máy chủ quét."
        )
    username = _setting(args, config, "username")
    if not username:
        username = input("Tên đăng nhập máy chủ để xác nhận: ").strip()
    if not username:
        raise NctlError("Username xác nhận không được để trống.")
    password = getpass.getpass("Nhập lại mật khẩu đăng nhập máy chủ quét để xác nhận xóa: ")
    if not password:
        raise NctlError("Đã hủy: mật khẩu xác nhận để trống.")
    client.verify_login_password(str(username), password)


def cmd_delete(client: NctlClient, args: argparse.Namespace, config: dict[str, Any]) -> int:
    scans, folder = _delete_selection(client, args)
    custom_folder = bool(folder and str(folder.get("type", "")).casefold() == "custom")
    permanent = bool(getattr(args, "permanent", False))
    folders = client.list_folders()
    folders_to_delete = (
        [item for item in folders if str(item.get("type", "")).casefold() == "custom"]
        if args.all else ([folder] if custom_folder else [])
    )
    trash_folder_ids = _trash_folder_ids(folders)
    if len(trash_folder_ids) != 1:
        raise NctlError(
            "Không xác định được duy nhất folder Trash trên máy chủ quét; không thực hiện xóa."
        )
    trash_folder_id = next(iter(trash_folder_ids))
    selected_trash_folder = bool(folder and _is_trash_folder(folder))
    trash_scans = [scan for scan in scans if _scan_in_folders(scan, trash_folder_ids)]
    active_scans = [scan for scan in scans if not _scan_in_folders(scan, trash_folder_ids)]

    if selected_trash_folder:
        trash_scans = scans
        active_scans = []

    actionable_scans = scans if permanent else active_scans

    if permanent:
        print("CẢNH BÁO: thao tác sau sẽ XÓA VĨNH VIỄN dữ liệu khỏi máy chủ quét.", file=sys.stderr)
    else:
        print("CẢNH BÁO: thao tác sau sẽ chuyển scan vào folder Trash.", file=sys.stderr)
    if actionable_scans:
        action = "xóa vĩnh viễn" if permanent else "chuyển vào Trash"
        print(f"Sẽ {action} {len(actionable_scans)} scan:", file=sys.stderr)
        for scan in actionable_scans:
            print(f"  - ID {scan.get('id')}: {scan.get('name', '-')}", file=sys.stderr)
    else:
        print("Không có scan nào trong phạm vi đã chọn.", file=sys.stderr)
    if trash_scans and not permanent:
        print(
            f"Bỏ qua {len(trash_scans)} scan đã ở Trash; dùng --permanent để xóa vĩnh viễn.",
            file=sys.stderr,
        )
    if folder:
        folder_type = str(folder.get("type", "-"))
        if custom_folder:
            print(
                f"Sau đó sẽ xóa folder ID {folder['id']}: {folder.get('name', '-')}.",
                file=sys.stderr,
            )
        else:
            print(
                f"Folder hệ thống ID {folder['id']} ({folder.get('name', '-')}, type={folder_type}) "
                "sẽ được giữ lại; chỉ các scan bên trong bị xóa.",
                file=sys.stderr,
            )

    if args.all and folders_to_delete:
        print(f"Sau đó sẽ xóa {len(folders_to_delete)} folder custom nếu đã rỗng:", file=sys.stderr)
        for item in folders_to_delete:
            print(f"  - Folder ID {item['id']}: {item.get('name', '-')}", file=sys.stderr)

    if not actionable_scans and not folders_to_delete:
        print("Không có gì để xóa.")
        return 0

    if permanent:
        _confirm_delete_password(client, args, config)
        print("Xác thực thành công. Bắt đầu xóa.")
    else:
        print("Bắt đầu chuyển scan vào Trash và dọn folder đã chọn; không cần xác nhận mật khẩu.")

    scan_failures = 0
    for index, scan in enumerate(actionable_scans, 1):
        scan_id = int(scan["id"])
        try:
            was_in_trash = selected_trash_folder or _scan_in_folders(scan, trash_folder_ids)
            if not was_in_trash:
                client.move_scan(scan_id, trash_folder_id)
            if permanent:
                client.delete_scan(scan_id)
            result = "Đã xóa vĩnh viễn" if permanent else "Đã chuyển vào Trash"
            print(
                f"[{index}/{len(actionable_scans)}] {result} scan {scan_id}: "
                f"{scan.get('name', '-')}"
            )
        except NctlError as exc:
            scan_failures += 1
            print(
                f"[{index}/{len(actionable_scans)}] LỖI scan {scan_id}: {exc}",
                file=sys.stderr,
            )

    folders_deleted = 0
    folder_failures = 0
    for item in folders_to_delete:
        try:
            current_folder_id = int(item["id"])
            # Recheck after scan operations: failed moves/new scans must not be deleted.
            if _scans_in_folder(client, current_folder_id):
                folder_failures += 1
                print(f"Không xóa folder ID {current_folder_id}: vẫn còn scan bên trong.", file=sys.stderr)
                continue
            client.delete_folder(current_folder_id)
            folders_deleted += 1
            print(f"Đã xóa folder ID {current_folder_id}: {item.get('name', '-')}")
        except NctlError as exc:
            folder_failures += 1
            print(f"LỖI xóa folder ID {item['id']}: {exc}", file=sys.stderr)

    failures = scan_failures + folder_failures
    deleted = len(actionable_scans) - scan_failures + folders_deleted
    verb = "xóa vĩnh viễn" if permanent else "chuyển/xóa"
    print(f"Hoàn tất: {deleted} đối tượng đã {verb}, {failures} lỗi.")
    return 1 if failures else 0


def _valid_target(value: str) -> str:
    target = value.strip()
    if not target:
        raise ValueError("target rỗng")
    if "-" in target:
        left, sep, right = target.partition("-")
        if sep and left.strip() and right.strip():
            first = ipaddress.ip_address(left.strip())
            second = ipaddress.ip_address(right.strip())
            if first.version != second.version or int(first) > int(second):
                raise ValueError(f"IP range không hợp lệ: {target}")
            return f"{first}-{second}"
    try:
        return str(ipaddress.ip_network(target, strict=False)) if "/" in target else str(ipaddress.ip_address(target))
    except ValueError as exc:
        raise ValueError(f"IP/CIDR/range không hợp lệ: {target}") from exc


def _read_targets(path: Path) -> list[str]:
    if not path.is_file():
        raise NctlError(f"Không tìm thấy file targets: {path}")
    values: list[str] = []
    seen: set[str] = set()
    for line_no, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        for raw in re.split(r"[,\s]+", content):
            try:
                target = _valid_target(raw)
            except ValueError as exc:
                raise NctlError(f"{path}:{line_no}: {exc}") from exc
            if target not in seen:
                seen.add(target)
                values.append(target)
    if not values:
        raise NctlError(f"File {path} không có IP hợp lệ.")
    return values


_CREDENTIAL_TYPES = {
    "ssh": "SSH",
    "windows": "Windows",
    "snmpv3": "SNMPv3",
}


def _strip_json_comments(text: str) -> str:
    """Remove // and # comments outside JSON strings, preserving line breaks."""
    output: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "#" or (char == "/" and index + 1 < len(text) and text[index + 1] == "/"):
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _credential_entries(value: Any, credential_type: str) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise NctlError(
            f"credentials.{credential_type} phải là object hoặc danh sách object."
        )
    entries: list[dict[str, Any]] = []
    for index, item in enumerate(value, 1):
        if not isinstance(item, dict):
            raise NctlError(
                f"credentials.{credential_type}[{index}] phải là JSON object."
            )
        entries.append(dict(item))
    return entries


def _expand_credential_values(
    client: NctlClient, entry: dict[str, Any], config_dir: Path
) -> dict[str, Any]:
    expanded: dict[str, Any] = {}
    for key, value in entry.items():
        if key.startswith("_comment"):
            continue
        if key.endswith("_env"):
            output_key = key[:-4]
            if output_key in entry:
                raise NctlError(f"Không được khai báo đồng thời {output_key} và {key}.")
            env_name = str(value)
            env_value = os.getenv(env_name)
            if env_value is None:
                raise NctlError(f"Thiếu biến môi trường {env_name} cho credential.")
            expanded[output_key] = env_value
        elif key.endswith("_file"):
            output_key = key[:-5]
            if output_key in entry:
                raise NctlError(f"Không được khai báo đồng thời {output_key} và {key}.")
            upload_path = Path(str(value)).expanduser()
            if not upload_path.is_absolute():
                upload_path = config_dir / upload_path
            if not upload_path.is_file():
                raise NctlError(f"Không tìm thấy file credential: {upload_path}")
            expanded[output_key] = client.upload_file(upload_path, no_enc=False)
        else:
            expanded[key] = value
    return expanded


def _validate_credential(entry: dict[str, Any], kind: str, index: int) -> None:
    label = f"{kind}[{index}]"

    def require(*names: str) -> None:
        missing = [name for name in names if entry.get(name) in (None, "")]
        if missing:
            raise NctlError(f"Credential {label} thiếu field: {', '.join(missing)}")

    if kind == "ssh":
        entry.setdefault("auth_method", "password")
        require("username")
        method = str(entry["auth_method"]).casefold()
        if method == "password":
            require("password")
        elif method == "public key":
            require("private_key")
        elif method == "certificate":
            require("user_cert", "private_key")
    elif kind == "windows":
        entry.setdefault("auth_method", "Password")
        method = str(entry["auth_method"]).casefold()
        if method in {"password", "lm hash", "ntlm hash", "kerberos"}:
            require("username", "password")
        if method == "kerberos":
            require("kdc", "domain")
    elif kind == "snmpv3":
        entry.setdefault("port", 161)
        entry.setdefault("snmp_auth_method", "Password Entry")
        entry.setdefault("security_level", "Authentication and privacy")
        require("username")
        level = str(entry["security_level"]).casefold()
        if level == "authentication without privacy":
            entry.setdefault("auth_algorithm", "SHA1")
            require("auth_password")
        elif level == "authentication and privacy":
            entry.setdefault("auth_algorithm", "SHA1")
            entry.setdefault("privacy_algorithm", "AES")
            require("auth_password", "privacy_password")


def _load_scan_credentials(
    client: NctlClient, path: Path
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if not path.is_file():
        raise NctlError(f"Không tìm thấy file credential config: {path}")
    try:
        raw = json.loads(_strip_json_comments(path.read_text(encoding="utf-8-sig")))
    except (OSError, json.JSONDecodeError) as exc:
        raise NctlError(f"Không đọc được credential config {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise NctlError("Credential config phải là một JSON object.")
    unknown = {
        key
        for key in raw
        if key not in {*_CREDENTIAL_TYPES, "settings"} and not key.startswith("_comment")
    }
    if unknown:
        raise NctlError(f"Credential config có key không hỗ trợ: {', '.join(sorted(unknown))}")
    extra_settings = raw.get("settings") or {}
    if not isinstance(extra_settings, dict):
        raise NctlError("credentials.settings phải là JSON object.")
    extra_settings = {
        key: value
        for key, value in extra_settings.items()
        if not key.startswith("_comment")
    }

    host: dict[str, list[dict[str, Any]]] = {}
    for source_name, api_name in _CREDENTIAL_TYPES.items():
        if source_name not in raw:
            continue
        entries = _credential_entries(raw[source_name], source_name)
        processed: list[dict[str, Any]] = []
        for index, entry in enumerate(entries, 1):
            expanded = _expand_credential_values(client, entry, path.parent)
            _validate_credential(expanded, source_name, index)
            processed.append(expanded)
        if processed:
            host[api_name] = processed
    credentials = {"add": {"Host": host}} if host else None
    return credentials, dict(extra_settings)


def _template_uuid(client: NctlClient, requested: str | None) -> tuple[str, str]:
    templates = client.list_scan_templates()
    if requested:
        exact = [
            item
            for item in templates
            if requested.casefold()
            in {str(item.get("uuid", "")).casefold(), str(item.get("title", item.get("name", ""))).casefold()}
        ]
        if len(exact) != 1:
            raise NctlError(f"Không tìm thấy duy nhất một scan template: {requested!r}")
        item = exact[0]
    else:
        candidates = [
            item for item in templates
            if str(item.get("title", item.get("name", ""))).casefold() == "advanced scan"
            or str(item.get("name", "")).casefold() == "advanced"
        ]
        if not candidates:
            raise NctlError("Không tìm thấy template 'Advanced Scan'; hãy dùng --template.")
        item = candidates[0]
    uuid = item.get("uuid")
    if not uuid:
        raise NctlError("Scan template không có UUID.")
    return str(uuid), str(item.get("title") or item.get("name") or uuid)


def _created_scan_id(result: dict[str, Any]) -> int:
    candidate = result.get("scan") if isinstance(result.get("scan"), dict) else result
    if candidate.get("id") is None:
        raise NctlError(f"máy chủ quét đã tạo task nhưng không trả về scan ID: {result}")
    return int(candidate["id"])


def cmd_task_create(client: NctlClient, args: argparse.Namespace, _: dict[str, Any]) -> int:
    targets = _read_targets(Path(args.targets))
    template_uuid, template_name = _template_uuid(client, args.template)
    folder_id = _folder_id(client, args.folder) if args.folder else None
    credentials: dict[str, Any] | None = None
    extra_settings: dict[str, Any] = {}
    if args.credentials_file:
        credentials, extra_settings = _load_scan_credentials(
            client, Path(args.credentials_file).expanduser()
        )
    result = client.create_scan(
        template_uuid,
        args.name,
        targets,
        folder_id=folder_id,
        scanner_id=args.scanner_id,
        safe=not args.unsafe,
        credentials=credentials,
        extra_settings=extra_settings,
    )
    scan_id = _created_scan_id(result)
    print(f"Đã tạo scan ID {scan_id}: {args.name}")
    print(f"Template: {template_name}; targets: {len(targets)}")
    print(
        "Safety: "
        + ("safe_checks=yes, stop_scan_on_disconnect=yes" if not args.unsafe else "DISABLED (--unsafe)")
    )
    if credentials:
        host = credentials["add"]["Host"]
        print("Credentials: " + ", ".join(f"{name}={len(items)}" for name, items in host.items()))
    if args.launch:
        scan_uuid = client.launch_scan(scan_id)
        print(f"Đã launch scan; scan UUID: {scan_uuid or '-'}")
    return 0


def cmd_task_launch(client: NctlClient, args: argparse.Namespace, _: dict[str, Any]) -> int:
    scan_uuid = client.launch_scan(args.scan_id)
    print(f"Đã launch scan {args.scan_id}; scan UUID: {scan_uuid or '-'}")
    return 0


def _progress(details: dict[str, Any]) -> tuple[str, str]:
    info = details.get("info") if isinstance(details.get("info"), dict) else {}
    status = str(info.get("status") or "unknown").lower()
    direct = info.get("progress")
    if direct is not None:
        return status, f"{direct}%"
    hosts = details.get("hosts") or []
    progresses: list[int] = []
    for host in hosts:
        raw = str(host.get("progress", "")).split("-", 1)[0]
        try:
            progresses.append(max(0, min(100, int(raw))))
        except ValueError:
            continue
    if progresses:
        done = sum(1 for value in progresses if value >= 100)
        return status, f"{sum(progresses) / len(progresses):.1f}% ({done}/{len(progresses)} host xong)"
    return status, f"0% (0/{len(hosts)} host xong)"


def cmd_monitor(client: NctlClient, args: argparse.Namespace, _: dict[str, Any]) -> int:
    started = time.monotonic()
    while True:
        details = client.scan_details(args.scan_id)
        status, progress = _progress(details)
        now = datetime.now().astimezone().strftime("%H:%M:%S")
        print(f"[{now}] scan {args.scan_id}: {status}; {progress}", flush=True)
        if args.once or status in TERMINAL_SCAN_STATES:
            return 0 if status not in {"canceled", "cancelled", "aborted"} else 1
        if args.timeout and time.monotonic() - started >= args.timeout:
            raise NctlError(f"Monitor quá thời hạn {args.timeout:g} giây.")
        time.sleep(args.interval)


class NctlArgumentParser(argparse.ArgumentParser):
    """Attach offline examples to root and every command's --help."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        super().__init__(*args, **kwargs)
        topic = " ".join(self.prog.split()[1:])
        self.epilog = TOPICS.get(topic, OVERVIEW if not topic else None)


def build_parser() -> argparse.ArgumentParser:
    parser = NctlArgumentParser(
        prog="nctl",
        description="Backup, restore, xuất report Excel, tạo và theo dõi scan trên máy chủ quét.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, default=Path("config.json"), help="JSON config (mặc định: config.json)")
    parser.add_argument("--url", help=f"URL máy chủ (mặc định: {DEFAULT_URL})")
    parser.add_argument("--username", help="Tên đăng nhập máy chủ")
    parser.add_argument("--access-key", help="API access key")
    parser.add_argument("--secret-key", help="API secret key")
    parser.add_argument("--verify-tls", action="store_true", default=None, help="Xác thực chứng chỉ TLS")
    parser.add_argument("--timeout", dest="http_timeout", type=float, help="HTTP timeout (giây)")
    parser.add_argument("--non-interactive", action="store_true", help="Không hỏi input; lấy credentials/password từ config hoặc env")
    sub = parser.add_subparsers(dest="command", required=True)

    help_command = sub.add_parser("help", help="Hướng dẫn offline kèm ví dụ sử dụng")
    help_command.add_argument(
        "topic", nargs="*", metavar="TOPIC",
        help="setup, status, folders, scans, backup, report, merge, restore, delete, task [create|launch], monitor",
    )
    help_command.epilog = "Ví dụ: nctl help; nctl help setup; nctl help task create"

    status = sub.add_parser("status", help="Kiểm tra kết nối")
    status.set_defaults(handler=cmd_status)

    folders = sub.add_parser("folders", help="Liệt kê folders")
    folders.set_defaults(handler=cmd_folders)

    scans = sub.add_parser("scans", help="Liệt kê scans và số history")
    scans.add_argument("--folder", help="Folder ID hoặc tên")
    scans.add_argument("--json", action="store_true", help="Xuất JSON")
    scans.set_defaults(handler=cmd_scans)

    backup = sub.add_parser("backup", help="Backup scan histories thành máy chủ quét DB")
    selector = backup.add_mutually_exclusive_group(required=True)
    selector.add_argument("--scan", type=int, help="Một scan ID")
    selector.add_argument("--scans", help="Nhiều scan ID, phân cách bằng dấu phẩy")
    selector.add_argument("--folder", help="Folder ID hoặc tên")
    selector.add_argument("--all", action="store_true", help="Toàn bộ scans")
    backup.add_argument(
        "--include-trash",
        action="store_true",
        help="Bao gồm scan trong Trash (mặc định bỏ qua)",
    )
    backup.add_argument("--history", default="all", help="all, latest hoặc history ID (mặc định: all)")
    backup.add_argument("--output", default="backups", help="Thư mục chứa lượt backup")
    backup.add_argument("--poll-interval", type=float, default=1.0, help="Chu kỳ kiểm tra export")
    backup.add_argument("--export-timeout", type=float, default=1800, help="Timeout mỗi export")
    backup.set_defaults(handler=cmd_backup)

    report = sub.add_parser("report", help="Xuất report Excel đầy đủ cột, mỗi scan một file")
    report_selector = report.add_mutually_exclusive_group(required=True)
    report_selector.add_argument("--scan", type=int, help="Một scan ID")
    report_selector.add_argument("--scans", help="Danh sách scan ID, phân cách bằng dấu phẩy")
    report_selector.add_argument("--folder", help="Một folder ID hoặc tên")
    report_selector.add_argument("--folders", nargs="+", help="Nhiều folder ID/tên, cách bằng dấu cách hoặc dấu phẩy")
    report_selector.add_argument("--all", action="store_true", help="Toàn bộ scan (mặc định bỏ qua Trash)")
    report.add_argument("--include-trash", action="store_true", help="Bao gồm Trash khi dùng --all")
    report.add_argument("--output", default="reports", help="Thư mục chứa lượt report (mặc định: reports)")
    report.add_argument(
        "--merge", action="store_true",
        help="Gộp thêm merged.xlsx khi chỉ chọn 1 scan; từ 2 scan trở lên tự động merge",
    )
    report.add_argument("--poll-interval", type=float, default=1.0, help="Chu kỳ kiểm tra export (giây)")
    report.add_argument("--export-timeout", type=float, default=1800, help="Timeout mỗi export (giây)")
    report.set_defaults(handler=cmd_report)

    merge = sub.add_parser("merge", help="Merge offline các file CSV/XLSX trong một thư mục")
    merge.add_argument("folder", nargs="?", type=Path, help="Thư mục chứa file CSV/XLSX")
    merge.add_argument("--folder", dest="folder_option", type=Path, help="Thư mục chứa file CSV/XLSX")
    merge.add_argument("--output", type=Path, help="File Excel đầu ra (mặc định: <folder>/merged.xlsx)")
    merge.set_defaults(handler=cmd_merge_files, offline=True)

    restore = sub.add_parser("restore", help="Restore hàng loạt file .db")
    restore.add_argument("paths", nargs="+", help="File .db hoặc thư mục (tìm đệ quy)")
    restore.add_argument(
        "--folder", help="Đổi folder đích cho file .db trực tiếp hoặc --flat: ID hoặc tên"
    )
    restore.add_argument(
        "--create-folder", action="store_true", help="Tạo --folder nếu tên chưa tồn tại"
    )
    restore.add_argument(
        "--flat",
        action="store_true",
        help="Bỏ qua thư mục con và restore tất cả file vào --folder (bắt buộc)",
    )
    restore.set_defaults(handler=cmd_restore)
    restore.add_argument("--force", action="store_true", help="Import lại cả file đã thành công trong checkpoint (có thể tạo scan trùng)")

    delete = sub.add_parser(
        "delete", help="Chuyển scan vào Trash; --permanent cần xác nhận mật khẩu"
    )
    delete_selector = delete.add_mutually_exclusive_group(required=True)
    delete_selector.add_argument("--scan", type=int, help="Chọn một scan ID")
    delete_selector.add_argument("--scans", help="Chọn nhiều scan ID, phân cách bằng dấu phẩy")
    delete_selector.add_argument(
        "--folder",
        help="Chọn scan theo folder ID/tên; folder tùy chỉnh được xóa sau khi rỗng",
    )
    delete_selector.add_argument("--all", action="store_true", help="Chọn toàn bộ scan và dọn folder custom đã rỗng")
    delete.add_argument(
        "--permanent",
        action="store_true",
        help="Xóa vĩnh viễn thay vì chuyển scan vào Trash",
    )
    delete.set_defaults(handler=cmd_delete)

    task = sub.add_parser("task", help="Tạo hoặc launch scan task")
    task_sub = task.add_subparsers(dest="task_command", required=True)
    create = task_sub.add_parser("create", help="Tạo task từ file IP")
    create.add_argument("--targets", required=True, help="File IP/CIDR/range")
    create.add_argument("--name", required=True, help="Tên scan")
    create.add_argument("--template", help="Tên hoặc UUID template; mặc định Advanced Scan")
    create.add_argument("--folder", help="Folder ID hoặc tên")
    create.add_argument("--scanner-id", type=int, help="Scanner ID")
    create.add_argument(
        "--credentials-file",
        help="JSON/JSONC cấu hình tài khoản SSH, Windows và SNMPv3",
    )
    create.add_argument(
        "--unsafe",
        action="store_true",
        help="Tắt safe checks và không dừng quét host mất phản hồi",
    )
    create.add_argument("--launch", action="store_true", help="Launch ngay sau khi tạo")
    create.set_defaults(handler=cmd_task_create)
    launch = task_sub.add_parser("launch", help="Launch một scan đã có")
    launch.add_argument("scan_id", type=int)
    launch.set_defaults(handler=cmd_task_launch)

    monitor = sub.add_parser("monitor", help="Theo dõi tiến độ một scan")
    monitor.add_argument("scan_id", type=int)
    monitor.add_argument("--interval", type=float, default=5.0, help="Chu kỳ cập nhật")
    monitor.add_argument("--timeout", type=float, default=0, help="Timeout tổng; 0 là không giới hạn")
    monitor.add_argument("--once", action="store_true", help="Chỉ lấy trạng thái một lần")
    monitor.set_defaults(handler=cmd_monitor)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    # Windows service shells can inherit CP1252 even when the source and terminal
    # support UTF-8.  Keep Vietnamese messages usable in both console and logs.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")
    parser = build_parser()
    command_args = list(sys.argv[1:] if argv is None else argv)
    if not command_args:
        parser.print_help()
        return 0
    args = parser.parse_args(command_args)
    if args.command == "help":
        topic = " ".join(args.topic)
        if topic:
            if topic not in TOPICS:
                parser.error(f"Không có chủ đề help {topic!r}; dùng nctl help để xem hướng dẫn.")
            print(TOPICS[topic])
        else:
            print(OVERVIEW)
            for name, guide in TOPICS.items():
                print(f"--- {name} ---\n{guide}")
        return 0
    client: NctlClient | None = None
    try:
        if getattr(args, "offline", False):
            return int(args.handler(None, args, {}))
        config = _load_config(args.config)
        client = _make_client(args, config)
        return int(args.handler(client, args, config))
    except KeyboardInterrupt:
        print("\nĐã dừng theo yêu cầu.", file=sys.stderr)
        return 130
    except (NctlError, OSError, ValueError) as exc:
        print(f"LỖI: {exc}", file=sys.stderr)
        return 2
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
