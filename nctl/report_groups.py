"""Deterministic, host-independent labels for exported scan findings."""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

from .client import NctlError


_OS_ADVISORY = re.compile(r"^(Ubuntu|RHEL|RockyLinux)\b[^:]*:\s*(.+)$", re.I)
_SECURITY_UPDATES = re.compile(r"^Security Updates? for\s+(.+)$", re.I)
_KB_UPDATE = re.compile(r"^KB\d+:\s*(.+?)\s+Security Update\b", re.I)
_VERSION_COMPARISON = re.compile(r"\s(?:<=|<|>=|>)\s")
_DATE = re.compile(
    r"^(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+\d{4}$",
    re.I,
)
_TRAILING_PAREN = re.compile(r"\s*\(([^()]*)\)\s*$")
_REFERENCE = re.compile(r"^(?:CVE-\d{4}-\d+|USN-\d+-\d+|R[HL]SA-\d{4}:\d+)$", re.I)
_ADVISORY = re.compile(r"\b(?:USN-\d+-\d+|R[HL]SA-\d{4}:\d+)\b", re.I)
_COMPONENT_VERSION = re.compile(r":\d[\w.+-]*$")
_PRODUCT_VERSION = re.compile(r"\s+\d[\w.+-]*$")
_GENERIC_ENDING = re.compile(
    r"\s+(?:multiple\s+)?(?:vulnerability|vulnerabilities|security updates?|update)$",
    re.I,
)
_CONFIGURATION = re.compile(
    r"^(?:ICMP|SSL|TLS|SSH|SMB|Remote Desktop|Terminal Services|"
    r"WinVerifyTrust|Windows Speculative)\b",
    re.I,
)
_MISSING_UPDATE = re.compile(r"\bmissing\b.*\b(?:security|updates?|patch(?:es)?)\b", re.I)
_REMEDIATION = re.compile(r"\b(?:upgrade|update|patch|security updates?)\b", re.I)
_VULNERABILITY = re.compile(r"\b(?:vulnerabilit\w*|CVE-\d{4}-\d+|security update|DoS)\b", re.I)
_VERSIONED_NAME = re.compile(r"^(.+?)\s+\d[\w.+-]*\s+(?:Multiple\s+)?Vulnerabilit\w*\b", re.I)
_INSTALLED_EVIDENCE = re.compile(r"\b(?:Installed (?:version|package)|Remote package installed)\s*:", re.I)
_FIXED_EVIDENCE = re.compile(r"\b(?:Fixed (?:version|package)|Should be)\s*:", re.I)
_SOLUTION_PRODUCT = re.compile(
    r"^(?:Upgrade to|Update)\s+(.+?)\s+(?:to\s+)?version\s+\S+", re.I
)


def _clean(value: Any) -> str:
    return " ".join(str(value or "").split())


def _strip_references(value: str) -> str:
    result = value.strip()
    while match := _TRAILING_PAREN.search(result):
        suffix = match.group(1).strip()
        if not (_REFERENCE.fullmatch(suffix) or _DATE.fullmatch(suffix)
                or suffix.casefold() in {"critical", "important", "moderate", "medium", "low"}):
            break
        result = result[:match.start()].strip()
    return result


def _product(value: str) -> str:
    product = _strip_references(_clean(value))
    product = re.sub(r"^Bug fix of\s+", "", product, flags=re.I)
    product = _GENERIC_ENDING.sub("", product)
    product = _COMPONENT_VERSION.sub("", product)
    product = _PRODUCT_VERSION.sub("", product)
    aliases = {
        "ibm qradar": "IBM QRadar SIEM",
        "ibm qradar siem": "IBM QRadar SIEM",
        "microsoft edge (chromium)": "Microsoft Edge",
        "microsoft defender": "Windows Defender",
        "windows defender": "Windows Defender",
        "fortinet fortigate": "Fortinet FortiGate",
    }
    return aliases.get(product.casefold(), product)


def group_for_finding(finding: dict[str, str]) -> str:
    """Return one stable group label without using Source or Host."""
    name = _clean(finding.get("Name"))
    synopsis = _clean(finding.get("Synopsis"))
    solution = _clean(finding.get("Solution"))
    plugin_output = _clean(finding.get("Plugin Output"))
    risk = _clean(finding.get("Risk") or finding.get("Risk Factor"))
    plugin_id = _clean(finding.get("Plugin ID")) or "unknown"

    os_match = _OS_ADVISORY.match(name)
    if os_match and (_ADVISORY.search(name) or _MISSING_UPDATE.search(synopsis)
                     or _REMEDIATION.search(solution)):
        component = _product(os_match.group(2))
        if component:
            os_name = {"ubuntu": "Ubuntu", "rhel": "RHEL", "rockylinux": "RockyLinux"}[
                os_match.group(1).casefold()
            ]
            return f"Security updates / {os_name} / {component}"

    product_match = _SECURITY_UPDATES.match(name)
    if product_match:
        product = _product(product_match.group(1))
        if product:
            return f"Security updates / {product}"

    kb_match = _KB_UPDATE.match(name)
    if kb_match:
        target = _product(kb_match.group(1))
        if re.match(r"^Windows\b", target, re.I):
            target = "Windows OS"
        if target:
            return f"Security updates / {target}"

    # Detection/inventory plugins must not become update findings just because
    # their names start with a product name (e.g. Google Chrome Detection).
    if risk.casefold() in {"", "none"}:
        return f"Information / {name or f'Plugin {plugin_id}'}"

    if re.match(r"^Fortinet\s+Fortigate\b", name, re.I) and (
        _MISSING_UPDATE.search(synopsis) or _REMEDIATION.search(solution)
    ):
        return "Security updates / Fortinet FortiGate"

    comparator = _VERSION_COMPARISON.search(name)
    if comparator and (_VULNERABILITY.search(name) or _REMEDIATION.search(solution)):
        product = _product(name[:comparator.start()])
        if product:
            return f"Security updates / {product}"

    versioned_name = _VERSIONED_NAME.match(name)
    if versioned_name and _REMEDIATION.search(solution):
        product = _product(versioned_name.group(1))
        if product:
            return f"Security updates / {product}"

    if re.match(r"^Windows Defender\b", name, re.I) and _REMEDIATION.search(solution):
        return "Security updates / Windows Defender"

    # For less structured names, require both version evidence from Nessus and
    # an explicit product in the remediation text instead of guessing a package.
    solution_product = _SOLUTION_PRODUCT.match(solution)
    if (solution_product and _INSTALLED_EVIDENCE.search(plugin_output)
            and _FIXED_EVIDENCE.search(plugin_output)):
        product = _product(solution_product.group(1))
        if product:
            return f"Security updates / {product}"

    if _CONFIGURATION.match(name):
        return f"Configuration / {name}"
    return f"Cần xem lại / Plugin {plugin_id}"


def add_group_column(source: Path, destination: Path) -> dict[str, Any]:
    """Write a classified CSV atomically, preserving every original record."""
    partial = destination.with_suffix(destination.suffix + ".part")
    previous_limit = csv.field_size_limit()
    csv.field_size_limit(2**31 - 1)
    counts: dict[str, int] = {}
    rows = 0
    try:
        with source.open(encoding="utf-8-sig", newline="") as input_file:
            reader = csv.reader(input_file, strict=True)
            header = next((row for row in reader if row), [])
            if (not header or "Name" not in header or "Group" in header
                    or any(not name.strip() for name in header) or len(set(header)) != len(header)):
                raise NctlError(f"CSV {source} không có header hợp lệ hoặc đã có cột Group.")
            with partial.open("w", encoding="utf-8-sig", newline="") as output_file:
                writer = csv.writer(output_file)
                writer.writerow([*header, "Group"])
                for row in reader:
                    if not row or row == header:
                        continue
                    if len(row) != len(header):
                        raise NctlError(
                            f"CSV {source}, dòng {reader.line_num}: số ô khác số cột header."
                        )
                    group = group_for_finding(dict(zip(header, row)))
                    writer.writerow([*row, group])
                    counts[group] = counts.get(group, 0) + 1
                    rows += 1
        partial.replace(destination)
    except (csv.Error, UnicodeError) as exc:
        raise NctlError(f"Không đọc được CSV {source} để phân nhóm: {exc}") from exc
    finally:
        csv.field_size_limit(previous_limit)
        if partial.exists():
            partial.unlink()
    return {"rows": rows, "groups": len(counts),
            "review_rows": sum(count for name, count in counts.items() if name.startswith("Cần xem lại / "))}
