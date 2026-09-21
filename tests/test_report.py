import csv
import io
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

import requests
import xlsxwriter

from nctl.app import _merge_csv_files, _report_scans, build_parser, cmd_report, main
from nctl.client import CSV_COLUMNS, NctlClient, NctlError
from nctl.report_excel import export_scan_xlsx, merge_scan_xlsx, reflow_narrative
from nctl.report_groups import add_group_column, group_for_finding


def write_csv(path, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as output:
        csv.writer(output).writerows(rows)


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        return list(csv.reader(source))


def read_xlsx(path):
    namespace = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    with zipfile.ZipFile(path) as archive:
        shared = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            shared = ["".join(node.text or "" for node in item.findall(".//x:t", namespace))
                      for item in root.findall("x:si", namespace)]
        sheet = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
    rows = []
    for xml_row in sheet.findall(".//x:sheetData/x:row", namespace):
        values = []
        for cell in xml_row.findall("x:c", namespace):
            reference = cell.attrib["r"]
            letters = "".join(character for character in reference if character.isalpha())
            column = 0
            for letter in letters:
                column = column * 26 + ord(letter.upper()) - 64
            while len(values) < column - 1:
                values.append("")
            if cell.attrib.get("t") == "inlineStr":
                value = "".join(node.text or "" for node in cell.findall(".//x:t", namespace))
            else:
                node = cell.find("x:v", namespace)
                raw = node.text if node is not None and node.text is not None else ""
                value = shared[int(raw)] if cell.attrib.get("t") == "s" and raw else raw
            values.append(value)
        rows.append(values)
    return rows


def write_xlsx(path, rows):
    with xlsxwriter.Workbook(str(path)) as workbook:
        worksheet = workbook.add_worksheet("Data")
        for row_number, row in enumerate(rows):
            for column, value in enumerate(row):
                worksheet.write_string(row_number, column, value)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.client.list_folders.return_value = [
            {"id": 1, "name": "My Scans", "type": "main"},
            {"id": 2, "name": "Group 2", "type": "custom"},
            {"id": 3, "name": "Trash", "type": "trash"},
        ]
        self.scans = [
            {"id": 10, "name": "Linux", "folder_id": 1},
            {"id": 20, "name": "Windows", "folder_id": 2},
            {"id": 30, "name": "Deleted", "folder_id": 3},
        ]
        self.client.list_scans.side_effect = lambda folder_id=None: {
            "scans": self.scans if folder_id is None else [
                scan for scan in self.scans if scan["folder_id"] == folder_id
            ]
        }

    def test_all_selectors_and_deduplication(self):
        cases = [
            (["--scan", "10"], [10]),
            (["--scans", "10,20,10"], [10, 20]),
            (["--folder", "my scans"], [10]),
            (["--folders", "My Scans", "Group 2", "1"], [10, 20]),
            (["--folders", "1,2,1"], [10, 20]),
            (["--all"], [10, 20]),
            (["--all", "--include-trash"], [10, 20, 30]),
            (["--folder", "Trash"], [30]),
            (["--scan", "30"], [30]),
        ]
        for flags, expected in cases:
            with self.subTest(flags=flags):
                args = build_parser().parse_args(["report", *flags])
                self.assertEqual([s["id"] for s in _report_scans(self.client, args)], expected)

    def test_invalid_or_missing_selections(self):
        for flags in (["--scans", "abc"], ["--scans", ","], ["--scan", "999"],
                      ["--folders", ","], ["--folders", "Missing"]):
            with self.subTest(flags=flags), self.assertRaises(NctlError):
                _report_scans(self.client, build_parser().parse_args(["report", *flags]))

    def test_ambiguous_folder_requires_id(self):
        self.client.list_folders.return_value.append({"id": 4, "name": "Group 2"})
        args = build_parser().parse_args(["report", "--folder", "Group 2"])
        with self.assertRaisesRegex(NctlError, "folder ID"):
            _report_scans(self.client, args)


class GroupTests(unittest.TestCase):
    def test_name_patterns_cover_software_updates_without_a_package_allowlist(self):
        cases = [
            ("Ubuntu 22.04 LTS : Linux kernel vulnerabilities (USN-7510-1)",
             "Security updates / Ubuntu / Linux kernel", {}),
            ("Ubuntu 22.04 LTS : libexample vulnerabilities (USN-9999-1)",
             "Security updates / Ubuntu / libexample", {}),
            ("RHEL 8 : kernel:4.18.0 (RHSA-2025:1068)",
             "Security updates / RHEL / kernel", {}),
            ("RHEL 8 : Bug fix of NetworkManager (Moderate) (RHSA-2025:0288)",
             "Security updates / RHEL / NetworkManager", {}),
            ("RockyLinux 8 : libxml2 (RLSA-2025:10698)",
             "Security updates / RockyLinux / libxml2", {}),
            ("Security Updates for Microsoft .NET Framework (May 2020)",
             "Security updates / Microsoft .NET Framework", {}),
            ("Security Update for Windows Defender (May 2026) (CVE-2026-41091)",
             "Security updates / Windows Defender", {}),
            ("Security Updates for Microsoft Malware Protection Engine (July 2026)",
             "Security updates / Microsoft Malware Protection Engine", {}),
            ("KB5021237: Windows 10 version 1809 / Windows Server 2019 Security Update (December 2022)",
             "Security updates / Windows OS", {}),
            ("Google Chrome < 137.0.7151.40 Multiple Vulnerabilities",
             "Security updates / Google Chrome", {"Solution": "Upgrade to Google Chrome version 137 or later."}),
            ("Microsoft Edge (Chromium) < 137.0.3296.52 Multiple Vulnerabilities",
             "Security updates / Microsoft Edge", {}),
            ("Apache Log4j 2.0-beta9 < 2.25.3 MitM",
             "Security updates / Apache Log4j", {"Solution": "Upgrade to Apache Log4j version 2.25.3."}),
            ("Fortinet Fortigate Firewall deny policy bypass (FG-IR-23-432)",
             "Security updates / Fortinet FortiGate",
             {"Synopsis": "Fortinet Firewall is missing one or more security-related updates."}),
            ("Notepad++ <= 8.9.3 Stack-based Buffer Overflow (CVE-2026-5525)",
             "Security updates / Notepad++", {}),
            ("Apache Tomcat 9.0.0.M1 < 9.0.105",
             "Security updates / Apache Tomcat", {"Solution": "Upgrade to Apache Tomcat 9.0.105."}),
            ("NVIDIA Container Toolkit 1.17.1 Multiple Vulnerabilities (2025_01)",
             "Security updates / NVIDIA Container Toolkit", {"Solution": "Upgrade to NVIDIA Container Toolkit 1.17.1."}),
            ("Trellix Agent < 5.8.1 Buffer Overflow Vulnerability (SB10416)",
             "Security updates / Trellix Agent", {}),
            ("IBM QRadar 7.5.x < 7.5.0 UP14 IF2 Information Disclosure (7253664)",
             "Security updates / IBM QRadar SIEM", {"Solution": "Upgrade to IBM QRadar 7.5.0."}),
            ("Apache Commons FileUpload < 1.6 , 2.0.0-M1 < 2.0.0-M4 Denial of Service (CVE-2025-48976)",
             "Security updates / Apache Commons FileUpload", {}),
            ("Windows Defender Antimalware/Antivirus Signature Definition Check",
             "Security updates / Windows Defender", {"Solution": "Trigger an update manually."}),
        ]
        for name, expected, extras in cases:
            with self.subTest(name=name):
                self.assertEqual(group_for_finding({"Name": name, "Risk": "High", **extras}), expected)

    def test_informational_configuration_review_and_none_risk_update(self):
        self.assertEqual(
            group_for_finding({"Name": "Ubuntu 22.04 LTS : Sudo vulnerability (USN-8092-1)",
                               "Risk": "None", "Synopsis": "The host is missing a security update."}),
            "Security updates / Ubuntu / Sudo",
        )
        self.assertEqual(group_for_finding({"Name": "Google Chrome Detection (Windows)", "Risk": "None"}),
                         "Information / Google Chrome Detection (Windows)")
        self.assertEqual(group_for_finding({"Name": "Apache Log4j Installed (Linux / Unix)", "Risk": "None"}),
                         "Information / Apache Log4j Installed (Linux / Unix)")
        self.assertEqual(group_for_finding({"Name": "SSL Certificate Cannot Be Trusted", "Risk": "Medium"}),
                         "Configuration / SSL Certificate Cannot Be Trusted")
        self.assertEqual(group_for_finding({"Name": "Unknown Vendor Finding", "Risk": "High", "Plugin ID": "42"}),
                         "Cần xem lại / Plugin 42")
        self.assertEqual(group_for_finding({
            "Name": "Foo Connector issue", "Risk": "High",
            "Solution": "Upgrade to Foo Connector version 1.2 or later.",
            "Plugin Output": "Installed version : 1.0\nFixed version : 1.2",
        }), "Security updates / Foo Connector")
        self.assertEqual(group_for_finding({
            "Name": "Foo Connector issue", "Risk": "High", "Plugin ID": "43",
            "Solution": "Upgrade to Foo Connector version 1.2 or later.",
        }), "Cần xem lại / Plugin 43")
        self.assertEqual(
            group_for_finding({"Name": "Google Chrome < 137.0 Multiple Vulnerabilities",
                               "Risk": "High", "Host": "192.0.2.99", "Source": "Another scan"}),
            group_for_finding({"Name": "Google Chrome < 137.0 Multiple Vulnerabilities",
                               "Risk": "High", "Host": "192.0.2.1", "Source": "First scan"}),
        )

    def test_add_group_column_preserves_rows_and_uses_atomic_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "raw.csv", root / "scan.csv"
            header = ["Plugin ID", "Risk", "Name", "Host", "Plugin Output"]
            rows = [
                ["1", "High", "Google Chrome < 137.0 Multiple Vulnerabilities", "192.0.2.1", "line 1\nline 2, quoted"],
                ["2", "High", "Google Chrome < 138.0 Multiple Vulnerabilities", "192.0.2.2", "other"],
                ["3", "None", "Google Chrome Detection (Windows)", "192.0.2.1", "detected"],
            ]
            write_csv(source, [header, *rows])
            original = source.read_bytes()
            self.assertEqual(add_group_column(source, destination),
                             {"rows": 3, "groups": 2, "review_rows": 0})
            self.assertEqual(read_csv(destination), [
                [*header, "Group"],
                [*rows[0], "Security updates / Google Chrome"],
                [*rows[1], "Security updates / Google Chrome"],
                [*rows[2], "Information / Google Chrome Detection (Windows)"],
            ])
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse((root / "scan.csv.part").exists())

    def test_bad_csv_keeps_previous_output_and_removes_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "raw.csv", root / "scan.csv"
            source.write_text('Name,Risk\n"unfinished,High\n', encoding="utf-8")
            destination.write_bytes(b"previous")
            with self.assertRaises(NctlError):
                add_group_column(source, destination)
            self.assertEqual(destination.read_bytes(), b"previous")
            self.assertFalse((root / "scan.csv.part").exists())
            write_csv(source, [["Risk", "Plugin ID"], ["High", "42"]])
            with self.assertRaisesRegex(NctlError, "header"):
                add_group_column(source, destination)
            self.assertEqual(destination.read_bytes(), b"previous")


class ExcelReportTests(unittest.TestCase):
    def test_reflow_narrative_removes_soft_wraps_and_keeps_structure(self):
        source = (
            "It is possible to determine the exact time set on the remote host.\r\n\r\n"
            "The remote host answers to an ICMP timestamp request.  This allows an\r\n"
            "attacker to know the date that is set on the targeted machine, which\r\n"
            "may assist an unauthenticated, remote attacker.\r\n\r\n"
            "Timestamps returned from Windows Vista / 7 / 2008 /\r\n"
            "2008 R2 are deliberately incorrect."
        )
        self.assertEqual(reflow_narrative(source), (
            "It is possible to determine the exact time set on the remote host.\n\n"
            "The remote host answers to an ICMP timestamp request. This allows an "
            "attacker to know the date that is set on the targeted machine, which "
            "may assist an unauthenticated, remote attacker.\n\n"
            "Timestamps returned from Windows Vista / 7 / 2008 / 2008 R2 are deliberately incorrect."
        ))
        structured = (
            "Actions:\n- Install the update\n- Restart the service\n\n"
            "https://example.test/advisory\nhttps://example.test/fix\n\n"
            "    command --flag\n    output"
        )
        self.assertEqual(reflow_narrative(structured), structured)

    def test_reflow_only_changes_merged_narrative_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "raw.csv"
            scan = root / "scan.xlsx"
            merged = root / "merged.xlsx"
            description = "First sentence continues on the\nnext display line.\n\nSecond paragraph."
            solution = "Upgrade the affected\npackage to the latest version."
            plugin_output = "package: old\npackage: fixed"
            write_csv(source, [
                ["Name", "Risk", "Synopsis", "Description", "Solution", "Plugin Output"],
                ["Detection", "None", "Short summary", description, solution, plugin_output],
            ])
            export_scan_xlsx(source, scan)
            self.assertEqual(read_xlsx(scan)[1][3], description)
            self.assertEqual(read_xlsx(scan)[1][4], solution)
            self.assertEqual(read_xlsx(scan)[1][5], plugin_output)
            merge_scan_xlsx([source], merged, ["Scan"])
            row = dict(zip(read_xlsx(merged)[0], read_xlsx(merged)[1]))
            self.assertEqual(
                row["Description"],
                "Short summary\n\nFirst sentence continues on the next display line.\n\nSecond paragraph.",
            )
            self.assertEqual(row["Solution"], "Upgrade the affected package to the latest version.")
            self.assertEqual(row["Plugin Output"], plugin_output)

    def test_scan_workbook_preserves_original_columns_and_appends_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "raw.csv", root / "scan.xlsx"
            header = ["Plugin ID", "CVE", "Protocol", "Port", "Name", "Synopsis", "Description", "Risk"]
            row = ["1", "CVE-1", "tcp", "443", "Google Chrome < 2 Multiple Vulnerabilities",
                   "Short summary", "Long description", "High"]
            write_csv(source, [header, row])
            result = export_scan_xlsx(source, destination)
            self.assertEqual(result, {
                "rows": 1, "truncated_cells": 0, "truncated_details": [],
                "groups": 1, "review_rows": 0,
            })
            self.assertEqual(read_xlsx(destination), [
                [*header, "Group"], [*row, "Security updates / Google Chrome"],
            ])

    def test_merged_workbook_reorders_combines_and_consolidates_cves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "raw.csv", root / "merged.xlsx"
            header = ["Plugin ID", "CVE", "Risk", "Host", "Protocol", "Port", "Name",
                      "Synopsis", "Description", "Solution", "See Also", "Plugin Output", "Score"]
            common = ["1", "High", "192.0.2.1", "tcp", "443",
                      "Google Chrome < 2 Multiple Vulnerabilities", "Short summary", "Long description",
                      "Upgrade", "https://example.test", "line 1\nline 2", "9.8"]
            write_csv(source, [header, [common[0], "CVE-1", *common[1:]],
                                       [common[0], "CVE-2", *common[1:]]])
            statistics = []
            result = merge_scan_xlsx([source], destination, ["Weekly Scan"], statistics=statistics,
                                     file_names=["scan-1.xlsx"])
            self.assertEqual(result, {"rows": 1, "truncated_cells": 0, "truncated_details": []})
            self.assertEqual(read_xlsx(destination), [
                ["Source", "Group", "Name", "Risk", "Host", "Location", "Description", "Solution",
                 "Plugin Output", "See Also", "CVE", "Plugin ID", "Score"],
                ["Weekly Scan", "Security updates / Google Chrome",
                 "Google Chrome < 2 Multiple Vulnerabilities", "High", "192.0.2.1", "tcp/443",
                 "Short summary\n\nLong description", "Upgrade", "line 1\nline 2",
                 "https://example.test", "CVE-1; CVE-2", "1", "9.8"],
            ])
            self.assertEqual(statistics, [{
                "file": "scan-1.xlsx", "scan_name": "Weekly Scan", "input_rows": 2,
                "unique_rows": 1, "duplicates_removed": 1,
            }])

    def test_excel_header_and_sheet_navigation_formatting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "raw.csv", root / "scan.xlsx"
            write_csv(source, [["Name", "Risk", "Plugin Output"],
                               ["Detection", "None", "first\nsecond"]])
            export_scan_xlsx(source, destination)
            namespace = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            with zipfile.ZipFile(destination) as archive:
                sheet = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
                styles = ET.fromstring(archive.read("xl/styles.xml"))
            xfs = styles.findall(".//x:cellXfs/x:xf", namespace)
            fonts = styles.findall(".//x:fonts/x:font", namespace)
            for cell in sheet.findall(".//x:sheetData/x:row/x:c", namespace):
                alignment = xfs[int(cell.attrib["s"])].find("x:alignment", namespace)
                self.assertIsNotNone(alignment)
                self.assertEqual(alignment.attrib.get("vertical"), "top")
                self.assertNotEqual(alignment.attrib.get("wrapText"), "1")
            header_cell = sheet.find(".//x:sheetData/x:row[@r='1']/x:c", namespace)
            header_style = xfs[int(header_cell.attrib["s"])]
            self.assertIsNotNone(fonts[int(header_style.attrib["fontId"])].find("x:b", namespace))
            pane = sheet.find(".//x:sheetViews/x:sheetView/x:pane", namespace)
            self.assertEqual(pane.attrib.get("state"), "frozen")
            self.assertEqual(pane.attrib.get("ySplit"), "1")
            self.assertEqual(sheet.find("x:autoFilter", namespace).attrib["ref"], "A1:D2")

    def test_excel_cell_limit_is_counted_and_truncated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "raw.csv", root / "scan.xlsx"
            write_csv(source, [["Name", "Risk", "Plugin Output"],
                               ["Detection", "None", "x" * 40000]])
            result = export_scan_xlsx(source, destination)
            self.assertEqual(result["truncated_cells"], 1)
            self.assertEqual(result["truncated_details"], [{
                "cell": "C2", "column": "Plugin Output", "original_length": 40000,
                "saved_length": 32767,
            }])
            self.assertEqual(len(read_xlsx(destination)[1][2]), 32767)
            namespace = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            with zipfile.ZipFile(destination) as archive:
                sheet = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
                styles = ET.fromstring(archive.read("xl/styles.xml"))
            cell = sheet.find(".//x:c[@r='C2']", namespace)
            style = styles.findall(".//x:cellXfs/x:xf", namespace)[int(cell.attrib["s"])]
            self.assertNotEqual(style.attrib.get("fillId"), "0")


class MergeTests(unittest.TestCase):
    def test_combines_cves_only_when_every_other_column_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "a.csv", root / "b.csv"
            header = ["CVE", "Host", "Plugin ID", "Score", "Plugin Output"]
            finding = ["192.0.2.1", "236880", "7.8", 'Tiếng Việt, "quoted"\noutput']
            rows = [
                ["CVE-2024-26982", *finding],
                ["CVE-2024-47726", *finding],
                ["CVE-2024-26982", *finding],
                ["CVE-2024-47726; CVE-2024-56599, CVE-2024-26982", *finding],
                ["", *finding],
                ["CVE-2024-26982", *finding[:2], "9.8", finding[3]],
                ["CVE-2024-26982", *finding[:3], "different output"],
                ["", "192.0.2.2", *finding[1:]],
            ]
            write_csv(first, [header, *rows])
            write_csv(second, [header, rows[0], rows[1]])
            stats = []
            merged = root / "merged.csv"
            self.assertEqual(_merge_csv_files([first, second], merged, ["A", "B"], statistics=stats), 5)
            self.assertEqual(read_csv(merged), [
                ["Source", *header],
                ["A", "CVE-2024-26982; CVE-2024-47726; CVE-2024-56599", *finding],
                ["A", *rows[5]], ["A", *rows[6]], ["A", *rows[7]],
                ["B", "CVE-2024-26982; CVE-2024-47726", *finding],
            ])
            self.assertEqual([s["input_rows"] for s in stats], [8, 2])
            self.assertEqual([s["duplicates_removed"] for s in stats], [4, 1])
            self.assertEqual([s["unique_rows"] for s in stats], [4, 1])
            self.assertEqual(read_csv(first), [header, *rows])

    def test_deduplicates_full_rows_per_file_preserving_order_and_scan_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "a.csv", root / "b.csv"
            header = ["Host", "Plugin ID", "Plugin Output"]
            row = ["192.0.2.1", "1", 'Tiếng Việt, "quoted"\nsecond line']
            different_plugin = ["192.0.2.1", "2", row[2]]
            different_output = ["192.0.2.1", "1", row[2] + " "]
            write_csv(first, [header, row, different_plugin, row, different_output, different_plugin])
            write_csv(second, [header, row, row])
            originals = [first.read_bytes(), second.read_bytes()]
            merged = root / "merged.csv"
            statistics = []
            self.assertEqual(_merge_csv_files([first, second], merged, ["Scan A", "Scan B"],
                                             statistics=statistics), 4)
            self.assertEqual(statistics, [
                {"file": "a.csv", "scan_name": "Scan A", "input_rows": 5,
                 "unique_rows": 3, "duplicates_removed": 2},
                {"file": "b.csv", "scan_name": "Scan B", "input_rows": 2,
                 "unique_rows": 1, "duplicates_removed": 1},
            ])
            self.assertEqual(read_csv(merged), [
                ["Source", *header], ["Scan A", *row], ["Scan A", *different_plugin],
                ["Scan A", *different_output], ["Scan B", *row],
            ])
            self.assertEqual([first.read_bytes(), second.read_bytes()], originals)

    def test_preserves_cells_rows_and_only_one_header(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second, empty = [root / name for name in ("a.csv", "b.csv", "empty.csv")]
            header = ["Plugin ID", "Host", "Plugin Output"]
            rows = [["1", "192.0.2.1", 'Tiếng Việt, "quoted"\r\nsecond line'],
                    ["2", "192.0.2.2", "x" * 200000]]
            write_csv(first, [header, rows[0], header])
            write_csv(second, [header, rows[1]])
            write_csv(empty, [header])
            destination = root / "merged.csv"
            names = ['Quét A, "Linux"\nweekly', "Quét B/Windows", "Empty"]
            statistics = []
            self.assertEqual(_merge_csv_files([first, second, empty], destination, names,
                                             statistics=statistics), 2)
            self.assertEqual([item["input_rows"] for item in statistics], [1, 1, 0])
            self.assertEqual([item["duplicates_removed"] for item in statistics], [0, 0, 0])
            previous_limit = csv.field_size_limit(2**31 - 1)
            try:
                self.assertEqual(read_csv(destination), [["Source", *header],
                                                       [names[0], *rows[0]], [names[1], *rows[1]]])
            finally:
                csv.field_size_limit(previous_limit)
            self.assertTrue(destination.read_bytes().startswith(b"\xef\xbb\xbf"))

    def test_union_of_columns_and_reordered_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a, b, c = [root / name for name in ("a.csv", "b.csv", "c.csv")]
            write_csv(a, [["id", "output"], ["1", "text"]])
            write_csv(b, [["score", "id"], ["9.1", "2"]])
            write_csv(c, [["output", "id"], ["other", "3"]])
            merged = root / "merged.csv"
            self.assertEqual(_merge_csv_files([a, b, c], merged, ["A", "B", "C"]), 3)
            self.assertEqual(read_csv(merged), [
                ["Source", "id", "output", "score"], ["A", "1", "text", ""],
                ["B", "2", "", "9.1"], ["C", "3", "other", ""],
            ])

    def test_bad_csv_does_not_publish_partial_merge_or_overwrite_existing(self):
        bad_inputs = ["", "id,id\n1,2\n", "id,output\n1\n", 'id,output\n1,"unfinished',
                      "Source,id\nexisting,1\n"]
        for content in bad_inputs:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, merged = root / "bad.csv", root / "merged.csv"
                source.write_text(content, encoding="utf-8")
                merged.write_bytes(b"existing")
                with self.assertRaises(NctlError):
                    _merge_csv_files([source], merged, ["Scan"])
                self.assertEqual(merged.read_bytes(), b"existing")
                self.assertFalse((root / "merged.csv.part").exists())

    def test_merge_cannot_overwrite_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.csv"
            write_csv(source, [["id"], ["1"]])
            with self.assertRaises(NctlError):
                _merge_csv_files([source], source, ["Scan"])
            self.assertEqual(read_csv(source), [["id"], ["1"]])


class ReportTests(unittest.TestCase):
    def test_truncated_cell_is_logged_and_recorded_in_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock(url="https://scanner.example")
            client.list_folders.return_value = []
            client.list_scans.return_value = {"scans": [{"id": 1, "name": "Weekly"}]}
            client.export_csv.side_effect = lambda scan_id, destination, **kwargs: write_csv(
                destination,
                [["Name", "Risk", "Plugin Output"], ["Detection", "None", "x" * 40000]],
            )
            args = build_parser().parse_args([
                "report", "--all", "--merge", "--output", directory,
            ])
            output = io.StringIO()
            with patch("sys.stdout", new=output), patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(cmd_report(client, args, {}), 0)
            root = next(Path(directory).iterdir())
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            detail = manifest["files"][0]["truncated_details"][0]
            self.assertEqual(detail, {
                "cell": "C2", "column": "Plugin Output", "original_length": 40000,
                "saved_length": 32767,
            })
            self.assertEqual(manifest["merged"]["truncated_details"], [{
                "cell": "I2", "column": "Plugin Output", "original_length": 40000,
                "saved_length": 32767,
            }])
            self.assertIn("CẢNH BÁO", output.getvalue())
            self.assertIn("ô C2 (Plugin Output) dài 40000 ký tự", output.getvalue())
            self.assertIn("ô I2 (Plugin Output) dài 40000 ký tự", output.getvalue())

    def test_separate_files_optional_merge_and_partial_export_failure(self):
        for merge, fail in ((False, False), (True, False), (True, True)):
            with self.subTest(merge=merge, fail=fail), tempfile.TemporaryDirectory() as directory:
                client = Mock()
                client.url = "https://scanner.example"
                client.list_folders.return_value = []
                client.list_scans.return_value = {"scans": [
                    {"id": 1, "name": "Quét/Linux"}, {"id": 2, "name": 'Windows, "weekly"'},
                    {"id": 3, "name": "Quét:Linux"},
                ]}

                def export(scan_id, destination, **kwargs):
                    if fail and scan_id == 2:
                        raise NctlError("Export failed")
                    name = ("Microsoft Edge (Chromium) < 137.0 Multiple Vulnerabilities"
                            if scan_id == 2 else "Google Chrome < 137.0 Multiple Vulnerabilities")
                    row = [str(scan_id), f"192.0.2.{scan_id}", name, "High", "data\nmore"]
                    write_csv(destination, [["id", "Host", "Name", "Risk", "output"], row, row])

                client.export_csv.side_effect = export
                args = build_parser().parse_args([
                    "report", "--all", "--output", directory, *(["--merge"] if merge else []),
                ])
                output = io.StringIO()
                with patch("sys.stdout", new=output), patch("sys.stderr", new=io.StringIO()):
                    self.assertEqual(cmd_report(client, args, {}), 2 if fail else 0)
                root = next(Path(directory).iterdir())
                manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(len(manifest["files"]), 2 if fail else 3)
                self.assertEqual(len(manifest["errors"]), int(fail))
                self.assertEqual(client.export_csv.call_count, 3)
                self.assertTrue((root / "merged.xlsx").exists())
                for item in manifest["files"]:
                    original_rows = read_xlsx(root / item["file"])
                    self.assertEqual(original_rows[0], ["id", "Host", "Name", "Risk", "output", "Group"])
                    self.assertEqual(len(original_rows), 3)
                    self.assertEqual(original_rows[1][-1],
                                     "Security updates / Microsoft Edge" if item["scan_id"] == 2
                                     else "Security updates / Google Chrome")
                    self.assertEqual(item["rows"], 2)
                    self.assertEqual(item["groups"], 1)
                self.assertFalse(list(root.glob("*.raw")))
                self.assertEqual(manifest["merged"]["rows"], 2 if fail else 3)
                self.assertEqual(manifest["merged"]["input_rows"], 4 if fail else 6)
                self.assertEqual(manifest["merged"]["duplicates_removed"], 2 if fail else 3)
                self.assertEqual(len(manifest["merged"]["files"]), 2 if fail else 3)
                self.assertIn("đọc 2 dòng dữ liệu; loại 1 dòng trùng; giữ 1 dòng unique", output.getvalue())
                self.assertIn(
                    "đọc 4 dòng dữ liệu; loại 2 dòng trùng; giữ 2 dòng unique" if fail else
                    "đọc 6 dòng dữ liệu; loại 3 dòng trùng; giữ 3 dòng unique", output.getvalue(),
                )
                self.assertEqual(read_xlsx(root / "merged.xlsx"), [
                    ["Source", "Group", "Name", "Risk", "Host", "Location", "Description",
                     "Solution", "Plugin Output", "See Also", "CVE", "id", "output"],
                    ["Quét/Linux", "Security updates / Google Chrome",
                     "Google Chrome < 137.0 Multiple Vulnerabilities", "High", "192.0.2.1",
                     "", "", "", "", "", "", "1", "data\nmore"],
                    *([] if fail else [["Windows, \"weekly\"", "Security updates / Microsoft Edge",
                                         "Microsoft Edge (Chromium) < 137.0 Multiple Vulnerabilities",
                                         "High", "192.0.2.2", "", "", "", "", "", "", "2",
                                         "data\nmore"]]),
                    ["Quét:Linux", "Security updates / Google Chrome",
                     "Google Chrome < 137.0 Multiple Vulnerabilities", "High", "192.0.2.3",
                    "", "", "", "", "", "", "3", "data\nmore"],
                ])

    def test_two_resolved_scans_auto_merge_for_all_selector_types(self):
        cases = [
            ["--scans", "1,2,1"],
            ["--folder", "Team A"],
            ["--folders", "Team A", "Empty"],
            ["--all"],
        ]
        for flags in cases:
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as directory:
                client = Mock(url="https://scanner.example")
                client.list_folders.return_value = [
                    {"id": 7, "name": "Team A", "type": "custom"},
                    {"id": 8, "name": "Empty", "type": "custom"},
                ]
                scans = [
                    {"id": 1, "name": "One", "folder_id": 7},
                    {"id": 2, "name": "Two", "folder_id": 7},
                ]
                client.list_scans.side_effect = lambda folder_id=None: {
                    "scans": scans if folder_id is None or folder_id == 7 else [],
                }
                client.export_csv.side_effect = lambda scan_id, destination, **kwargs: write_csv(
                    destination,
                    [["Name", "Risk"], [f"Detection {scan_id}", "None"]],
                )
                args = build_parser().parse_args([
                    "report", *flags, "--output", directory,
                ])
                output = io.StringIO()
                with patch("sys.stdout", new=output), patch("sys.stderr", new=io.StringIO()):
                    self.assertEqual(cmd_report(client, args, {}), 0)
                root = next(Path(directory).iterdir())
                self.assertTrue((root / "merged.xlsx").exists())
                self.assertIn("Tự động bật merge", output.getvalue())

    def test_one_scan_does_not_auto_merge_without_option(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock(url="https://scanner.example")
            client.list_folders.return_value = []
            client.list_scans.return_value = {"scans": [{"id": 1, "name": "One"}]}
            client.export_csv.side_effect = lambda scan_id, destination, **kwargs: write_csv(
                destination, [["Name", "Risk"], ["Detection", "None"]],
            )
            args = build_parser().parse_args([
                "report", "--scans", "1,1", "--output", directory,
            ])
            with patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(cmd_report(client, args, {}), 0)
            root = next(Path(directory).iterdir())
            self.assertFalse((root / "merged.xlsx").exists())

    def test_all_failed_exports_do_not_create_merged_excel(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock(url="https://scanner.example")
            client.list_folders.return_value = []
            client.list_scans.return_value = {"scans": [{"id": 1}]}
            client.export_csv.side_effect = NctlError("no results")
            args = build_parser().parse_args(["report", "--all", "--merge", "--output", directory])
            with patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(cmd_report(client, args, {}), 2)
            self.assertFalse(list(Path(directory).rglob("*.xlsx")))


class OfflineMergeTests(unittest.TestCase):
    def test_merge_folder_accepts_csv_and_xlsx_and_runs_without_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_header = [
                "Plugin ID", "CVE", "Risk", "Host", "Protocol", "Port", "Name",
                "Synopsis", "Description", "Solution", "See Also", "Plugin Output",
            ]
            common = [
                "1", "High", "192.0.2.1", "tcp", "443",
                "Google Chrome < 2 Multiple Vulnerabilities", "Summary", "Details",
                "Upgrade", "https://example.test", "output",
            ]
            write_csv(root / "raw-scan.csv", [
                csv_header,
                [common[0], "CVE-1", *common[1:]],
                [common[0], "CVE-2", *common[1:]],
            ])
            xlsx_header = [
                "Source", "Group", "Name", "Risk", "Host", "Location", "Description",
                "Solution", "Plugin Output", "See Also", "CVE", "Extra",
            ]
            write_xlsx(root / "existing.xlsx", [xlsx_header, [
                "Original Source", "Existing Group", "Existing Finding", "Medium", "192.0.2.2",
                "udp/53", "Already combined", "Fix", "evidence", "https://existing.test",
                "CVE-3", "kept",
            ]])
            output = io.StringIO()
            with patch("nctl.app._load_config") as load_config, \
                    patch("sys.stdout", new=output), patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(main(["merge", str(root)]), 0)
                load_config.assert_not_called()
            merged = root / "merged.xlsx"
            manifest_path = root / "merged.manifest.json"
            self.assertTrue(merged.exists())
            self.assertTrue(manifest_path.exists())
            self.assertEqual(read_xlsx(merged), [
                ["Source", "Group", "Name", "Risk", "Host", "Location", "Description",
                 "Solution", "Plugin Output", "See Also", "CVE", "Extra", "Plugin ID"],
                ["Original Source", "Existing Group", "Existing Finding", "Medium", "192.0.2.2",
                 "udp/53", "Already combined", "Fix", "evidence", "https://existing.test",
                 "CVE-3", "kept", ""],
                ["raw-scan", "Security updates / Google Chrome",
                 "Google Chrome < 2 Multiple Vulnerabilities", "High", "192.0.2.1", "tcp/443",
                 "Summary\n\nDetails", "Upgrade", "output", "https://example.test",
                 "CVE-1; CVE-2", "", "1"],
            ])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["mode"], "offline_merge")
            self.assertEqual(manifest["input_rows"], 3)
            self.assertEqual(manifest["duplicates_removed"], 1)
            self.assertIn("Merge offline 2 file", output.getvalue())

            # The current output is excluded when the command is run again.
            with patch("nctl.app._load_config") as load_config, \
                    patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(main(["merge", "--folder", str(root)]), 0)
                load_config.assert_not_called()
            self.assertEqual(len(read_xlsx(merged)), 3)

    def test_merge_folder_requires_supported_input(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()):
            Path(directory, "notes.txt").write_text("nothing", encoding="utf-8")
            self.assertEqual(main(["merge", directory]), 2)


class ClientTests(unittest.TestCase):
    def make_client(self):
        client = NctlClient.__new__(NctlClient)
        client.post_json = Mock(return_value={"token": "csv/token"})
        client.get_json = Mock(side_effect=[{"status": "loading"}, {"status": "ready"}])
        self.response = Mock()
        self.response.iter_content.return_value = [b"id,output\r\n", b"1,test\r\n"]
        client._request = Mock(return_value=self.response)
        return client

    def test_full_columns_poll_and_download(self):
        client = self.make_client()
        with tempfile.TemporaryDirectory() as directory, patch("nctl.client.time.sleep"):
            output = Path(directory) / "scan.csv"
            client.export_csv(12, output)
            self.assertEqual(read_csv(output), [["id", "output"], ["1", "test"]])
            self.assertFalse(output.with_suffix(".csv.part").exists())
        payload = client.post_json.call_args.kwargs["json"]
        self.assertEqual(payload["format"], "csv")
        self.assertEqual(payload["reportContents"]["csvColumns"], dict.fromkeys(CSV_COLUMNS, True))
        self.assertIn("plugin_output", payload["reportContents"]["csvColumns"])
        client.get_json.assert_called_with("/tokens/csv%2Ftoken/status")
        client._request.assert_called_once_with(
            "GET", "/tokens/csv%2Ftoken/download", stream=True, timeout=300,
        )
        self.response.close.assert_called_once()

    def test_failed_export_missing_token_and_timeout(self):
        for status in ("failed", "error", "canceled", "cancelled"):
            client = self.make_client()
            client.get_json.side_effect = None
            client.get_json.return_value = {"status": status}
            with self.subTest(status=status), self.assertRaises(NctlError):
                client.export_csv(12, Path("unused.csv"))
            client._request.assert_not_called()
        client = self.make_client()
        client.post_json.return_value = {}
        with self.assertRaisesRegex(NctlError, "token"):
            client.export_csv(12, Path("unused.csv"))
        client = self.make_client()
        with patch("nctl.client.time.monotonic", side_effect=[0, 2]), self.assertRaisesRegex(NctlError, "thời hạn"):
            client.export_csv(12, Path("unused.csv"), export_timeout=1)

    def test_interrupted_download_cleans_partial_and_keeps_previous(self):
        client = self.make_client()
        client.get_json.side_effect = None
        client.get_json.return_value = {"status": "ready"}

        def chunks(**kwargs):
            yield b"partial"
            raise requests.ConnectionError("interrupted")

        self.response.iter_content.side_effect = chunks
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scan.csv"
            output.write_bytes(b"previous")
            with self.assertRaisesRegex(NctlError, "gián đoạn"):
                client.export_csv(12, output)
            self.assertEqual(output.read_bytes(), b"previous")
            self.assertFalse(output.with_suffix(".csv.part").exists())
        self.response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
