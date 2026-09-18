import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from nctl.app import _merge_csv_files, _report_scans, build_parser, cmd_report
from nctl.client import CSV_COLUMNS, NctlClient, NctlError


def write_csv(path, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as output:
        csv.writer(output).writerows(rows)


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        return list(csv.reader(source))


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
                    row = [str(scan_id), "192.0.2.1", "data\nmore"]
                    write_csv(destination, [["id", "Host", "output"], row, row])

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
                self.assertEqual((root / "merged.csv").exists(), merge)
                for item in manifest["files"]:
                    original_rows = read_csv(root / item["file"])
                    self.assertEqual(original_rows[0], ["id", "Host", "output"])
                    self.assertEqual(len(original_rows), 3)
                if merge:
                    self.assertEqual(manifest["merged"]["rows"], 2 if fail else 3)
                    self.assertEqual(manifest["merged"]["input_rows"], 4 if fail else 6)
                    self.assertEqual(manifest["merged"]["duplicates_removed"], 2 if fail else 3)
                    self.assertEqual(len(manifest["merged"]["files"]), 2 if fail else 3)
                    self.assertIn("đọc 2 dòng dữ liệu; loại 1 dòng trùng; giữ 1 dòng unique", output.getvalue())
                    self.assertIn(
                        "đọc 4 dòng dữ liệu; loại 2 dòng trùng; giữ 2 dòng unique" if fail else
                        "đọc 6 dòng dữ liệu; loại 3 dòng trùng; giữ 3 dòng unique", output.getvalue(),
                    )
                    self.assertEqual(read_csv(root / "merged.csv"), [
                        ["Source", "id", "Host", "output"], ["Quét/Linux", "1", "192.0.2.1", "data\nmore"],
                        *([] if fail else [['Windows, "weekly"', "2", "192.0.2.1", "data\nmore"]]),
                        ["Quét:Linux", "3", "192.0.2.1", "data\nmore"],
                    ])

    def test_all_failed_exports_do_not_create_merged_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock(url="https://scanner.example")
            client.list_folders.return_value = []
            client.list_scans.return_value = {"scans": [{"id": 1}]}
            client.export_csv.side_effect = NctlError("no results")
            args = build_parser().parse_args(["report", "--all", "--merge", "--output", directory])
            with patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(cmd_report(client, args, {}), 2)
            self.assertFalse(list(Path(directory).rglob("*.csv")))


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
