import io
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import xlsxwriter

from nctl.app import main
from nctl.client import NctlError
from nctl.report_mask import mask_workbook, unmask_workbook


_NS = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def write_workbook(path, sheets):
    with xlsxwriter.Workbook(str(path)) as workbook:
        for name, rows in sheets:
            worksheet = workbook.add_worksheet(name)
            bold = workbook.add_format({"bold": True})
            for row_number, row in enumerate(rows):
                for column, value in enumerate(row):
                    worksheet.write_string(
                        row_number, column, value, bold if row_number == 0 else None,
                    )


def add_excel_compatibility_namespaces(path):
    temporary = path.with_suffix(".namespaces.xlsx")
    marker = '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    replacement = (
        marker
        + ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
        + ' xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"'
        + ' mc:Ignorable="x14ac xr xr2 xr3"'
        + ' xmlns:x14ac="http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac"'
        + ' xmlns:xr="http://schemas.microsoft.com/office/spreadsheetml/2014/revision"'
        + ' xmlns:xr2="http://schemas.microsoft.com/office/spreadsheetml/2015/revision2"'
        + ' xmlns:xr3="http://schemas.microsoft.com/office/spreadsheetml/2016/revision3"'
        + ' xr:uid="{00000000-0001-0000-0000-000000000000}"'
    )
    with zipfile.ZipFile(path) as source, zipfile.ZipFile(temporary, "w") as destination:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename == "xl/worksheets/sheet1.xml":
                xml = data.decode("utf-8")
                if marker not in xml:
                    raise AssertionError("Không tìm thấy worksheet root để tạo fixture namespace")
                xml = xml.replace(marker, replacement, 1)
                xml = xml.replace(
                    "<sheetFormatPr ", '<sheetFormatPr x14ac:dyDescent="0.25" ', 1,
                )
                data = xml.encode("utf-8")
            destination.writestr(item, data)
    temporary.replace(path)


def replace_cell_with_empty_shared_string(path, cell_reference, shared_index=15):
    temporary = path.with_suffix(".shared-empty.xlsx")
    with zipfile.ZipFile(path) as source, zipfile.ZipFile(temporary, "w") as destination:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename == "xl/sharedStrings.xml":
                root = ET.fromstring(data)
                items = root.findall("x:si", _NS)
                while len(items) <= shared_index:
                    value = "" if len(items) == shared_index else f"padding-{len(items)}"
                    item_node = ET.SubElement(root, f"{{{_NS['x']}}}si")
                    text_node = ET.SubElement(item_node, f"{{{_NS['x']}}}t")
                    text_node.text = value
                    items.append(item_node)
                root.set("uniqueCount", str(len(items)))
                data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
            elif item.filename == "xl/worksheets/sheet1.xml":
                root = ET.fromstring(data)
                cell = root.find(f".//x:c[@r='{cell_reference}']", _NS)
                if cell is None:
                    raise AssertionError(f"Không tìm thấy cell {cell_reference} trong fixture")
                for child in list(cell):
                    cell.remove(child)
                cell.set("t", "s")
                value_node = ET.SubElement(cell, f"{{{_NS['x']}}}v")
                value_node.text = str(shared_index)
                data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
            destination.writestr(item, data)
    temporary.replace(path)


def cell_xml(path, cell_reference, sheet_number=1):
    with zipfile.ZipFile(path) as archive:
        root = ET.fromstring(archive.read(f"xl/worksheets/sheet{sheet_number}.xml"))
    cell = root.find(f".//x:c[@r='{cell_reference}']", _NS)
    if cell is None:
        raise AssertionError(f"Không tìm thấy cell {cell_reference}")
    return cell


def read_sheet(path, sheet_number=1):
    with zipfile.ZipFile(path) as archive:
        shared = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            shared = [
                "".join(node.text or "" for node in item.findall(".//x:t", _NS))
                for item in root.findall("x:si", _NS)
            ]
        root = ET.fromstring(archive.read(f"xl/worksheets/sheet{sheet_number}.xml"))
    result = []
    for xml_row in root.findall(".//x:sheetData/x:row", _NS):
        values = []
        for cell in xml_row.findall("x:c", _NS):
            reference = cell.attrib["r"]
            letters = "".join(character for character in reference if character.isalpha())
            column = 0
            for letter in letters:
                column = column * 26 + ord(letter.upper()) - 64
            while len(values) < column - 1:
                values.append("")
            if cell.attrib.get("t") == "inlineStr":
                value = "".join(node.text or "" for node in cell.findall(".//x:t", _NS))
            else:
                node = cell.find("x:v", _NS)
                raw = node.text if node is not None and node.text is not None else ""
                value = shared[int(raw)] if cell.attrib.get("t") == "s" and raw else raw
            values.append(value)
        result.append(values)
    return result


class MaskingTests(unittest.TestCase):
    def test_mask_and_unmask_preserve_columns_and_blank_plugin_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "report.xlsx"
            masked = root / "report_masked.xlsx"
            mapping = root / "report.mask.enc"
            unmasked = root / "report_unmasked.xlsx"
            write_workbook(source, [
                ("Report", [
                    ["Name", "Host", "Location", "Plugin Output"],
                    ["A", "192.0.2.10", "tcp/443", "sensitive evidence"],
                    ["B", "192.0.2.10", "tcp/80", "more evidence"],
                ]),
                ("Second", [
                    ["Host", "Location", "Plugin Output"],
                    ["192.0.2.10", "tcp/443", "other evidence"],
                ]),
            ])

            result = mask_workbook(source, masked, mapping, "strong password")
            first = read_sheet(masked)
            second = read_sheet(masked, 2)
            self.assertEqual(first[0], ["Name", "Host", "Location", "Plugin Output"])
            self.assertRegex(
                first[1][1],
                r"^\[\[HOST:(?:[0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{2}\]\]$",
            )
            self.assertRegex(
                first[1][2],
                r"^\[\[LOCATION:(?:[0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{2}\]\]$",
            )
            self.assertEqual(first[1][1], first[2][1])
            self.assertEqual(first[1][1], second[1][0])
            self.assertEqual(first[1][2], second[1][1])
            self.assertEqual([first[1][3], first[2][3], second[1][2]], ["", "", ""])
            self.assertEqual(result["plugin_output_cells_cleared"], 3)
            self.assertNotIn(b"192.0.2.10", mapping.read_bytes())
            with zipfile.ZipFile(masked) as archive:
                extracted_xml = b"".join(
                    archive.read(name) for name in archive.namelist() if name.endswith(".xml")
                )
            self.assertNotIn(b"192.0.2.10", extracted_xml)
            self.assertNotIn(b"sensitive evidence", extracted_xml)

            result = unmask_workbook(masked, unmasked, mapping, "strong password")
            unmasked_first = read_sheet(unmasked)
            self.assertEqual(unmasked_first[1], ["A", "192.0.2.10", "tcp/443", ""])
            self.assertEqual(unmasked_first[2], ["B", "192.0.2.10", "tcp/80", ""])
            self.assertEqual(result["host_tokens"], 3)
            self.assertEqual(result["location_tokens"], 3)
            self.assertTrue(result["source_matches_original_masked"])

    def test_mask_writes_empty_cells_without_shared_string_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "report.xlsx"
            masked = root / "report_masked.xlsx"
            mapping = root / "report.mask.enc"
            write_workbook(source, [
                ("Report", [
                    ["Host", "Location", "Plugin Output", "Notes"],
                    ["server.example", "tcp/443", "evidence", "placeholder"],
                ]),
            ])
            replace_cell_with_empty_shared_string(source, "D2", shared_index=15)

            mask_workbook(source, masked, mapping, "strong password")

            self.assertEqual(read_sheet(masked)[1][2:], ["", ""])
            for reference in ("C2", "D2"):
                cell = cell_xml(masked, reference)
                self.assertNotIn("t", cell.attrib)
                self.assertIsNone(cell.find("x:v", _NS))
                self.assertIsNone(cell.find("x:is", _NS))

    def test_unmask_rejects_wrong_password_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "report.xlsx"
            masked = root / "report_masked.xlsx"
            mapping = root / "report.mask.enc"
            output = root / "report_unmasked.xlsx"
            write_workbook(source, [
                ("Report", [["Host", "Location", "Plugin Output"], ["host", "tcp/22", "x"]]),
            ])
            mask_workbook(source, masked, mapping, "correct password")
            with self.assertRaisesRegex(NctlError, "Sai mật khẩu"):
                unmask_workbook(masked, output, mapping, "wrong password")
            self.assertFalse(output.exists())

    def test_shared_strings_reused_by_headers_do_not_blank_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "report.xlsx"
            masked = root / "report_masked.xlsx"
            mapping = root / "report.mask.enc"
            write_workbook(source, [
                ("Report", [
                    ["Host", "Location", "Plugin Output"],
                    ["Host", "Location", "Plugin Output"],
                ]),
            ])
            mask_workbook(source, masked, mapping, "strong password")
            rows = read_sheet(masked)
            self.assertEqual(rows[0], ["Host", "Location", "Plugin Output"])
            self.assertRegex(rows[1][0], r"^\[\[HOST:")
            self.assertRegex(rows[1][1], r"^\[\[LOCATION:")
            self.assertEqual(rows[1][2], "")

    def test_tokens_are_random_between_mask_runs_but_readable_by_type(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "report.xlsx"
            write_workbook(source, [
                ("Report", [
                    ["Host", "Location", "Plugin Output"],
                    ["server.example", "tcp/443", "evidence"],
                ]),
            ])
            first = root / "first_masked.xlsx"
            second = root / "second_masked.xlsx"
            mask_workbook(source, first, root / "first.mask.enc", "same password")
            mask_workbook(source, second, root / "second.mask.enc", "same password")

            first_row = read_sheet(first)[1]
            second_row = read_sheet(second)[1]
            self.assertTrue(first_row[0].startswith("[[HOST:"))
            self.assertTrue(first_row[1].startswith("[[LOCATION:"))
            self.assertNotEqual(first_row[0], second_row[0])
            self.assertNotEqual(first_row[1], second_row[1])

    def test_unmask_replaces_mapped_tokens_in_any_cell_across_all_sheets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "report.xlsx"
            masked = root / "report_masked.xlsx"
            mapping = root / "report.mask.enc"
            ai_result = root / "ai-result.xlsx"
            unmasked = root / "ai-result_unmasked.xlsx"
            write_workbook(source, [
                ("Report", [
                    ["Host", "Location", "Plugin Output"],
                    ["server.example", "tcp/443", "evidence"],
                ]),
            ])
            mask_workbook(source, masked, mapping, "strong password")
            host_token, location_token, _ = read_sheet(masked)[1]
            unknown_token = "[[HOST:0000-0000-0000-0000-0000-0000-00]]"
            write_workbook(ai_result, [
                ("Summary", [
                    ["Nội dung tự do"],
                    [f"Prefix {host_token}; middle {location_token}; suffix"],
                    [f"Lặp lại {host_token} và {host_token}"],
                ]),
                ("Arbitrary", [
                    ["Không cần header Host/Location", "Giá trị"],
                    ["Token ở ô bất kỳ", location_token],
                    ["Token không có trong mapping", unknown_token],
                ]),
            ])

            result = unmask_workbook(ai_result, unmasked, mapping, "strong password")
            first_sheet = read_sheet(unmasked)
            second_sheet = read_sheet(unmasked, 2)
            self.assertEqual(
                first_sheet[1][0],
                "Prefix server.example; middle tcp/443; suffix",
            )
            self.assertEqual(first_sheet[2][0], "Lặp lại server.example và server.example")
            self.assertEqual(second_sheet[1][1], "tcp/443")
            self.assertEqual(second_sheet[2][1], unknown_token)
            self.assertEqual(result["host_tokens"], 3)
            self.assertEqual(result["location_tokens"], 2)
            self.assertEqual(result["cells"], 3)

    def test_unmask_preserves_excel_compatibility_namespaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "report.xlsx"
            masked = root / "report_masked.xlsx"
            mapping = root / "report.mask.enc"
            unmasked = root / "report_unmasked.xlsx"
            write_workbook(source, [
                ("Report", [
                    ["Host", "Location", "Plugin Output"],
                    ["server.example", "tcp/443", "evidence"],
                ]),
            ])
            mask_workbook(source, masked, mapping, "strong password")
            add_excel_compatibility_namespaces(masked)

            unmask_workbook(masked, unmasked, mapping, "strong password")

            self.assertEqual(read_sheet(unmasked)[1], ["server.example", "tcp/443", ""])
            with zipfile.ZipFile(unmasked) as archive:
                worksheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
            self.assertIn('xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"', worksheet)
            self.assertIn('xmlns:x14ac="http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac"', worksheet)
            self.assertIn('xmlns:xr="http://schemas.microsoft.com/office/spreadsheetml/2014/revision"', worksheet)
            self.assertIn('mc:Ignorable="x14ac xr"', worksheet)
            self.assertNotIn("xr2 xr3", worksheet)

    def test_unmask_handles_ai_reordered_content_and_preserves_pasted_plugin_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "report.xlsx"
            masked = root / "report_masked.xlsx"
            mapping = root / "report.mask.enc"
            ai_result = root / "ai-result.xlsx"
            unmasked = root / "ai-result_unmasked.xlsx"
            write_workbook(source, [
                ("Report", [
                    ["Host", "Location", "Plugin Output"],
                    ["server.example", "tcp/443", "original evidence"],
                ]),
            ])
            mask_workbook(source, masked, mapping, "strong password")
            masked_row = read_sheet(masked)[1]
            write_workbook(ai_result, [
                ("AI", [
                    ["Summary", "Plugin Output"],
                    [f"Finding on {masked_row[0]} at {masked_row[1]}", "pasted evidence"],
                ]),
            ])

            result = unmask_workbook(ai_result, unmasked, mapping, "strong password")
            rows = read_sheet(unmasked)
            self.assertEqual(
                rows[1],
                ["Finding on server.example at tcp/443", "pasted evidence"],
            )
            self.assertFalse(result["source_matches_original_masked"])

    def test_mask_and_unmask_cli_run_offline_with_environment_password(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.xlsx"
            missing_config = root / "missing-config.json"
            write_workbook(source, [
                ("Report", [["Host", "Location", "Plugin Output"], ["host", "tcp/22", "x"]]),
            ])
            common = ["--config", str(missing_config), "--non-interactive"]
            with patch.dict("os.environ", {"NCTL_MASK_PASSWORD": "environment password"}):
                self.assertEqual(main([*common, "mask", str(source)]), 0)
                masked = root / "input_masked.xlsx"
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(main([*common, "unmask", str(masked)]), 0)
            self.assertTrue((root / "input.mask.enc").exists())
            self.assertTrue((root / "input_unmasked.xlsx").exists())
            self.assertIn(
                f"Phát hiện và sẽ sử dụng file mapping .enc: {(root / 'input.mask.enc').resolve()}",
                output.getvalue(),
            )

    def test_unmask_cli_prompts_to_select_one_of_multiple_mappings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.xlsx"
            masked = root / "input_masked.xlsx"
            first_mapping = root / "a.enc"
            second_mapping = root / "b.enc"
            missing_config = root / "missing-config.json"
            write_workbook(source, [
                ("Report", [["Host", "Location"], ["host", "tcp/22"]]),
            ])
            mask_workbook(source, masked, second_mapping, "environment password")
            first_mapping.write_bytes(second_mapping.read_bytes())

            output = io.StringIO()
            with (
                patch.dict("os.environ", {"NCTL_MASK_PASSWORD": "environment password"}),
                patch("builtins.input", return_value="2") as prompt,
                redirect_stdout(output),
            ):
                result = main(["--config", str(missing_config), "unmask", str(masked)])

            self.assertEqual(result, 0)
            prompt.assert_called_once()
            self.assertIn("Phát hiện 2 file mapping .enc", output.getvalue())
            self.assertIn(f"  1. {first_mapping.resolve()}", output.getvalue())
            self.assertIn(f"  2. {second_mapping.resolve()}", output.getvalue())
            self.assertIn(
                f"Sẽ sử dụng file mapping .enc: {second_mapping.resolve()}",
                output.getvalue(),
            )
            self.assertTrue((root / "input_unmasked.xlsx").exists())

    def test_unmask_cli_accepts_typed_mapping_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.xlsx"
            masked = root / "input_masked.xlsx"
            external = root / "external" / "chosen.enc"
            missing_config = root / "missing-config.json"
            write_workbook(source, [
                ("Report", [["Host", "Location"], ["host", "tcp/22"]]),
            ])
            external.parent.mkdir()
            mask_workbook(source, masked, external, "environment password")
            (root / "a.enc").write_bytes(external.read_bytes())
            (root / "b.enc").write_bytes(external.read_bytes())

            output = io.StringIO()
            with (
                patch.dict("os.environ", {"NCTL_MASK_PASSWORD": "environment password"}),
                patch("builtins.input", return_value=str(external)),
                redirect_stdout(output),
            ):
                result = main(["--config", str(missing_config), "unmask", str(masked)])

            self.assertEqual(result, 0)
            self.assertIn(
                f"Sẽ sử dụng file mapping .enc: {external.resolve()}",
                output.getvalue(),
            )
            self.assertTrue((root / "input_unmasked.xlsx").exists())

    def test_unmask_cli_requires_map_for_multiple_candidates_when_non_interactive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.xlsx"
            masked = root / "input_masked.xlsx"
            mapping = root / "a.enc"
            missing_config = root / "missing-config.json"
            write_workbook(source, [
                ("Report", [["Host", "Location"], ["host", "tcp/22"]]),
            ])
            mask_workbook(source, masked, mapping, "environment password")
            (root / "b.enc").write_bytes(mapping.read_bytes())

            output = io.StringIO()
            errors = io.StringIO()
            with (
                patch.dict("os.environ", {"NCTL_MASK_PASSWORD": "environment password"}),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                result = main([
                    "--config", str(missing_config), "--non-interactive",
                    "unmask", str(masked),
                ])

            self.assertEqual(result, 2)
            self.assertIn("Phát hiện 2 file mapping .enc", output.getvalue())
            self.assertIn("hãy truyền --map <mapping.enc>", errors.getvalue())
            self.assertFalse((root / "input_unmasked.xlsx").exists())


if __name__ == "__main__":
    unittest.main()
