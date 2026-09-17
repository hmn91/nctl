import contextlib
import io
import unittest
from unittest.mock import Mock, patch

from nctl.app import build_parser, cmd_delete
from nctl.client import NctlError


class DeleteCleanupTests(unittest.TestCase):
    def client(self, scans=None):
        client = Mock()
        client.list_folders.return_value = [
            {"id": 2, "name": "Trash", "type": "trash"},
            {"id": 3, "name": "My Scans", "type": "main"},
            {"id": 4, "name": "Empty", "type": "custom"},
            {"id": 5, "name": "Targets", "type": "custom"},
        ]
        remaining = list(scans or [])
        client.list_scans.side_effect = lambda folder_id=None: {
            "scans": [dict(scan) for scan in remaining
                      if folder_id is None or scan["folder_id"] == folder_id]
        }

        def move(scan_id, folder_id):
            for scan in remaining:
                if scan["id"] == scan_id:
                    scan["folder_id"] = folder_id

        client.move_scan.side_effect = move
        client.delete_scan.side_effect = lambda scan_id: remaining.__setitem__(
            slice(None), [scan for scan in remaining if scan["id"] != scan_id])
        return client

    def run_delete(self, client, *arguments):
        args = build_parser().parse_args([*arguments])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return cmd_delete(client, args, {})

    def test_all_moves_scans_cleans_custom_folders_without_password(self):
        client = self.client([{"id": 10, "folder_id": 5}])
        with patch("nctl.app._confirm_delete_password") as confirm:
            self.assertEqual(self.run_delete(client, "--non-interactive", "delete", "--all"), 0)
        confirm.assert_not_called()
        client.move_scan.assert_called_once_with(10, 2)
        client.delete_scan.assert_not_called()
        self.assertEqual([call.args[0] for call in client.delete_folder.call_args_list], [4, 5])

    def test_all_cleans_empty_folders_even_without_scans(self):
        client = self.client()
        self.assertEqual(self.run_delete(client, "delete", "--all"), 0)
        self.assertEqual([call.args[0] for call in client.delete_folder.call_args_list], [4, 5])

    def test_failed_move_keeps_nonempty_folder_but_cleans_others(self):
        client = self.client([{"id": 10, "folder_id": 5}])
        client.move_scan.side_effect = NctlError("move failed")
        self.assertEqual(self.run_delete(client, "delete", "--all"), 1)
        client.delete_folder.assert_called_once_with(4)

    def test_folder_delete_failure_continues_cleanup(self):
        client = self.client()
        client.delete_folder.side_effect = [NctlError("denied"), None]
        self.assertEqual(self.run_delete(client, "delete", "--all"), 1)
        self.assertEqual(client.delete_folder.call_count, 2)

    def test_selected_folder_cleans_only_selected_folder_without_password(self):
        client = self.client()
        with patch("nctl.app._confirm_delete_password") as confirm:
            self.assertEqual(self.run_delete(client, "delete", "--folder", "Empty"), 0)
        confirm.assert_not_called()
        client.delete_folder.assert_called_once_with(4)

    def test_permanent_all_requires_password_before_any_changes(self):
        client = self.client([{"id": 10, "folder_id": 5}])
        with patch("nctl.app._confirm_delete_password", side_effect=NctlError("wrong password")) as confirm:
            with self.assertRaisesRegex(NctlError, "wrong password"):
                self.run_delete(client, "delete", "--all", "--permanent")
        confirm.assert_called_once()
        client.move_scan.assert_not_called()
        client.delete_scan.assert_not_called()
        client.delete_folder.assert_not_called()

    def test_permanent_all_deletes_scans_and_cleans_folders(self):
        client = self.client([{"id": 10, "folder_id": 5}, {"id": 20, "folder_id": 2}])
        with patch("nctl.app._confirm_delete_password") as confirm:
            self.assertEqual(self.run_delete(client, "delete", "--all", "--permanent"), 0)
        confirm.assert_called_once()
        self.assertEqual(client.delete_scan.call_count, 2)
        self.assertEqual([call.args[0] for call in client.delete_folder.call_args_list], [4, 5])

    def test_delete_scan_does_not_cleanup_unselected_folders(self):
        client = self.client([{"id": 10, "folder_id": 5}])
        self.assertEqual(self.run_delete(client, "delete", "--scan", "10"), 0)
        client.delete_folder.assert_not_called()
