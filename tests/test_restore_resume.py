import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from nctl.app import build_parser, cmd_restore
from nctl.client import NctlClient, NctlError
from tests.test_app import FakeResponse


class UploadRetryTests(unittest.TestCase):
    def make_client(self):
        client = NctlClient.__new__(NctlClient)
        client.url = "https://localhost:11127"
        client.verify_tls = False
        client.timeout = 60
        client.username = None
        client.password = None
        client.session = Mock()
        return client

    def test_eof_retries_reopens_file_and_discards_connection(self):
        client = self.make_client()
        attempts = []

        def request(*args, **kwargs):
            attempts.append(kwargs["files"]["Filedata"][1].read())
            if len(attempts) < 3:
                raise requests.exceptions.SSLError("EOF occurred in violation of protocol")
            return FakeResponse({"fileuploaded": "ok"})

        client.session.request.side_effect = request
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.db"
            path.write_bytes(b"complete-db-content")
            with patch("nctl.client.time.sleep") as sleep:
                self.assertEqual(client.upload_file(path), "ok")
        self.assertEqual(attempts, [b"complete-db-content"] * 3)
        self.assertEqual(client.session.close.call_count, 2)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2, 4])

    def test_connection_retry_is_bounded(self):
        client = self.make_client()
        client.session.request.side_effect = requests.ConnectionError("connection reset")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.db"
            path.write_bytes(b"db")
            with patch("nctl.client.time.sleep") as sleep:
                with self.assertRaises(NctlError):
                    client.upload_file(path)
        self.assertEqual(client.session.request.call_count, 4)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2, 4, 8])

    def test_certificates_http_and_json_errors_are_not_retried(self):
        for error in (requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED"),
                      NctlError("HTTP 500"), NctlError("invalid JSON")):
            with self.subTest(error=error):
                client = self.make_client()
                client.session.request.side_effect = error
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "test.db"
                    path.write_bytes(b"db")
                    with patch("nctl.client.time.sleep") as sleep:
                        with self.assertRaises(NctlError):
                            client.upload_file(path)
                client.session.request.assert_called_once()
                sleep.assert_not_called()

    def test_import_failure_does_not_repeat_import(self):
        client = self.make_client()
        client.upload_file = Mock(return_value="uploaded")
        client.session.request.side_effect = requests.exceptions.SSLError("EOF")
        with self.assertRaises(NctlError):
            client.import_db(Path("test.db"), 3, "password")
        client.session.request.assert_called_once()
        client.upload_file.assert_called_once()


class RestoreResumeTests(unittest.TestCase):
    def make_client(self):
        client = Mock()
        client.url = "https://localhost:11127"
        client.username = "admin"
        client.list_folders.return_value = [{"id": 3, "name": "My Scans"}]
        client.import_db.return_value = {"scan": {"id": 99}}
        return client

    def restore(self, client, *arguments):
        args = build_parser().parse_args(["--non-interactive", "restore", *arguments])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return cmd_restore(client, args, {"default_db_password": "private-secret"})

    def test_rerun_only_failed_files_then_force(self):
        client = self.make_client()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a, b = root / "a.db", root / "b.db"
            a.write_bytes(b"a")
            b.write_bytes(b"b")
            client.import_db.side_effect = [{"scan": {"id": 90}}, NctlError("failed")]
            self.assertEqual(self.restore(client, str(a), str(b)), 1)
            checkpoint = root / ".nctl-restore.json"
            self.assertEqual(len(json.loads(checkpoint.read_text())["completed"]), 1)
            self.assertNotIn("private-secret", checkpoint.read_text())
            client.import_db.reset_mock(side_effect=True)
            self.assertEqual(self.restore(client, str(a), str(b)), 0)
            client.import_db.assert_called_once_with(b, 3, "private-secret")
            client.import_db.reset_mock()
            self.assertEqual(self.restore(client, str(a), str(b)), 0)
            client.import_db.assert_not_called()
            self.assertEqual(self.restore(client, str(a), str(b), "--force"), 0)
            self.assertEqual(client.import_db.call_count, 2)

    def test_changed_content_server_account_or_folder_imports_again(self):
        client = self.make_client()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.db"
            path.write_bytes(b"a")
            self.restore(client, str(path))
            client.import_db.reset_mock()
            path.write_bytes(b"changed")
            self.restore(client, str(path))
            client.url = "https://other:11127"
            self.restore(client, str(path))
            client.username = "other-user"
            self.restore(client, str(path))
            client.list_folders.return_value = [{"id": 5, "name": "My Scans"}]
            self.restore(client, str(path))
            self.assertEqual(client.import_db.call_count, 4)

    def test_nested_folder_resume_survives_new_client(self):
        with tempfile.TemporaryDirectory() as directory:
            group = Path(directory) / "Target Group 1"
            group.mkdir()
            (group / "a.db").write_bytes(b"a")
            client = self.make_client()
            client.create_folder.return_value = 7
            self.assertEqual(self.restore(client, directory), 0)
            client = self.make_client()
            client.list_folders.return_value.append({"id": 7, "name": "Target Group 1"})
            self.assertEqual(self.restore(client, directory), 0)
            client.import_db.assert_not_called()
            client.create_folder.assert_not_called()

    def test_invalid_checkpoint_stops_before_server_changes(self):
        client = self.make_client()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.db"
            path.write_bytes(b"a")
            (path.parent / ".nctl-restore.json").write_text("broken")
            with self.assertRaises(NctlError):
                self.restore(client, str(path))
        client.import_db.assert_not_called()
        client.create_folder.assert_not_called()

    def test_checkpoint_write_failure_stops_after_import(self):
        client = self.make_client()
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / "a.db", Path(directory) / "b.db"
            a.write_bytes(b"a")
            b.write_bytes(b"b")
            with patch("nctl.app._save_restore_checkpoint", side_effect=OSError("disk full")):
                with self.assertRaisesRegex(NctlError, "ĐÃ IMPORT"):
                    self.restore(client, str(a), str(b))
        client.import_db.assert_called_once()
