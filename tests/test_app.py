import argparse
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from nctl.app import (
    _backup_folder_layout,
    _db_files,
    _delete_selection,
    _history_list,
    _latest_history,
    _load_scan_credentials,
    _read_targets,
    _restore_items,
    _selected_scans,
    _setting,
    _strip_json_comments,
    _template_uuid,
    build_parser,
    cmd_backup,
    cmd_delete,
    cmd_restore,
    cmd_status,
    main,
)
from nctl.client import NctlClient, NctlError
from nctl.helptext import TOPICS


class AppTests(unittest.TestCase):
    def test_default_outputs_are_partitioned_under_data(self):
        backup = build_parser().parse_args(["backup", "--scan", "1"])
        report = build_parser().parse_args(["report", "--scan", "1"])
        self.assertEqual(Path(backup.output), Path("data") / "backups")
        self.assertEqual(Path(report.output), Path("data") / "reports")

    def test_backup_folder_layout_preserves_names_and_resolves_collisions(self):
        layout, manifest = _backup_folder_layout(
            [
                {"id": 1, "name": "Web/Servers", "type": "custom"},
                {"id": 2, "name": "Web:Servers", "type": "custom"},
                {"id": 3, "name": "Empty Folder", "type": "custom"},
            ],
            [{"id": 10, "folder_id": 1}],
        )
        self.assertEqual(layout[1], Path("Web_Servers"))
        self.assertEqual(layout[2], Path("Web_Servers__folder-2"))
        self.assertEqual(layout[3], Path("Empty Folder"))
        self.assertEqual(len(manifest), 3)

    def test_backup_all_writes_histories_inside_server_folders(self):
        client = Mock()
        client.url = "https://scanner.example"
        client.list_scans.return_value = {
            "scans": [
                {"id": 10, "name": "Linux scan", "folder_id": 1},
                {"id": 20, "name": "Windows scan", "folder_id": 2},
                {"id": 30, "name": "Deleted scan", "folder_id": 4},
            ]
        }
        client.list_folders.return_value = [
            {"id": 1, "name": "Linux", "type": "custom"},
            {"id": 2, "name": "Windows", "type": "custom"},
            {"id": 3, "name": "Empty", "type": "custom"},
            {"id": 4, "name": "Trash", "type": "trash"},
        ]
        client.scan_details.side_effect = lambda scan_id: {
            "history": [{"history_id": scan_id + 100, "status": "completed"}]
        }

        def export_db(scan_id, history_id, password, destination, **kwargs):
            del scan_id, history_id, password, kwargs
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"db")

        client.export_db.side_effect = export_db
        args = argparse.Namespace(
            all=True,
            folder=None,
            scan=None,
            scans=None,
            history="all",
            output=None,
            poll_interval=0,
            export_timeout=10,
            non_interactive=True,
            include_trash=False,
        )
        with tempfile.TemporaryDirectory() as directory:
            args.output = directory
            with (
                patch("nctl.app._db_password", return_value="db-password"),
                patch("sys.stdout", new=io.StringIO()),
                patch("sys.stderr", new=io.StringIO()),
            ):
                self.assertEqual(cmd_backup(client, args, {}), 0)
            backup_dir = next(Path(directory).iterdir())
            self.assertTrue(backup_dir.name.startswith("nctl-backup-"))
            self.assertEqual(len(list((backup_dir / "Linux").glob("*.db"))), 1)
            self.assertEqual(len(list((backup_dir / "Windows").glob("*.db"))), 1)
            self.assertTrue((backup_dir / "Empty").is_dir())
            self.assertFalse((backup_dir / "Trash").exists())
            manifest = json.loads((backup_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["server_url"], client.url)
            self.assertTrue(manifest["preserve_folders"])
            self.assertEqual(
                {item["file"].split("/", 1)[0] for item in manifest["files"]},
                {"Linux", "Windows"},
            )

    def test_read_targets_validates_deduplicates_and_accepts_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            path.write_text(
                "192.0.2.1\n192.0.2.0/24 # lab\n192.0.2.1\n2001:db8::1\n192.0.2.10-192.0.2.20\n",
                encoding="utf-8",
            )
            self.assertEqual(
                _read_targets(path),
                ["192.0.2.1", "192.0.2.0/24", "2001:db8::1", "192.0.2.10-192.0.2.20"],
            )

    def test_latest_history_uses_timestamp_then_id(self):
        histories = _history_list(
            {"history": [
                {"history_id": 7, "last_modification_date": 100},
                {"history_id": 9, "last_modification_date": 200},
            ]}
        )
        self.assertEqual(_latest_history(histories)["history_id"], 9)

    def test_selected_scans_rejects_missing_id(self):
        client = Mock()
        client.list_scans.return_value = {"scans": [{"id": 1}, {"id": 2}]}
        client.list_folders.return_value = [{"id": 9, "name": "Trash", "type": "trash"}]
        args = argparse.Namespace(all=False, folder=None, scan=None, scans="1,3")
        with self.assertRaisesRegex(Exception, "3"):
            _selected_scans(client, args)

    def test_backup_ignores_trash_unless_included(self):
        client = Mock()
        client.list_folders.return_value = [
            {"id": 2, "name": "Trash", "type": "trash"},
            {"id": 3, "name": "My Scans", "type": "main"},
        ]

        def list_scans(folder_id=None):
            if folder_id == 2:
                return {"scans": [{"id": 20, "name": "trashed", "folder_id": 2}]}
            return {
                "scans": [
                    {"id": 10, "name": "active", "folder_id": 3},
                    {"id": 20, "name": "trashed", "folder_id": 2},
                ]
            }

        client.list_scans.side_effect = list_scans
        args = argparse.Namespace(
            all=True, folder=None, scan=None, scans=None, include_trash=False
        )
        self.assertEqual([scan["id"] for scan in _selected_scans(client, args)], [10])
        args.include_trash = True
        self.assertEqual(
            [scan["id"] for scan in _selected_scans(client, args)], [10, 20]
        )

    def test_backup_trash_folder_requires_include_flag(self):
        client = Mock()
        client.list_folders.return_value = [
            {"id": 2, "name": "Trash", "type": "trash"}
        ]
        args = argparse.Namespace(
            all=False, folder="trash", scan=None, scans=None, include_trash=False
        )
        with self.assertRaisesRegex(NctlError, "--include-trash"):
            _selected_scans(client, args)

    def test_db_files_recurses_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            first = root / "one.db"
            second = root / "nested" / "two.DB"
            first.touch()
            second.touch()
            self.assertEqual(len(_db_files([str(root), str(first)])), 2)

    def test_restore_items_uses_manifest_and_flattens_nested_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Safe Name").mkdir()
            (root / "Archive" / "2025").mkdir(parents=True)
            (root / "direct.db").touch()
            (root / "Safe Name" / "web.db").touch()
            (root / "Archive" / "2025" / "old.db").touch()
            (root / "manifest.json").write_text(
                json.dumps(
                    {
                        "folders": [
                            {
                                "path": "Safe Name",
                                "folder_name": "Original:Name",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            mapped = {path.name: folder for path, folder in _restore_items([str(root)])}
        self.assertEqual(mapped["direct.db"], Path(directory).name)
        self.assertEqual(mapped["web.db"], "Original:Name")
        self.assertEqual(mapped["old.db"], "Archive - 2025")

    def test_restore_creates_and_reuses_parent_folder(self):
        client = Mock()
        client.list_folders.return_value = [
            {"id": 9, "name": "Recovered", "type": "custom"}
        ]
        client.create_folder.return_value = 10
        client.import_db.return_value = {"scan": {"id": 100}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Linux").mkdir()
            (root / "root.db").touch()
            (root / "Linux" / "one.db").touch()
            (root / "Linux" / "two.db").touch()
            args = argparse.Namespace(
                paths=[str(root)],
                folder="Recovered",
                create_folder=False,
                flat=False,
                non_interactive=True,
            )
            with (
                patch("nctl.app._db_password", return_value="db-password"),
                patch("sys.stdout", new=io.StringIO()),
                patch("sys.stderr", new=io.StringIO()),
            ):
                self.assertEqual(cmd_restore(client, args, {}), 0)
        client.create_folder.assert_called_once_with("Linux")
        target_ids = [call.args[1] for call in client.import_db.call_args_list]
        self.assertEqual(target_ids.count(9), 1)
        self.assertEqual(target_ids.count(10), 2)

    def test_restore_nested_backup_without_folder_argument(self):
        client = Mock()
        client.list_folders.return_value = []
        client.create_folder.side_effect = [11, 12]
        client.import_db.return_value = {"scan": {"id": 100}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "backup"
            group_one = root / "Target Group 1"
            group_two = root / "Target Group 2"
            group_one.mkdir(parents=True)
            group_two.mkdir()
            (group_one / "task1.db").touch()
            (group_one / "task 2.db").touch()
            (group_two / "task3.db").touch()
            args = build_parser().parse_args(["restore", str(root)])
            with (
                patch("nctl.app._db_password", return_value="db-password"),
                patch("sys.stdout", new=io.StringIO()),
            ):
                self.assertEqual(cmd_restore(client, args, {}), 0)
        self.assertEqual(
            [call.args[0] for call in client.create_folder.call_args_list],
            ["Target Group 1", "Target Group 2"],
        )
        target_by_name = {
            call.args[0].name: call.args[1]
            for call in client.import_db.call_args_list
        }
        self.assertEqual(target_by_name, {"task1.db": 11, "task 2.db": 11, "task3.db": 12})

    def test_restore_folder_root_db_uses_input_folder_name(self):
        client = Mock()
        client.list_folders.return_value = []
        client.create_folder.return_value = 13
        client.import_db.return_value = {"scan": {"id": 100}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "backup"
            root.mkdir()
            (root / "task1.db").touch()
            (root / "task 2.db").touch()
            args = build_parser().parse_args(["restore", str(root)])
            with (
                patch("nctl.app._db_password", return_value="db-password"),
                patch("sys.stdout", new=io.StringIO()),
            ):
                self.assertEqual(cmd_restore(client, args, {}), 0)
        client.create_folder.assert_called_once_with("backup")
        self.assertEqual(
            [call.args[1] for call in client.import_db.call_args_list], [13, 13]
        )

    def test_restore_dot_path_uses_resolved_folder_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "backup"
            root.mkdir()
            (root / "task1.db").touch()
            original_directory = Path.cwd()
            try:
                os.chdir(root)
                items = _restore_items(["."])
            finally:
                os.chdir(original_directory)
        self.assertEqual(items[0][1], "backup")

    def test_restore_direct_db_without_folder_uses_my_scans(self):
        client = Mock()
        client.list_folders.return_value = [
            {"id": 3, "name": "My Scans", "type": "main"}
        ]
        client.import_db.return_value = {"scan": {"id": 100}}
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "task1.db"
            db_path.touch()
            args = build_parser().parse_args(["restore", str(db_path)])
            with (
                patch("nctl.app._db_password", return_value="db-password"),
                patch("sys.stdout", new=io.StringIO()),
            ):
                self.assertEqual(cmd_restore(client, args, {}), 0)
        client.create_folder.assert_not_called()
        client.import_db.assert_called_once_with(db_path, 3, "db-password")

    def test_restore_mixed_direct_file_and_folder_uses_separate_destinations(self):
        client = Mock()
        client.list_folders.return_value = [
            {"id": 3, "name": "My Scans", "type": "main"}
        ]
        client.create_folder.return_value = 14
        client.import_db.return_value = {"scan": {"id": 100}}
        with tempfile.TemporaryDirectory() as directory:
            direct = Path(directory) / "direct.db"
            direct.touch()
            root = Path(directory) / "backup"
            root.mkdir()
            (root / "inside.db").touch()
            args = build_parser().parse_args(["restore", str(direct), str(root)])
            with (
                patch("nctl.app._db_password", return_value="db-password"),
                patch("sys.stdout", new=io.StringIO()),
            ):
                self.assertEqual(cmd_restore(client, args, {}), 0)
        client.create_folder.assert_called_once_with("backup")
        targets = {
            call.args[0].name: call.args[1]
            for call in client.import_db.call_args_list
        }
        self.assertEqual(targets, {"direct.db": 3, "inside.db": 14})

    def test_restore_flat_requires_folder_argument(self):
        client = Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "backup"
            (root / "Target Group 1").mkdir(parents=True)
            (root / "Target Group 1" / "task1.db").touch()
            args = build_parser().parse_args(["restore", str(root), "--flat"])
            with self.assertRaisesRegex(NctlError, "--folder"):
                cmd_restore(client, args, {})
        client.create_folder.assert_not_called()
        client.import_db.assert_not_called()

    def test_monitor_timeout_does_not_replace_http_timeout(self):
        args = build_parser().parse_args(
            ["--timeout", "30", "monitor", "7", "--timeout", "90"]
        )
        self.assertEqual(args.http_timeout, 30)
        self.assertEqual(args.timeout, 90)

    def test_delete_selection_by_ids(self):
        client = Mock()
        client.list_scans.return_value = {
            "scans": [{"id": 1, "name": "one"}, {"id": 2, "name": "two"}]
        }
        args = argparse.Namespace(all=False, folder=None, scan=None, scans="2,1")
        scans, folder = _delete_selection(client, args)
        self.assertEqual({scan["id"] for scan in scans}, {1, 2})
        self.assertIsNone(folder)

    def test_bad_confirmation_password_prevents_delete(self):
        client = Mock()
        client.list_scans.return_value = {"scans": [{"id": 12, "name": "protected"}]}
        client.verify_login_password.side_effect = NctlError("Invalid Credentials")
        client.list_folders.return_value = [
            {"id": 2, "name": "Trash", "type": "trash"}
        ]
        args = argparse.Namespace(
            all=False,
            folder=None,
            scan=12,
            scans=None,
            non_interactive=False,
            username=None,
            permanent=True,
        )
        with patch("nctl.app.getpass.getpass", return_value="wrong"):
            with self.assertRaisesRegex(NctlError, "Invalid Credentials"):
                cmd_delete(client, args, {"username": "admin"})
        client.delete_scan.assert_not_called()
        client.move_scan.assert_not_called()

    def test_delete_default_moves_active_scans_and_skips_trash(self):
        client = Mock()
        client.list_scans.return_value = {
            "scans": [
                {"id": 10, "name": "active", "folder_id": 3},
                {"id": 20, "name": "trashed", "folder_id": 2},
            ]
        }
        client.list_folders.return_value = [
            {"id": 2, "name": "Trash", "type": "trash"},
            {"id": 3, "name": "My Scans", "type": "main"},
        ]
        args = argparse.Namespace(
            all=True,
            folder=None,
            scan=None,
            scans=None,
            permanent=False,
            non_interactive=False,
        )
        with (
            patch("nctl.app._confirm_delete_password"),
            patch("sys.stdout", new=io.StringIO()),
            patch("sys.stderr", new=io.StringIO()),
        ):
            self.assertEqual(cmd_delete(client, args, {}), 0)
        client.move_scan.assert_called_once_with(10, 2)
        client.delete_scan.assert_not_called()

    def test_delete_permanent_moves_active_then_deletes_every_scan_once(self):
        client = Mock()

        def list_scans(folder_id=None):
            if folder_id == 2:
                return {"scans": [{"id": 20, "name": "trashed", "folder_id": 2}]}
            return {"scans": [{"id": 10, "name": "active", "folder_id": 3}]}

        client.list_scans.side_effect = list_scans
        client.list_folders.return_value = [
            {"id": 2, "name": "Trash", "type": "trash"},
            {"id": 3, "name": "My Scans", "type": "main"},
        ]
        args = argparse.Namespace(
            all=True,
            folder=None,
            scan=None,
            scans=None,
            permanent=True,
            non_interactive=False,
        )
        with (
            patch("nctl.app._confirm_delete_password"),
            patch("sys.stdout", new=io.StringIO()),
            patch("sys.stderr", new=io.StringIO()),
        ):
            self.assertEqual(cmd_delete(client, args, {}), 0)
        client.move_scan.assert_called_once_with(10, 2)
        self.assertEqual(
            [item.args[0] for item in client.delete_scan.call_args_list], [10, 20]
        )

    def test_delete_trash_by_folder_name_requires_permanent(self):
        client = Mock()
        client.list_folders.return_value = [
            {"id": 2, "name": "Trash", "type": "trash"}
        ]
        client.list_scans.return_value = {
            "scans": [{"id": 20, "name": "trashed", "folder_id": 2}]
        }
        args = argparse.Namespace(
            all=False,
            folder="trash",
            scan=None,
            scans=None,
            permanent=False,
            non_interactive=False,
        )
        with (
            patch("nctl.app._confirm_delete_password") as confirm,
            patch("sys.stdout", new=io.StringIO()),
            patch("sys.stderr", new=io.StringIO()),
        ):
            self.assertEqual(cmd_delete(client, args, {}), 0)
        confirm.assert_not_called()
        client.move_scan.assert_not_called()
        client.delete_scan.assert_not_called()

        args.permanent = True
        with (
            patch("nctl.app._confirm_delete_password"),
            patch("sys.stdout", new=io.StringIO()),
            patch("sys.stderr", new=io.StringIO()),
        ):
            self.assertEqual(cmd_delete(client, args, {}), 0)
        client.delete_scan.assert_called_once_with(20)

    def test_advanced_scan_is_default_template(self):
        client = Mock()
        client.list_scan_templates.return_value = [
            {"title": "Basic Network Scan", "name": "basic", "uuid": "basic-id"},
            {"title": "Advanced Scan", "name": "advanced", "uuid": "advanced-id"},
        ]
        self.assertEqual(_template_uuid(client, None), ("advanced-id", "Advanced Scan"))

    def test_json_comments_preserve_comment_characters_inside_strings(self):
        source = '''{
          // whole line comment
          "url": "https://vault.example/api", # trailing comment
          "password": "abc#123//xyz"
        }'''
        parsed = json.loads(_strip_json_comments(source))
        self.assertEqual(parsed["url"], "https://vault.example/api")
        self.assertEqual(parsed["password"], "abc#123//xyz")

    def test_credentials_file_expands_environment_secrets(self):
        client = Mock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            path.write_text(
                json.dumps(
                    {
                        "_comment_usage": "ignored top-level documentation",
                        "ssh": {
                            "_comment_username": "ignored field documentation",
                            "username": "audit",
                            "password_env": "TEST_SSH_PASSWORD",
                        },
                        "windows": [
                            {
                                "username": "administrator",
                                "password_env": "TEST_WINDOWS_PASSWORD",
                            }
                        ],
                        "settings": {
                            "_comment_ssh_port": "ignored setting documentation",
                            "ssh_port": "2222",
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"TEST_SSH_PASSWORD": "ssh-secret", "TEST_WINDOWS_PASSWORD": "win-secret"},
            ):
                credentials, settings = _load_scan_credentials(client, path)
        host = credentials["add"]["Host"]
        self.assertEqual(host["SSH"][0]["password"], "ssh-secret")
        self.assertEqual(host["SSH"][0]["auth_method"], "password")
        self.assertNotIn("_comment_username", host["SSH"][0])
        self.assertEqual(host["Windows"][0]["password"], "win-secret")
        self.assertEqual(host["Windows"][0]["auth_method"], "Password")
        self.assertEqual(settings, {"ssh_port": "2222"})

    def test_credentials_file_uploads_relative_private_key(self):
        client = Mock()
        client.upload_file.return_value = "uploaded-key-id"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "id_rsa"
            key.write_text("private-key-placeholder", encoding="utf-8")
            path = root / "credentials.json"
            path.write_text(
                json.dumps(
                    {
                        "ssh": {
                            "auth_method": "public key",
                            "username": "audit",
                            "private_key_file": "id_rsa",
                        }
                    }
                ),
                encoding="utf-8",
            )
            credentials, _ = _load_scan_credentials(client, path)
            client.upload_file.assert_called_once_with(key, no_enc=False)
        self.assertEqual(
            credentials["add"]["Host"]["SSH"][0]["private_key"],
            "uploaded-key-id",
        )


class HelpTests(unittest.TestCase):
    def test_full_guide_is_offline_and_uses_only_new_product_name(self):
        output = io.StringIO()
        with (
            patch("nctl.app._load_config") as load_config,
            patch("nctl.app._make_client") as make_client,
            patch("sys.stdout", new=output),
        ):
            self.assertEqual(main(["--config", "missing.json", "help"]), 0)
        load_config.assert_not_called()
        make_client.assert_not_called()
        guide = output.getvalue()
        self.assertNotIn("nessus", guide.casefold())
        self.assertIn("nctl", guide)
        for topic in TOPICS:
            self.assertIn(f"--- {topic} ---", guide)

    def test_each_help_topic_has_examples_without_loading_config(self):
        for topic in TOPICS:
            with self.subTest(topic=topic):
                output = io.StringIO()
                with (
                    patch("nctl.app._load_config") as load_config,
                    patch("nctl.app._make_client") as make_client,
                    patch("sys.stdout", new=output),
                ):
                    self.assertEqual(main(["help", *topic.split()]), 0)
                load_config.assert_not_called()
                make_client.assert_not_called()
                self.assertIn("Ví dụ", output.getvalue())
                self.assertNotIn("nessus", output.getvalue().casefold())

    def test_command_help_includes_examples_and_is_offline(self):
        commands = [""] + [topic for topic in TOPICS if topic != "setup"]
        for command in commands:
            with self.subTest(command=command):
                output = io.StringIO()
                with (
                    patch("nctl.app._load_config") as load_config,
                    patch("nctl.app._make_client") as make_client,
                    patch("sys.stdout", new=output),
                    self.assertRaises(SystemExit) as stopped,
                ):
                    main([*command.split(), "--help"])
                self.assertEqual(stopped.exception.code, 0)
                load_config.assert_not_called()
                make_client.assert_not_called()
                self.assertIn("Ví dụ", output.getvalue())
                self.assertNotIn("nessus", output.getvalue().casefold())

    def test_no_arguments_displays_help_without_login(self):
        output = io.StringIO()
        with (
            patch("nctl.app._make_client") as make_client,
            patch("sys.stdout", new=output),
        ):
            self.assertEqual(main([]), 0)
        make_client.assert_not_called()
        self.assertIn("nctl", output.getvalue())

    def test_invalid_topic_fails_without_login(self):
        with (
            patch("nctl.app._make_client") as make_client,
            patch("sys.stderr", new=io.StringIO()),
            self.assertRaises(SystemExit) as stopped,
        ):
            main(["help", "unknown"])
        self.assertEqual(stopped.exception.code, 2)
        make_client.assert_not_called()

    def test_nctl_environment_setting_and_cli_precedence(self):
        args = argparse.Namespace(username=None)
        with patch.dict(os.environ, {"NCTL_USERNAME": "env-user"}):
            self.assertEqual(_setting(args, {"username": "config-user"}, "username"), "env-user")
            args.username = "cli-user"
            self.assertEqual(_setting(args, {"username": "config-user"}, "username"), "cli-user")

    def test_status_uses_generic_server_label(self):
        client = Mock()
        client.url = "https://127.0.0.1:11127"
        client.server_properties.return_value = {"server_version": "1.2.3"}
        output = io.StringIO()
        with patch("sys.stdout", new=output):
            self.assertEqual(cmd_status(client, argparse.Namespace(), {}), 0)
        self.assertIn("Phiên bản máy chủ: 1.2.3", output.getvalue())
        self.assertNotIn("nessus", output.getvalue().casefold())


class FakeResponse:
    ok = True
    status_code = 200
    reason = "OK"
    text = ""

    def __init__(self, data):
        self.data = data

    def json(self):
        return self.data

    def close(self):
        pass

    def iter_content(self, chunk_size):
        del chunk_size
        yield b"db-content"


class ClientTests(unittest.TestCase):
    def test_session_login_sets_x_cookie(self):
        session = Mock()
        session.headers = {}
        session.request.return_value = FakeResponse({"token": "abc"})
        original = __import__("requests").Session
        __import__("requests").Session = lambda: session
        try:
            client = NctlClient("https://127.0.0.1:8834", username="u", password="p")
        finally:
            __import__("requests").Session = original
        self.assertEqual(session.headers["X-Cookie"], "token=abc")
        call = session.request.call_args
        self.assertEqual(call.args[:2], ("POST", "https://127.0.0.1:8834/session"))

    def test_export_db_uses_history_password_and_download_token(self):
        client = NctlClient.__new__(NctlClient)
        client.post_json = Mock(return_value={"token": "export-token"})
        client.get_json = Mock(return_value={"status": "ready"})
        client._request = Mock(return_value=FakeResponse({}))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "scan.db"
            client.export_db(12, 34, "shared-password", destination)
            self.assertEqual(destination.read_bytes(), b"db-content")
        client.post_json.assert_called_once_with(
            "/scans/12/export",
            params={"history_id": 34},
            json={"format": "db", "password": "shared-password"},
            timeout=120,
        )
        client._request.assert_called_once_with(
            "GET", "/tokens/export-token/download", stream=True, timeout=300
        )

    def test_upload_file_sends_no_enc_in_query_not_multipart_body(self):
        client = NctlClient.__new__(NctlClient)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.db"
            path.write_bytes(b"encrypted-db-placeholder")
            for no_enc in (True, False):
                with self.subTest(no_enc=no_enc):
                    def request(method, route, **kwargs):
                        self.assertEqual((method, route), ("POST", "/file/upload"))
                        self.assertEqual(kwargs["params"], {"no_enc": str(int(no_enc))})
                        self.assertNotIn("data", kwargs)
                        filename, source, content_type = kwargs["files"]["Filedata"]
                        self.assertEqual(filename, "scan.db")
                        self.assertEqual(content_type, "application/octet-stream")
                        self.assertEqual(source.read(), b"encrypted-db-placeholder")
                        self.assertEqual(kwargs["timeout"], 600)
                        return FakeResponse({"fileuploaded": "uploaded-id"})

                    client._request = Mock(side_effect=request)
                    self.assertEqual(client.upload_file(path, no_enc=no_enc), "uploaded-id")
                    client._request.assert_called_once()

    def test_import_db_uploads_then_targets_folder(self):
        client = NctlClient.__new__(NctlClient)
        client.upload_file = Mock(return_value="uploaded-id")
        client.post_json = Mock(return_value={"scan": {"id": 99}})
        path = Path("backup.db")
        result = client.import_db(path, 7, "shared-password")
        client.upload_file.assert_called_once_with(path)
        self.assertEqual(result["scan"]["id"], 99)
        client.post_json.assert_called_once_with(
            "/scans/import",
            json={"file": "uploaded-id", "folder_id": 7, "password": "shared-password"},
            timeout=600,
        )

    def test_delete_scan_calls_delete_endpoint(self):
        client = NctlClient.__new__(NctlClient)
        response = FakeResponse({})
        client._request = Mock(return_value=response)
        client.delete_scan(42)
        client._request.assert_called_once_with("DELETE", "/scans/42")

    def test_move_scan_calls_folder_endpoint(self):
        client = NctlClient.__new__(NctlClient)
        response = FakeResponse({})
        client._request = Mock(return_value=response)
        client.move_scan(42, 2)
        client._request.assert_called_once_with(
            "PUT", "/scans/42/folder", json={"folder_id": 2}
        )

    def test_create_scan_enables_safety_and_credentials(self):
        client = NctlClient.__new__(NctlClient)
        client.post_json = Mock(return_value={"scan": {"id": 42}})
        credentials = {"add": {"Host": {"SSH": [{"username": "audit"}]}}}
        client.create_scan(
            "advanced-id",
            "safe scan",
            ["192.0.2.1"],
            safe=True,
            credentials=credentials,
            extra_settings={"ssh_port": "2222", "safe_checks": "no"},
        )
        payload = client.post_json.call_args.kwargs["json"]
        self.assertEqual(payload["settings"]["safe_checks"], "yes")
        self.assertEqual(payload["settings"]["stop_scan_on_disconnect"], "yes")
        self.assertEqual(payload["settings"]["ssh_port"], "2222")
        self.assertEqual(payload["credentials"], credentials)

    def test_create_scan_unsafe_disables_both_safety_settings(self):
        client = NctlClient.__new__(NctlClient)
        client.post_json = Mock(return_value={"scan": {"id": 43}})
        client.create_scan("advanced-id", "unsafe scan", ["192.0.2.1"], safe=False)
        settings = client.post_json.call_args.kwargs["json"]["settings"]
        self.assertEqual(settings["safe_checks"], "no")
        self.assertEqual(settings["stop_scan_on_disconnect"], "no")


if __name__ == "__main__":
    unittest.main()
