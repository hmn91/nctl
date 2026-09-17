from __future__ import annotations

import time
from pathlib import Path
from typing import Any, BinaryIO, Iterable
from urllib.parse import quote

import requests
import urllib3

from . import __version__


class NctlError(RuntimeError):
    """Lỗi trả về từ máy chủ quét hoặc lỗi kết nối."""


class NctlClient:
    def __init__(
        self,
        url: str,
        *,
        username: str | None = None,
        password: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        verify_tls: bool | str = False,
        timeout: float = 60,
    ) -> None:
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"Accept": "application/json", "User-Agent": f"nctl/{__version__}"}
        )
        self._session_token: str | None = None

        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if access_key and secret_key:
            self.session.headers["X-ApiKeys"] = (
                f"accessKey={access_key}; secretKey={secret_key}"
            )
        elif username and password:
            self.login()
        else:
            raise NctlError(
                "Cần username/password hoặc cả NCTL_ACCESS_KEY và NCTL_SECRET_KEY."
            )

    def login(self) -> None:
        response = self._request(
            "POST",
            "/session",
            auth_required=False,
            allow_reauth=False,
            json={"username": self.username, "password": self.password},
        )
        data = self._json(response)
        token = data.get("token")
        if not token:
            raise NctlError("máy chủ quét không trả về session token.")
        self._session_token = str(token)
        self.session.headers["X-Cookie"] = f"token={token}"

    def close(self) -> None:
        if self._session_token:
            try:
                self._request("DELETE", "/session", allow_reauth=False)
            except NctlError:
                pass
        self.session.close()

    def verify_login_password(self, username: str, password: str) -> None:
        """Verify destructive-action confirmation using a separate login session."""
        verifier = NctlClient(
            self.url,
            username=username,
            password=password,
            verify_tls=self.verify_tls,
            timeout=self.timeout,
        )
        verifier.close()

    def __enter__(self) -> "NctlClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        auth_required: bool = True,
        allow_reauth: bool = True,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        try:
            response = self.session.request(
                method,
                f"{self.url}{path}",
                verify=self.verify_tls,
                timeout=timeout or self.timeout,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise NctlError(f"Không kết nối được tới {self.url}: {exc}") from exc

        if (
            response.status_code == 401
            and auth_required
            and allow_reauth
            and self.username
            and self.password
        ):
            response.close()
            self.login()
            return self._request(
                method,
                path,
                auth_required=auth_required,
                allow_reauth=False,
                timeout=timeout,
                **kwargs,
            )

        if not response.ok:
            detail = self._error_detail(response)
            response.close()
            raise NctlError(
                f"máy chủ quét API {method} {path} trả về HTTP {response.status_code}: {detail}"
            )
        return response

    @staticmethod
    def _json(response: requests.Response) -> dict[str, Any]:
        try:
            data = response.json()
        except ValueError as exc:
            raise NctlError("máy chủ quét trả về dữ liệu không phải JSON.") from exc
        if not isinstance(data, dict):
            raise NctlError("máy chủ quét trả về JSON không đúng cấu trúc mong đợi.")
        return data

    @staticmethod
    def _error_detail(response: requests.Response) -> str:
        try:
            data = response.json()
            if isinstance(data, dict):
                return str(
                    data.get("error")
                    or data.get("message")
                    or data.get("details")
                    or data
                )
        except ValueError:
            pass
        text = response.text.strip().replace("\n", " ")
        return text[:500] or response.reason

    def get_json(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._json(self._request("GET", path, **kwargs))

    def post_json(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._json(self._request("POST", path, **kwargs))

    def server_properties(self) -> dict[str, Any]:
        return self.get_json("/server/properties")

    def list_scans(self, folder_id: int | None = None) -> dict[str, Any]:
        params = {"folder_id": folder_id} if folder_id is not None else None
        return self.get_json("/scans", params=params)

    def scan_details(self, scan_id: int, history_id: int | None = None) -> dict[str, Any]:
        params = {"history_id": history_id} if history_id is not None else None
        return self.get_json(f"/scans/{scan_id}", params=params)

    def list_folders(self) -> list[dict[str, Any]]:
        data = self.get_json("/folders")
        return list(data.get("folders") or [])

    def create_folder(self, name: str) -> int:
        data = self.post_json("/folders", json={"name": name})
        return int(data["id"])

    def delete_scan(self, scan_id: int) -> None:
        response = self._request("DELETE", f"/scans/{scan_id}")
        response.close()

    def move_scan(self, scan_id: int, folder_id: int) -> None:
        response = self._request(
            "PUT", f"/scans/{scan_id}/folder", json={"folder_id": folder_id}
        )
        response.close()

    def delete_folder(self, folder_id: int) -> None:
        response = self._request("DELETE", f"/folders/{folder_id}")
        response.close()

    def export_db(
        self,
        scan_id: int,
        history_id: int,
        password: str,
        destination: Path,
        *,
        poll_interval: float = 1.0,
        export_timeout: float = 1800,
    ) -> None:
        queued = self.post_json(
            f"/scans/{scan_id}/export",
            params={"history_id": history_id},
            json={"format": "db", "password": password},
            timeout=120,
        )
        token = queued.get("token")
        if not token:
            raise NctlError(f"Không nhận được export token cho scan {scan_id}.")

        started = time.monotonic()
        encoded_token = quote(str(token), safe="")
        while True:
            status_data = self.get_json(f"/tokens/{encoded_token}/status")
            status = str(status_data.get("status", "")).lower()
            if status == "ready":
                break
            if status in {"error", "failed", "cancelled", "canceled"}:
                raise NctlError(
                    f"Export scan {scan_id}, history {history_id} thất bại: {status_data}"
                )
            if time.monotonic() - started >= export_timeout:
                raise NctlError(
                    f"Export scan {scan_id}, history {history_id} quá thời hạn "
                    f"{export_timeout:g} giây."
                )
            time.sleep(poll_interval)

        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_suffix(destination.suffix + ".part")
        response = self._request(
            "GET", f"/tokens/{encoded_token}/download", stream=True, timeout=300
        )
        try:
            with partial.open("wb") as output:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        output.write(chunk)
            partial.replace(destination)
        finally:
            response.close()
            if partial.exists():
                partial.unlink()

    def upload_file(self, path: Path, *, no_enc: bool = True) -> str:
        with path.open("rb") as source:
            data = self._json(
                self._request(
                    "POST",
                    "/file/upload",
                    params={"no_enc": str(int(no_enc))},
                    files={
                        "Filedata": (
                            path.name,
                            source,
                            "application/octet-stream",
                        )
                    },
                    timeout=600,
                )
            )
        file_id = data.get("fileuploaded")
        if not file_id:
            raise NctlError(f"máy chủ quét không trả về file ID sau khi upload {path}.")
        return str(file_id)

    def import_db(self, path: Path, folder_id: int, password: str) -> dict[str, Any]:
        file_id = self.upload_file(path)
        return self.post_json(
            "/scans/import",
            json={"file": file_id, "folder_id": folder_id, "password": password},
            timeout=600,
        )

    def list_scan_templates(self) -> list[dict[str, Any]]:
        data = self.get_json("/editor/scan/templates")
        if isinstance(data.get("templates"), list):
            return data["templates"]
        return []

    def create_scan(
        self,
        template_uuid: str,
        name: str,
        targets: Iterable[str],
        *,
        folder_id: int | None = None,
        scanner_id: int | None = None,
        safe: bool = True,
        credentials: dict[str, Any] | None = None,
        extra_settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        settings: dict[str, Any] = {
            "name": name,
            "enabled": False,
            "text_targets": "\n".join(targets),
        }
        if extra_settings:
            settings.update(extra_settings)
        settings["safe_checks"] = "yes" if safe else "no"
        settings["stop_scan_on_disconnect"] = "yes" if safe else "no"
        if folder_id is not None:
            settings["folder_id"] = folder_id
        if scanner_id is not None:
            settings["scanner_id"] = scanner_id
        payload: dict[str, Any] = {"uuid": template_uuid, "settings": settings}
        if credentials:
            payload["credentials"] = credentials
        return self.post_json("/scans", json=payload)

    def launch_scan(self, scan_id: int) -> str:
        data = self.post_json(f"/scans/{scan_id}/launch", json={})
        return str(data.get("scan_uuid") or "")
