# nctl

Công cụ dòng lệnh quản lý máy chủ quét: list scan/history, backup/restore `.db`, tạo task và monitor.

## Bắt đầu

```powershell
if (-not (Test-Path config.json)) { Copy-Item config.example.json config.json }
# Sửa url, username và password trong config.json
.\nctl.exe status
.\nctl.exe help
```

Mọi hướng dẫn, ví dụ và lưu ý an toàn được tích hợp trong chương trình:

```powershell
.\nctl.exe --help
.\nctl.exe help setup
.\nctl.exe help backup
.\nctl.exe help restore
.\nctl.exe help delete
.\nctl.exe help task
.\nctl.exe help monitor
```

Bản Windows portable không cần Python. Khi chạy mã nguồn: `python nctl.py help` hoặc `python -m nctl help`.

## Phát triển

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
pyinstaller --noconfirm nctl.spec
```

Không chia sẻ `config.json` hay file credential đã cấu hình vì có thể chứa bí mật.

## Cấu trúc project

- `nctl/`: mã nguồn CLI, API client và help tích hợp.
- `nctl.py`: entry point khi chạy Python hoặc đóng gói EXE.
- `nctl.spec`: cấu hình build EXE; `pyproject.toml`: package và lệnh `nctl`.
- `tests/`: kiểm thử; các file `*.example.*`: cấu hình mẫu.
- `dist/nctl.exe`, `release/`: EXE và bản portable mới nhất.
- `config.json`, `backups/`, `.venv/`: cấu hình/dữ liệu/môi trường local, không đưa vào Git.

`build/`, cache Python và metadata `*.egg-info/` được tự tạo lại khi test/build/install.
