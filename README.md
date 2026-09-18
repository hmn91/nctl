# nctl

Công cụ dòng lệnh quản lý máy chủ quét: list scan/history, report CSV, backup/restore `.db`, tạo task và monitor.

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
.\nctl.exe help report
.\nctl.exe help restore
.\nctl.exe help delete
.\nctl.exe help task
.\nctl.exe help monitor
```

Bản Windows portable không cần Python. Khi chạy mã nguồn: `python nctl.py help` hoặc `python -m nctl help`.

## Report CSV

Xuất report CSV đầy đủ cột, mỗi scan một file riêng (kết quả mới nhất):

```powershell
.\nctl.exe report --scan 12
.\nctl.exe report --scans "12,15,20"
.\nctl.exe report --folder "Target Group 1"
.\nctl.exe report --folders "Target Group 1" "Target Group 2" --merge
.\nctl.exe report --all --merge
```

Output mặc định trong `reports/nctl-report-.../`. `--merge` tạo thêm `merged.csv`
với một header ở đầu và dữ liệu nối tiếp của các CSV xuất thành công; giữ nguyên file lẻ.
`--all` bỏ qua Trash; thêm `--include-trash` để lấy cả Trash. Lỗi được ghi vào `manifest.json`
và trả exit code 2. Chi tiết: `nctl help report`.

## Phát triển

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
pyinstaller --noconfirm nctl.spec
```

Không chia sẻ `config.json` hay file credential đã cấu hình vì có thể chứa bí mật.

Restore tự retry upload tối đa 3 lần khi lỗi kết nối/timeout/TLS EOF (chờ 2/4/8 giây),
không tự retry bước import. Resume mặc định lưu `.nctl-restore.json` cạnh file `.db`:
chạy lại cùng lệnh sẽ bỏ qua file đã import thành công vào cùng máy chủ/tài khoản/folder.
Dùng `restore ... --force` để import lại (có thể tạo scan trùng). Giữ checkpoint khi
chuyển backup; không chạy nhiều restore đồng thời trên cùng thư mục. Nếu mất phản hồi
import, kiểm tra scan trên server trước khi chạy lại. Chi tiết: `nctl help restore`.

## Cấu trúc project

- `nctl/`: mã nguồn CLI, API client và help tích hợp.
- `nctl.py`: entry point khi chạy Python hoặc đóng gói EXE.
- `nctl.spec`: cấu hình build EXE; `pyproject.toml`: package và lệnh `nctl`.
- `tests/`: kiểm thử; các file `*.example.*`: cấu hình mẫu.
- `dist/nctl.exe`, `release/`: EXE và bản portable mới nhất.
- `config.json`, `backups/`, `.venv/`: cấu hình/dữ liệu/môi trường local, không đưa vào Git.

`build/`, cache Python và metadata `*.egg-info/` được tự tạo lại khi test/build/install.
