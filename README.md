# nctl

Công cụ dòng lệnh quản lý máy chủ quét: list scan/history, report Excel, backup/restore `.db`, tạo task và monitor.

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

## Report Excel

Xuất report Excel đầy đủ cột, mỗi scan một file riêng (kết quả mới nhất):

```powershell
.\nctl.exe report --scan 12
.\nctl.exe report --scans "12,15,20"
.\nctl.exe report --folder "Target Group 1"
.\nctl.exe report --folders "Target Group 1" "Target Group 2" --merge
.\nctl.exe report --all --merge
```

Output mặc định trong `reports/nctl-report-.../`. Từ 2 scan thực tế trở lên chương trình tự tạo
`merged.xlsx`, bất kể chọn bằng list scan, folder, nhiều folder hay `--all`. Với đúng 1 scan,
dùng `--merge` nếu vẫn muốn tạo file gộp;
các file Excel riêng vẫn được giữ. Mỗi file riêng giữ nguyên thứ tự cột gốc và thêm `Group` ở cuối.
File gộp đặt các cột đầu theo thứ tự `Source`, `Group`, `Name`, `Risk`, `Host`, `Location`,
`Description`, `Solution`, `Plugin Output`, `See Also`, `CVE`, rồi đến các cột còn lại.
Chỉ trong file gộp, `Location` ghép `Protocol/Port`; `Description` ghép `Synopsis`, một dòng trống,
rồi `Description` gốc. Tất cả ô được căn trên và tắt Wrap Text.
Trong file merge, các xuống dòng đơn dùng để wrap nội dung web được nối lại trong `Synopsis`,
`Description` và `Solution`; đoạn trống, bullet, danh sách, URL và khối thụt dòng được giữ nguyên.
Hàng header được in đậm, freeze ở trên cùng và bật sẵn Filter. Ô vượt giới hạn 32.767 ký tự
của Excel được rút gọn, highlight, in cảnh báo ra terminal và ghi chi tiết vào `manifest.json`.
Group chỉ mô tả nguyên nhân/thành phần (ví dụ `Security updates / Ubuntu / Linux kernel`
hoặc `Security updates / Microsoft .NET Framework`), không chứa host hay tên scan.
Tên group ưu tiên tên plugin; trường hợp tên chưa rõ cần bằng chứng phiên bản trong
`Plugin Output` và sản phẩm được nêu trong `Solution`, không dùng danh sách package cố định.
Lọc thêm `Host` hoặc `Source` để thu hẹp phạm vi. Trường hợp chưa rõ được ghi
`Cần xem lại / Plugin <ID>`; dữ liệu gốc và thứ tự dòng được giữ nguyên.
Cột `Source` ở đầu file gộp chứa tên scan sinh ra từng dòng, giúp lọc các IP trùng giữa scan.
Khi gộp, các dòng giống ở mọi cột ngoài `CVE` trong từng scan được gom thành một dòng,
theo thứ tự ban đầu; ô `CVE` chứa toàn bộ CVE khác nhau, phân cách bằng `; `.
Dòng khác ở bất kỳ cột nào ngoài `CVE` vẫn giữ riêng.
Dòng giống nhau từ các scan khác nhau vẫn được giữ với `Source` tương ứng.
Log và `manifest.json` ghi số dòng đọc, dòng trùng bị loại và dòng unique giữ lại cho từng scan và tổng.
Chỉ `merged.xlsx` được lọc trùng khi dùng `--merge`; các file riêng giữ nguyên dữ liệu gốc.
`--all` bỏ qua Trash; thêm `--include-trash` để lấy cả Trash. Lỗi và thống kê nhóm được ghi vào `manifest.json`
và trả exit code 2. Chi tiết: `nctl help report`.

Merge các report CSV/XLSX đã có mà không cần kết nối máy chủ:

```powershell
.\nctl.exe merge .\existing-reports
.\nctl.exe merge --folder D:\ScanReports --output D:\Combined\report.xlsx
```

Lệnh đọc các file `.csv` và `.xlsx` ở cấp đầu tiên của thư mục. Nếu đã có `Source`, `Group`,
`Location` hoặc `Description` tổng hợp thì giữ lại; cột thiếu được bổ sung theo cùng logic của
`report --merge`. Khi thiếu `Source`, tên file được dùng làm nguồn. Output mặc định là
`merged.xlsx` cùng `merged.manifest.json` trong thư mục đầu vào. Lệnh này chạy offline.

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
