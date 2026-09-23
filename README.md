# nctl

`nctl` là CLI quản lý máy chủ quét: xem folder/scan, xuất report Excel, backup và restore database,
tạo hoặc chạy task, theo dõi tiến độ và xóa scan. Bản Windows portable chạy độc lập; mã nguồn yêu cầu
Python 3.10 trở lên.

Phiên bản hiện tại: **2.6.1**. Thay đổi chi tiết xem tại [RELEASE_NOTES.md](RELEASE_NOTES.md).

## Bắt đầu nhanh

### Windows portable

Giải nén gói phát hành, mở PowerShell tại thư mục đó rồi tạo cấu hình:

```powershell
Copy-Item config.example.json config.json
# Sửa url, username và password trong config.json
.\nctl.exe status
.\nctl.exe help
```

### Chạy từ mã nguồn

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python nctl.py status
```

Không đưa `config.json`, file credential thật, database backup hoặc report có dữ liệu nhạy cảm lên Git.

## Cấu hình

Thứ tự ưu tiên là tham số CLI, biến môi trường, `config.json`, sau đó mới đến giá trị mặc định.
Các biến thường dùng:

```powershell
$env:NCTL_USERNAME = "admin"
$env:NCTL_PASSWORD = "your-login-password"
$env:NCTL_DB_PASSWORD = "your-db-password"
$env:NCTL_ACCESS_KEY = "your-access-key"
$env:NCTL_SECRET_KEY = "your-secret-key"
$env:NCTL_TIMEOUT = "60"
```

Mặc định chương trình dùng `https://127.0.0.1:11127` và không kiểm tra TLS để hỗ trợ chứng chỉ tự ký.
Dùng `--verify-tls` khi máy đã tin cậy CA. Có thể dùng access key/secret key thay cho username/password.

## Lệnh chính

| Lệnh | Mục đích |
| --- | --- |
| `status` | Kiểm tra kết nối và phiên bản máy chủ |
| `folders` | Liệt kê folder |
| `scans` | Liệt kê scan, có thể lọc theo folder |
| `report` | Xuất report Excel từ một hoặc nhiều scan/folder |
| `merge` | Gộp các file CSV/XLSX có sẵn và tạo report chuẩn hóa |
| `backup` | Tải database `.db` theo scan/history |
| `restore` | Import lại database, có checkpoint để resume |
| `delete` | Chuyển scan vào Trash hoặc xóa vĩnh viễn |
| `task create` | Tạo scan từ danh sách target và credential tùy chọn |
| `task launch` | Chạy scan đã tồn tại |
| `monitor` | Theo dõi trạng thái và tiến độ scan |

Hướng dẫn đầy đủ luôn có trong chương trình:

```powershell
.\nctl.exe --help
.\nctl.exe help report
.\nctl.exe help merge
.\nctl.exe help backup
.\nctl.exe help restore
.\nctl.exe help delete
.\nctl.exe help task create
.\nctl.exe help monitor
```

## Thư mục dữ liệu mặc định

Chương trình tách dữ liệu runtime dưới `data/`:

- Report: `data/reports/nctl-report-YYYYMMDD-HHMMSS-microseconds/`
- Backup: `data/backups/nctl-backup-YYYYMMDD-HHMMSS/`

Thư mục `data/`, `config.json`, `.venv/`, `build/`, `dist/` và `release/` không được commit.

## Report Excel

### Chọn dữ liệu

```powershell
.\nctl.exe report --scan 12
.\nctl.exe report --scans "12,15,20"
.\nctl.exe report --folder "Target Group 1"
.\nctl.exe report --folders "Target Group 1" "Target Group 2"
.\nctl.exe report --all
.\nctl.exe report --all --include-trash
```

`--scan` và `--scans` nhận scan ID. `--folder` và `--folders` nhận folder ID hoặc tên, không phân biệt
hoa thường. Scan/folder trùng chỉ được xử lý một lần. `--all` bỏ qua Trash trừ khi có `--include-trash`.

Từ hai scan thực tế trở lên, chương trình tự động merge bất kể kiểu selector. Với đúng một scan, thêm
`--merge` nếu vẫn muốn tạo file gộp.

### File đầu ra

| File | Nội dung |
| --- | --- |
| `scan-<id>_<name>.xlsx` | Một file cho mỗi scan; giữ cột gốc và thêm `Group` ở cuối |
| `merged.xlsx` | Dữ liệu chuẩn hóa và gộp từ các scan thành công |
| `merged_resolved.xlsx` | Bản gộp có thêm cột `References` sau `See Also` |
| `merged_resolved_lookup.xlsx` | Chi tiết URL nguồn, URL đích, status, số lần thử và lý do giữ/bỏ |
| `manifest.json` | Metadata, lỗi, thống kê dòng, group, URL và cell bị rút gọn |

Một scan export lỗi không dừng các scan còn lại. Khi có lỗi, exit code là 2 và `merged.xlsx` chỉ chứa
những scan xuất thành công.

### Chuẩn hóa file gộp

Các cột đầu được sắp theo thứ tự:

`Source`, `Group`, `Name`, `Risk`, `Host`, `Location`, `Description`, `Solution`, `Plugin Output`,
`See Also`, `CVE`, sau đó đến các cột còn lại.

- `Source` là tên scan sinh ra dòng dữ liệu, giúp phân biệt IP trùng giữa nhiều scan.
- `Location` ghép `Protocol/Port` theo dạng `<protocol>/<port>`.
- `Description` ghép `Synopsis`, hai ký tự xuống dòng, rồi `Description` gốc.
- Xuống dòng mềm do giao diện web trong `Synopsis`, `Description` và `Solution` được nối lại; paragraph,
  bullet, danh sách, URL và khối thụt dòng vẫn được giữ.
- Các dòng giống ở mọi cột ngoài `CVE` được gom trong phạm vi từng scan; CVE khác nhau được nối bằng `; `.
- Dòng từ scan khác nhau vẫn tách riêng nhờ `Source`.
- Header in đậm, freeze top row và bật Filter; mọi cell căn trên và tắt Wrap Text.
- Cell vượt 32.767 ký tự được rút gọn, highlight, log ra terminal và ghi vị trí vào manifest.

### Phân nhóm lỗ hổng

`Group` mô tả nguyên nhân hoặc thành phần, không chứa host hay tên scan. Ví dụ:

- `Security updates / Ubuntu / Linux kernel`
- `Security updates / Microsoft .NET Framework`
- `Security updates / Google Chrome`
- `Configuration / TLS`
- `Information / Service detection`

Tên group ưu tiên tên plugin. Khi tên chưa rõ, logic dùng thêm sản phẩm trong `Solution` và bằng chứng
phiên bản trong `Plugin Output`; không giới hạn vào danh sách package cố định. Trường hợp chưa đủ bằng chứng
được ghi `Cần xem lại / Plugin <ID>`.

### Resolve References

Sau khi tạo `merged.xlsx`, chương trình resolve **mọi URL HTTP/HTTPS** trong `See Also`, kể cả dòng có
`Risk = None`:

1. URL rút gọn dạng `nessus.org/u?...` được chuẩn hóa qua endpoint Tenable.
2. URL trực tiếp được kiểm tra ngay; mỗi URL nguồn chuẩn hóa chỉ resolve một lần.
3. Tối đa 16 worker chạy liên tục; progress được in sau mỗi 25 URL hoàn thành.
4. Theo tối đa 20 redirect, dừng nếu phát hiện loop.
5. Redirect từ trang con về homepage chỉ bị bỏ khi hostname giống nhau, không tính tiền tố `www`.
   Chuyển sang subdomain khác vẫn tiếp tục được kiểm tra.
6. URL đích trùng nhau chỉ xuất hiện một lần trong mỗi cell `References`, kể cả khi URL đã tồn tại sẵn.

| Kết quả | Xử lý |
| --- | --- |
| HTTP 2xx | Giữ trong `References`, status `resolved` |
| HTTP 401/403 | Retry; nếu vẫn bị chặn thì giữ, status `access_restricted` |
| HTTP 404/410, lỗi HTTP khác hoặc lỗi kết nối sau retry | Bỏ |
| Redirect loop hoặc quá 20 redirect | Bỏ, không retry |
| Trang con quay về homepage cùng hostname | Bỏ, không retry |

Các lỗi `access_restricted`, `shortener_not_redirect`, `missing_location`, `target_unavailable` và
`request_error` được retry tối đa ba lần sau lần đầu, chờ lần lượt 1, 2 và 4 giây.

## Merge report có sẵn

```powershell
.\nctl.exe merge .\existing-reports
.\nctl.exe merge --folder D:\ScanReports
.\nctl.exe merge .\existing-reports --output D:\Combined\report.xlsx
```

Lệnh đọc file `.csv` và `.xlsx` ở cấp đầu tiên của thư mục, dùng worksheet đầu tiên của XLSX. File output
hiện tại được loại khỏi input khi chạy lại. Cột `Source`, `Group`, `Location` và `Description` có sẵn được giữ;
ô hoặc cột thiếu được bổ sung theo cùng logic của `report --merge`. Nếu thiếu `Source`, tên file được dùng.

Bước đọc và gộp file không cần kết nối máy chủ; bước tạo file resolved cần Internet để kiểm tra URL.

## Backup và restore

```powershell
.\nctl.exe backup --scan 12
.\nctl.exe backup --folder "Target Group 1"
.\nctl.exe backup --all
.\nctl.exe restore .\data\backups\nctl-backup-...
```

Backup mặc định lấy mọi history và giữ cấu trúc folder. Restore dùng `.nctl-restore.json` làm checkpoint:
chạy lại cùng lệnh sẽ bỏ qua file đã import thành công vào cùng máy chủ, tài khoản và folder. Upload tự retry
tối đa ba lần khi gặp lỗi kết nối, timeout hoặc TLS EOF, chờ 2/4/8 giây. `--force` import lại và có thể tạo
scan trùng.

## Task, monitor và delete

```powershell
.\nctl.exe task create --targets targets.txt --name "Weekly servers"
.\nctl.exe task launch 42
.\nctl.exe monitor 42 --interval 5
.\nctl.exe delete --scan 42
```

`delete` mặc định chỉ chuyển scan vào Trash. `--permanent` xóa vĩnh viễn và yêu cầu nhập lại mật khẩu đăng
nhập. Nên backup trước khi xóa vĩnh viễn. Credential cho task có thể lấy từ biến môi trường và file
`credentials.example.jsonc`; không lưu secret thật trong repository.

## Phát triển và build

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean nctl.spec
.\dist\nctl.exe --version
```

Dependencies runtime được khai báo trong `pyproject.toml` và `requirements.txt`: `requests` và
`XlsxWriter`. Cấu trúc chính:

- `nctl/`: CLI, API client, xử lý report và help tích hợp.
- `tests/`: unit/integration tests không yêu cầu máy chủ thật.
- `nctl.py`: entry point khi chạy mã nguồn.
- `nctl.spec`: cấu hình PyInstaller.
- `config.example.json`, `credentials.example.jsonc`, `targets.example.txt`: file mẫu an toàn.
