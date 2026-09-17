"""Offline user guide shipped with the CLI and portable executable."""

OVERVIEW = """nctl - quản lý scan và backup/restore DB

Bắt đầu:
  1. Đặt EXE và config.json trong cùng thư mục; mở terminal tại thư mục đó.
  2. Nếu chưa có config, sao chép config.example.json và điền url/username/password.
  3. Chạy .\\nctl.exe status để kiểm tra kết nối.

Ví dụ nhanh:
  .\\nctl.exe --version
  .\\nctl.exe help
  .\\nctl.exe help setup
  .\\nctl.exe help restore
  .\\nctl.exe backup --all
  .\\nctl.exe restore .\\backup

Tùy chọn kết nối phải đứng TRƯỚC subcommand:
  .\\nctl.exe --config config.json --url https://127.0.0.1:11127 status

Mỗi lệnh có --help kèm ví dụ. Help chạy offline, không cần config hay đăng nhập.
Bản EXE chạy độc lập trên Windows 64-bit, không cần cài Python.
Chạy mã nguồn: python nctl.py help hoặc python -m nctl help.
"""

TOPICS = {
    "setup": """Cấu hình và mật khẩu

Sao chép config.example.json thành config.json nếu chưa có. Ví dụ nội dung:
  {
    "url": "https://127.0.0.1:11127",
    "username": "admin",
    "password": "your-login-password",
    "verify_tls": false,
    "timeout": 60,
    "default_db_password": "your-shared-db-password"
  }

Mật khẩu đăng nhập và mật khẩu DB là HAI giá trị riêng biệt.
Không đổi default_db_password giữa backup và restore nếu muốn nhấn Enter ở cả hai.
Mỗi lượt backup/restore hỏi mật khẩu DB một lần; Enter dùng cấu hình mặc định.
Delete luôn bắt nhập lại mật khẩu đăng nhập, không lấy sẵn từ config.

Biến môi trường PowerShell (ưu tiên CLI > môi trường > config):
  $env:NCTL_USERNAME = "admin"
  $env:NCTL_PASSWORD = "your-login-password"
  $env:NCTL_DB_PASSWORD = "your-shared-db-password"
  $env:NCTL_ACCESS_KEY = "your-access-key"
  $env:NCTL_SECRET_KEY = "your-secret-key"
  $env:NCTL_TIMEOUT = "60"
Có thể dùng cặp API key thay username/password nếu máy chủ hỗ trợ.

Ví dụ:
  .\\nctl.exe --config D:\\Config\\config.json status
  .\\nctl.exe --non-interactive backup --all
  .\\nctl.exe --verify-tls status

Mặc định không kiểm tra TLS cho chứng chỉ tự ký; dùng --verify-tls khi đã tin cậy CA.
Không gửi config.json hoặc file credential thật cho người khác.
""",
    "status": """Ví dụ:
  .\\nctl.exe status
  .\\nctl.exe --url https://127.0.0.1:11127 status
Hiển thị trạng thái kết nối và phiên bản máy chủ, không chạy scan.
""",
    "folders": """Ví dụ:
  .\\nctl.exe folders
Hiển thị ID, type và tên folder. Dùng ID nếu có nhiều folder cùng tên.
""",
    "scans": """Ví dụ:
  .\\nctl.exe scans
  .\\nctl.exe scans --folder "My Scans"
  .\\nctl.exe scans --folder 7 --json
Hiển thị scan ID, tên, trạng thái, folder và số history.
Folder nhận ID hoặc tên, không phân biệt hoa thường.
""",
    "backup": """Ví dụ:
  .\\nctl.exe backup --scan 12
  .\\nctl.exe backup --scans "12,15,20" --output D:\\ScanBackups
  .\\nctl.exe backup --folder "Target Group 1"
  .\\nctl.exe backup --all
  .\\nctl.exe backup --all --include-trash
  .\\nctl.exe backup --folder Trash --include-trash
  .\\nctl.exe backup --scan 12 --history latest
  .\\nctl.exe backup --scan 12 --history 35

Mặc định backup mọi history của scan đã chọn; Trash bị bỏ qua.
Mỗi lượt dùng chung mật khẩu DB, hỏi một lần; Enter dùng mật khẩu mặc định.
--all giữ cấu trúc folder thực tế, kể cả folder rỗng (trừ Trash mặc định).
Thư mục output: nctl-backup-YYYYMMDD-HHMMSS, kèm manifest.json.
Tên file: scan-12_history-35_Ten scan.db; mỗi history là một file riêng.
Manifest lưu folder gốc, tên file và các lỗi; không lưu mật khẩu.
Backup cũ vẫn có thể restore mà không cần đổi tên.
Lỗi một history không dừng phần còn lại; exit code khác 0 nếu có lỗi.
""",
    "restore": """Ví dụ:
  .\\nctl.exe restore .\\task1.db
  .\\nctl.exe restore .\\backup
  .\\nctl.exe restore a.db b.db --folder "Recovered" --create-folder
  .\\nctl.exe restore .\\backup --folder 7 --flat

Không có --folder:
  - Path trỏ thẳng file .db: vào My Scans.
  - .db ngay trong backup: tạo/tái sử dụng folder tên backup.
  - backup/Target Group 1/task1.db: vào Target Group 1.
  - backup/Target Group 2/task2.db: vào Target Group 2.
  - backup/Archive/2025/task3.db: vào Archive - 2025.
Folder máy chủ là phẳng; đường dẫn nhiều cấp dùng dấu " - ".
Manifest của backup giúp lấy lại đúng tên folder gốc.

--folder đổi đích cho file .db trực tiếp và file ở gốc input.
--create-folder chỉ tạo tên chỉ định bởi --folder nếu chưa tồn tại.
Folder suy ra từ đường dẫn luôn tự tạo/tái sử dụng, không cần --create-folder.
--flat bỏ ánh xạ folder con và đưa tất cả vào --folder (bắt buộc).

Một lượt restore hỏi mật khẩu DB một lần; dùng ĐÚNG mật khẩu lúc backup.
Restore nhiều lần có thể tạo task trùng. Không tự retry khi lỗi import.
""",
    "delete": """Ví dụ:
  .\\nctl.exe delete --scan 12
  .\\nctl.exe delete --scans "12,15,20"
  .\\nctl.exe delete --folder "Old scans"
  .\\nctl.exe delete --all
  .\\nctl.exe delete --all --permanent
  .\\nctl.exe delete --folder Trash --permanent

Mặc định CHỈ CHUYỂN scan vào Trash; scan đã ở Trash được bỏ qua.
--permanent XÓA VĨNH VIỄN scan/history, không thể khôi phục.
--folder chọn theo ID/tên; folder custom bị xóa sau khi xử lý hết scan bên trong.
Folder hệ thống My Scans/Trash được giữ lại. --all giữ các folder.
Delete --folder Trash không có --permanent sẽ không xóa dữ liệu.
Luôn hiển thị cảnh báo và nhập lại mật khẩu đăng nhập trước khi thay đổi dữ liệu.
Delete không hỗ trợ --non-interactive. Nên backup trước khi xóa vĩnh viễn.
""",
    "task": """Ví dụ:
  .\\nctl.exe task create --targets targets.example.txt --name "Weekly servers"
  .\\nctl.exe task launch 42
Chi tiết: .\\nctl.exe help task create hoặc .\\nctl.exe help task launch.
""",
    "task create": """Ví dụ:
  .\\nctl.exe task create --targets targets.txt --name "Weekly servers"
  .\\nctl.exe task create --targets targets.txt --name "Weekly servers" --folder "My Scans" --launch
  .\\nctl.exe task create --targets targets.txt --name "Credentialed scan" --credentials-file credentials.example.jsonc
  .\\nctl.exe task create --targets targets.txt --name "Custom scan" --template "Basic Network Scan"
  .\\nctl.exe task create --targets targets.txt --name "Unsafe scan" --unsafe

targets.txt: mỗi dòng IPv4/IPv6, CIDR hoặc range; bỏ dòng trống/comment # và IP trùng.
Ví dụ: 192.0.2.1, 192.0.2.0/24, 2001:db8::1, 192.0.2.10-192.0.2.20.
Template mặc định Advanced Scan; --template nhận tên hoặc UUID.
Safe checks và dừng quét host mất phản hồi được BẬT mặc định.
--unsafe tắt cả hai. Chỉ quét các hệ thống bạn được phép kiểm tra.

Tài khoản SSH, Windows, SNMPv3 cấu hình bằng JSON/JSONC:
  Copy-Item credentials.example.jsonc credentials.jsonc
  $env:NCTL_TARGET_SSH_PASSWORD = "your-ssh-password"
  .\\nctl.exe task create --targets targets.txt --name "Audit" --credentials-file credentials.jsonc
Sửa các mục trong file example theo tài khoản thật và đặt đủ biến môi trường được tham chiếu.
Các key *_env lấy secret từ môi trường; *_file upload file tương đối với file config.
JSONC cho phép // và # ngoài chuỗi. Không gửi file chứa secret thật cho người khác.
Task chỉ được tạo, chưa chạy nếu không có --launch.
""",
    "task launch": """Ví dụ:
  .\\nctl.exe task launch 42
Chạy task đã tồn tại theo scan ID. Dùng monitor để theo dõi tiến độ.
""",
    "monitor": """Ví dụ:
  .\\nctl.exe monitor 42
  .\\nctl.exe monitor 42 --interval 5 --timeout 3600
  .\\nctl.exe monitor 42 --once
Hiển thị trạng thái và tiến độ từng chu kỳ; dừng khi scan kết thúc.
--timeout 0: không giới hạn thời gian. Ctrl+C chỉ dừng monitor, không dừng scan.
--timeout trước subcommand là HTTP timeout; sau monitor là thời hạn theo dõi.
""",
}
