"""Offline user guide shipped with the CLI and portable executable."""

OVERVIEW = """nctl - quản lý scan, report Excel và backup/restore DB

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
  .\\nctl.exe report --all --merge
  .\\nctl.exe merge .\\existing-reports
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
    "report": """Ví dụ:
  .\\nctl.exe report --scan 12
  .\\nctl.exe report --scans "12,15,20"
  .\\nctl.exe report --folder "Target Group 1"
  .\\nctl.exe report --folders "Target Group 1" "Target Group 2"
  .\\nctl.exe report --folders 7,8,9 --merge
  .\\nctl.exe report --all --merge --output D:\\ScanReports
  .\\nctl.exe report --all --include-trash

Mỗi scan xuất kết quả mới nhất thành một file Excel riêng, bật toàn bộ cột API hỗ trợ.
File riêng giữ nguyên thứ tự cột gốc và thêm Group ở cuối; file gộp cũng có Group.
Group không chứa host hay tên scan: lọc Group trên mọi host, rồi lọc Host/Source nếu cần.
Tên nhóm phần mềm bắt đầu bằng "Security updates /", ví dụ Ubuntu / Linux kernel,
Microsoft .NET Framework, Google Chrome, Apache Log4j, Fortinet FortiGate.
Tên phần mềm được lấy từ tên plugin, không giới hạn ở một danh sách package cố định.
Với tên chưa rõ, có thể xác nhận sản phẩm bằng Solution và phiên bản trong Plugin Output.
Phát hiện cấu hình có tiền tố "Configuration /"; thông tin có "Information /".
Trường hợp thiếu bằng chứng dùng "Cần xem lại / Plugin <ID>" để tránh gộp sai.
Không lọc severity/host/plugin; không hỏi mật khẩu DB.
Folder nhận ID hoặc tên, không phân biệt hoa thường; tên có dấu cách đặt trong ngoặc kép.
--folders nhận nhiều giá trị cách bằng dấu cách hoặc dấu phẩy; scan/folder trùng chỉ xử lý một lần.
--all bỏ qua Trash mặc định; --include-trash để lấy cả Trash.
Chọn rõ scan ID hoặc folder Trash vẫn xuất các scan đó.
Output mặc định: reports/nctl-report-YYYYMMDD-HHMMSS-microseconds/.
Tên file: scan-12_Ten scan.xlsx; manifest.json ghi các file và lỗi.
Từ 2 scan thực tế trở lên tự tạo merged.xlsx rồi merged_resolved.xlsx, bất kể đầu vào là list, folder, nhiều folder hay --all.
Với đúng 1 scan, dùng --merge nếu vẫn muốn tạo file gộp. Các file lẻ luôn được giữ nguyên.
File gộp chỉ có một header ở dòng đầu; dữ liệu tất cả scan nối tiếp phía sau.
Thứ tự đầu file gộp: Source, Group, Name, Risk, Host, Location, Description, Solution,
Plugin Output, See Also, CVE, sau đó là các cột còn lại.
Chỉ file gộp tạo Location từ Protocol/Port và Description từ Synopsis + dòng trống + Description gốc.
File gộp nối các xuống dòng đơn do wrap web trong Synopsis, Description và Solution;
vẫn giữ đoạn trống, bullet, danh sách đánh số, URL và khối thụt dòng. Plugin Output không bị reflow.
Tất cả cell căn trên và tắt Wrap Text, kể cả nội dung có nhiều dòng.
Header in đậm, freeze ở hàng đầu và bật sẵn Filter.
Ô vượt 32.767 ký tự được rút gọn, highlight, log địa chỉ ô và ghi chi tiết vào manifest.json.
Trong từng scan, gộp các dòng giống ở mọi cột ngoài CVE, giữ thứ tự xuất hiện đầu tiên.
Gom CVE khác nhau vào một ô, phân cách bằng "; ", bỏ CVE lặp và giữ đủ thông tin.
Dòng khác severity/score/plugin output hoặc bất kỳ cột nào ngoài CVE vẫn giữ riêng.
Dòng giống nhau ở các scan khác nhau vẫn được giữ theo Source tương ứng.
In số dòng đã đọc, dòng trùng/gộp bị loại và dòng unique giữ lại cho từng scan và tổng.
Các số đếm này cũng được lưu trong manifest.json; không tính header hoặc dòng trống.
Chỉ lọc trùng khi --merge; các file Excel lẻ vẫn giữ nguyên dữ liệu gốc.
Cột Source ở đầu file gộp ghi tên scan gốc cho từng dòng, giúp lọc khi IP trùng.
Sau merged.xlsx, chương trình tạo merged_resolved.xlsx với cột References ngay sau See Also.
Mỗi URL rút gọn dạng /u?... trong See Also chỉ resolve một lần; chỉ giữ URL đích trả HTTP 2xx và không redirect thêm.
URL hết hạn, lỗi kết nối hoặc redirect lần nữa bị bỏ qua; mỗi URL hợp lệ nằm trên một dòng trong cell.
Manifest ghi số URL tìm thấy/unique/thành công/bị bỏ và chi tiết trạng thái. Bước này cần Internet.
Tên scan giữ nguyên, không lấy tên file đã thay ký tự; scan thiếu tên dùng scan-ID.
Giữ nguyên dấu phẩy, dấu ngoặc kép, Unicode và nội dung xuống dòng trong ô.
Nếu các scan có cột khác nhau, lấy hợp tất cả cột, ánh xạ theo tên và để trống ô thiếu.
Lỗi một scan không dừng scan còn lại; exit code 2 nếu có lỗi export/gộp.
Nếu scan nào thất bại, merged.xlsx chỉ chứa các scan xuất thành công; xem manifest.json.
Scan chưa có kết quả hoặc không có quyền export có thể báo lỗi từ máy chủ.
""",
    "merge": """Ví dụ:
  .\\nctl.exe merge .\\existing-reports
  .\\nctl.exe merge --folder D:\\ScanReports
  .\\nctl.exe merge .\\existing-reports --output D:\\Combined\\report.xlsx

Lệnh chạy offline, không cần config hoặc đăng nhập máy chủ.
Đọc trực tiếp các file .csv và .xlsx ở cấp đầu tiên của thư mục; dùng worksheet đầu tiên của XLSX.
File output hiện tại được bỏ qua nếu nằm trong thư mục đầu vào.
Nếu một dòng đã có Source hoặc Group thì giữ giá trị đó; ô trống hoặc cột thiếu sẽ được tự bổ sung.
Source thiếu dùng tên file không có phần mở rộng. Group thiếu được phân loại theo cùng quy tắc report.
Nếu file đã có Location/Description tổng hợp thì giữ nguyên; nếu còn Protocol/Port hoặc Synopsis/Description
thì tạo Location và Description theo cùng quy tắc merged.xlsx của report.
Đầu ra mặc định là <folder>/merged.xlsx, <folder>/merged_resolved.xlsx và <folder>/merged.manifest.json.
File gộp áp dụng unique/CVE, thứ tự cột, highlight ô bị rút gọn, header, freeze và Filter như report.
Synopsis, Description và Solution cũng được bỏ xuống dòng do wrap web; Plugin Output giữ nguyên.
Sau khi tạo merged.xlsx, lệnh tạo merged_resolved.xlsx với cột References ngay sau See Also.
Chỉ URL rút gọn dạng /u?... trong See Also được resolve; URL đích phải trả HTTP 2xx và không redirect thêm.
Mỗi reference nằm trên một dòng. Bước resolve cần Internet; kết quả được ghi trong manifest.
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
Upload tự thử lại tối đa 3 lần khi lỗi kết nối/timeout/TLS EOF, chờ 2/4/8 giây.
Không retry lỗi chứng chỉ, HTTP hoặc /scans/import (tránh task trùng).
Resume mặc định: ghi .nctl-restore.json cạnh mỗi nhóm file .db sau import OK.
Chạy lại cùng lệnh: bỏ qua file thành công, thử lại file lỗi/chưa xử lý.
Checkpoint nhận diện nội dung + tên file + máy chủ + tài khoản + folder ID.
Không lưu mật khẩu/API key. Giữ checkpoint cùng backup khi chuyển thư mục.
--force import lại dù có checkpoint; có thể tạo task trùng:
  .\\nctl.exe restore .\\backup --force
Không chạy đồng thời nhiều restore trên cùng thư mục.
Checkpoint không kiểm tra scan còn tồn tại; đã xóa scan thì dùng --force.
Mất phản hồi import hoặc dừng đúng lúc import xong nhưng chưa ghi checkpoint:
kiểm tra scan trên máy chủ trước khi chạy lại vì có thể đã import thành công.
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
Folder hệ thống My Scans/Trash được giữ lại. --all xóa cả folder custom đã rỗng.
Folder còn scan (do lỗi hoặc scan mới xuất hiện) được giữ lại, báo lỗi.
Delete --folder Trash không có --permanent sẽ không xóa dữ liệu.
Luôn hiển thị cảnh báo. Chỉ --permanent yêu cầu nhập lại mật khẩu đăng nhập.
Không --permanent: thực hiện ngay, không hỏi mật khẩu xác nhận; vẫn cần đăng nhập API.
--non-interactive dùng được nếu không --permanent và có thông tin đăng nhập config/env.
--permanent không hỗ trợ --non-interactive. Nên backup trước khi xóa vĩnh viễn.
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
