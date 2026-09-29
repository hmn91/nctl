# Release notes

## nctl 2.7.1 — 2026-09-29

### Sửa lỗi unmask workbook do Microsoft Excel lưu

- Giữ lại prefix namespace chuẩn của Excel (`mc`, `x14ac`, `xr`, `xr2`, `xr3`) khi ghi lại worksheet.
- Đồng bộ `mc:Ignorable` với các namespace thực sự còn được sử dụng, tránh cảnh báo “We found a problem with
  some content” khi mở file `_unmasked.xlsx`.
- Chuẩn hóa mọi chuỗi rỗng thành cell rỗng thực sự khi mask/unmask; không còn `t="s"`/`<v>15</v>` trỏ tới
  một mục rỗng trong `sharedStrings.xml` khiến một số bộ đọc XLSX của AI hiểu nhầm giá trị là `15`.
- Thêm regression test mô phỏng đúng workbook có compatibility/revision namespaces của Microsoft Excel.
- 104 tests passed trên Python 3.10.

## nctl 2.7.0 — 2026-09-28

### Mask/unmask report dành cho AI

- Thêm lệnh offline `mask` và `unmask` cho file XLSX.
- `Host` và `Location` được thay bằng token ngẫu nhiên khoảng 130-bit, dùng alphabet tránh ký tự dễ nhầm và
  giữ nhãn loại dễ đọc như `[[HOST:...]]`/`[[LOCATION:...]]`; mapping được bảo vệ bằng AES-256-GCM và scrypt.
- Giữ nguyên cột `Plugin Output` nhưng làm rỗng toàn bộ giá trị trong bản masked.
- `unmask` thay mọi token đã map trong mọi ô của mọi sheet, kể cả khi token xen giữa nội dung khác hoặc hàng
  đã được sắp xếp lại; `Plugin Output` được giữ nguyên.
- Xóa cả dữ liệu nhạy cảm không còn được tham chiếu trong `sharedStrings.xml` của gói XLSX.
- `report` luôn tạo bản masked dành cho AI từ `merged_resolved.xlsx`, hoặc từ `merged.xlsx` nếu resolve lỗi.

### Report luôn merge

- Bỏ option `report --merge`; `report` luôn merge kể cả khi chỉ chọn một scan.
- Luôn giữ các file report riêng và file gộp đầy đủ song song với bản masked.
- 102 tests passed trên Python 3.10, gồm mask/unmask nhiều sheet, sai mật khẩu, dữ liệu ẩn trong XLSX và
  kết quả AI đã sắp xếp lại nội dung.

## nctl 2.6.1 — 2026-09-23

### Điểm nổi bật

- Mặc định lưu report tại `data/reports/` và backup tại `data/backups/` để tách dữ liệu runtime khỏi mã nguồn.
- Tạo thêm `merged_resolved_lookup.xlsx`, ghi đầy đủ URL nguồn, URL chuẩn hóa, URL đích, quyết định giữ/bỏ,
  HTTP status, số lần thử, redirect chain và lý do.
- Resolve mọi URL HTTP/HTTPS trong `See Also`, không giới hạn link rút gọn và không phụ thuộc giá trị `Risk`.
- Giữ URL trả HTTP 401/403 dưới trạng thái `access_restricted`, vì đây có thể là trang hợp lệ chặn client tự động.
- Loại URL đích trùng trong từng cell `References`, kể cả URL đã có sẵn và nhiều URL nguồn cùng trỏ tới một đích.

### Redirect và retry

- Cho phép tối đa 20 redirect và phát hiện redirect loop.
- Chỉ coi là `redirected_to_homepage` khi trang con quay về homepage cùng hostname; `www` được xem là tương
  đương, còn chuyển sang subdomain khác vẫn hợp lệ.
- Các lỗi tạm thời được retry tối đa ba lần sau lần đầu với delay 1/2/4 giây.
- `too_many_redirects`, `redirect_loop` và `redirected_to_homepage` không retry.
- URL rút gọn dạng `nessus.org/u?...` vẫn được chuẩn hóa qua Tenable; URL trực tiếp được kiểm tra tại chỗ.

### File Excel và khả năng tra cứu

- `References` nằm ngay sau `See Also`, mỗi URL một dòng.
- File lookup được tạo cho cả `report` và lệnh `merge` offline.
- Manifest và log có thêm số URL `access_restricted`, số URL resolved/bị bỏ và chi tiết cell lookup bị rút gọn.
- Bộ tách URL giữ đúng dấu ngoặc cân bằng trong đường dẫn, ví dụ `Manual:Ciphers(1)`.
- Các URL nguồn được chuẩn hóa trước khi đưa vào hàng đợi; tối đa 16 worker xử lý liên tục, log progress sau
  mỗi 25 URL hoàn thành.

### Tương thích và nâng cấp

- Không thay đổi cấu trúc `config.json` hoặc cú pháp selector scan/folder.
- File Excel riêng của từng scan vẫn giữ nguyên cột gốc và thêm `Group` ở cuối.
- `merged.xlsx` vẫn được tạo trước và không bị thay thế; kết quả resolve nằm trong file riêng
  `merged_resolved.xlsx`.
- Khi chạy mã nguồn, cần Python 3.10+ và các dependency trong `pyproject.toml`.

### Kiểm thử

- 94 tests passed trên Python 3.10.
- Đã kiểm tra build Windows portable bằng PyInstaller và chạy smoke test cho `--version`, `--help` và
  `help report`.
