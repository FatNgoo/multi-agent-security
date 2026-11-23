# Bộ công cụ lab máy thật

Đọc [hướng dẫn chi tiết](../../docs/REAL_MACHINE_LAB.md) từ bước bố trí máy tới lưu
báo cáo và dọn lab trước khi chạy các script.

| File | Chạy ở đâu | Tác dụng |
|---|---|---|
| `sysmon-lab.xml` | Windows lab | Cấu hình thu endpoint events; chỉ nạp khi bạn chủ động cài/cập nhật Sysmon |
| `Invoke-LabScenario.ps1` | Windows lab | Tạo marker autorun và/hoặc HTTP có giới hạn tới server IPv4 private |
| `Export-LabLogs.ps1` | Windows lab | Đọc cửa sổ ca, giữ EVTX, chia XML, ghi metadata và SHA-256 |

`Combined` và `PersistenceOnly` tạo value HKCU Run `SecurityLabMarker`. Script không
tự xóa value này để bạn quan sát; hướng dẫn có lệnh dọn chính xác. HTTP chỉ lấy file
heartbeat, không thực thi nội dung phản hồi. Mỗi ca có `scenario.json` và từ chối
ghi đè ca cũ.

Sau khi copy dữ liệu về máy phân tích, dùng `scripts.validate_lab_capture` từ thư mục
`verification/` để kiểm tra bằng parser sản phẩm. Bộ công cụ không tự cài hay thay cấu
hình máy khi build/chạy Docker của sản phẩm.
