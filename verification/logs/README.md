# Log nằm riêng với sản phẩm

| Thư mục | Nội dung | Tự nạp khi build? |
|---|---|---|
| `samples/` | Log mẫu Sysmon/Zeek, có thể chọn upload thủ công | Không |
| `captures/` | Log do bạn thu trên máy thật, chia theo mã ca | Không |
| `archive/` | Database cũ và các bản ghi đã xuất để lưu trữ | Không |

Sản phẩm chỉ nhận log khi bạn upload trong giao diện. Docker build không copy hay đọc
thư mục này. Database chứa dữ liệu đã upload dùng volume riêng; giữ nguyên sau rebuild.

`captures/` và `archive/` không được commit. Giữ một bản backup riêng nếu cần lưu dài hạn.
`*.stored-events.jsonl` trong archive là bản xuất record database, **không phải file
upload gốc nguyên byte**. Để phục hồi đầy đủ dữ liệu cũ, dùng `database.dump` hoặc
volume cũ được giữ lại, theo [hướng dẫn tự kiểm thử](../../docs/MANUAL_PRODUCT_TEST.md).

Log mẫu không chứng minh chất lượng phát hiện trên dữ liệu thật. Xem
[lab máy thật](../../docs/REAL_MACHINE_LAB.md) để tự tạo hoạt động và thu bằng chứng.
