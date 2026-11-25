# Tự kiểm thử Persistence và C2

Thư mục này chứa 61 bản ghi mô phỏng trong 15 tệp JSONL. Mỗi thư mục con là một ca độc lập. Tên tệp cho biết nguồn cần chọn khi nhập. Bảng dưới mô tả những gì người phân tích có thể xác minh trực tiếp từ log.

| Thư mục | Tín hiệu hoặc đối chứng | Kết quả chờ đợi với cấu hình mặc định |
|---|---|---|
| service-periodic | Ghi ImagePath, Event 3 và flow Zeek trùng tiến trình, địa chỉ, cổng và thời gian | Hai dấu vết, 8 liên kết có bằng chứng, ưu tiên cao |
| other-process | Ghi Run và có kết nối định kỳ từ một tiến trình khác | Hai dấu vết, chỉ có giả thuyết khi cung cấp ánh xạ máy–IP, ưu tiên trung bình |
| startup-file | Tạo tệp trong Startup sau sự kiện mở trình duyệt | Dấu hiệu Startup, trung bình. Cần xác minh nguồn tạo tệp |
| startup-cleanup | Xóa tệp trong Startup | Không có dấu vết tạo cấu hình |
| task-after-document | Mở trình xem tài liệu và sau đó ghi TaskCache | Dấu hiệu tác vụ định kỳ, trung bình. Quan hệ với tài liệu còn cần xác minh |
| task-cleanup | Xóa khóa tác vụ cũ | Thay đổi registry ở mức thông tin |
| service-change | Sửa đường dẫn chương trình của dịch vụ | Dấu hiệu cấu hình dịch vụ, trung bình |
| service-inventory | Kiểm kê một dịch vụ có tên config | Không có dấu vết tạo hoặc sửa dịch vụ |
| autorun-cleanup | Xóa giá trị Run | Thay đổi registry ở mức thông tin |
| dns-label | Một nhãn DNS dài giữa những truy vấn thông thường | Bất thường DNS, ưu tiên thấp |
| dns-multi-label | Tên DNS dài được ghép từ nhiều nhãn ngắn | Không có dấu vết nhãn DNS bất thường |
| short-series | Có 5 kết nối đều tới một đích | Chưa đủ mẫu để kết luận có chu kỳ theo luật mặc định |
| split-destinations | 8 kết nối phân bổ cho hai đích | Mỗi đích chỉ có 4 mẫu |

## Thử ca đầu tiên

1. Mở mục **Phân tích**. Nhập `service-periodic/sysmon.jsonl` với nguồn **Sysmon** rồi nhập `service-periodic/zeek_conn.jsonl` với nguồn **Zeek · Kết nối**.
2. Chỉ chọn hai tệp của ca đó. Chọn **Offline** rồi bấm **Phân tích log**. Có thể giữ nguyên phạm vi tự động cho ca này.
3. Trong **Nhận định**, kiểm tra dấu hiệu cấu hình dịch vụ và kết nối lặp lại. Mở **Bằng chứng → Liên kết Sysmon và Zeek** để đối chiếu dấu vết registry, Event 3 và flow mạng.
4. Đọc kế hoạch xử lý. Bước xác minh cần đề cập ImagePath và đích kết nối. Mở phần đối chiếu để kiểm tra từng mã bằng chứng và tiêu chí hoàn thành.
5. Tạo lượt mới để thử `other-process`. Để so với kết quả đánh giá tự động, dùng máy `WIN-LAB-01`, IP `192.0.2.10`, xác nhận ánh xạ và đặt cửa sổ **14/10/2026 08:00–09:00 UTC**. Kiểm tra việc thay đổi ProcessGuid làm giảm sức mạnh của liên kết.

Các ca chạy độc lập. Nếu đã nhập nhiều ca có tên tệp giống nhau, dùng tám ký tự đầu của dataset ID trong ô chọn để nhận diện. Chọn Gemini hoặc DeepSeek trên cùng phạm vi nếu muốn đối chiếu bản kế hoạch AI với hướng dẫn cục bộ.

## Chạy đánh giá

Từ thư mục `verification`, lệnh sau chạy 13 ca ở đây và 4 ca gốc do `scripts/scenarios.py` sinh ra. Mỗi ca đi qua API trong SQLite tạm, với ba chiến lược và ba lần lặp.

```powershell
..\.venv\Scripts\python.exe -m scripts.evaluate --runs 3 --output artifacts/evaluation-manual.json
```

Nhãn kỳ vọng và số dòng bằng chứng nằm trong [manifest.json](manifest.json). Để đánh giá một ca mới, ghi nhãn từ quan sát dự kiến trước khi chạy detector. Các ca sau khi mở tài liệu hay trình duyệt chỉ chứa dấu vết quan sát được trên máy. Hồ sơ không có bằng chứng về lỗ hổng hoặc cách khai thác ban đầu.
