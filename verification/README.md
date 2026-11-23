# Kiểm thử, demo và đánh giá

Toàn bộ dữ liệu mẫu và công cụ kiểm chứng nằm ở đây. Sản phẩm trong `../product/`
không phụ thuộc thư mục này. Các lệnh dưới đây chạy từ root repository.

## Thu log từ máy thật

Đọc [hướng dẫn lab chi tiết](../docs/REAL_MACHINE_LAB.md) trước khi chạy.
`lab/Invoke-LabScenario.ps1` tạo một Run Key marker và/hoặc chuỗi HTTP có giới hạn
trên endpoint lab. `lab/Export-LabLogs.ps1` giữ EVTX, xuất XML và SHA-256.
`lab/sysmon-lab.xml` là cấu hình thu dành riêng cho lab, không tự nạp lên máy hiện tại.

Sau khi chuyển bằng chứng về `logs/captures/<case>/`, chạy trong `verification/`:

```powershell
..\.venv\Scripts\python.exe -m scripts.validate_lab_capture logs/captures/combined-01
```

Validator dùng parser thật của sản phẩm để kiểm tra định dạng, host, thời gian và
dung lượng; chỉ đọc file, không upload hay gọi provider. Thu log máy thật vẫn là
một bước thực hiện riêng, không thay bằng fixtures hay kết quả unit test.

## Cài thư viện và chạy test

```powershell
uv pip install -r verification/requirements.txt
.\.venv\Scripts\python.exe -m pytest -c verification/pytest.ini -q
```

Hoặc chuyển vào `verification/` rồi chạy `..\.venv\Scripts\python.exe -m pytest -q`.
Pytest dùng SQLite tạm, chế độ offline và tắt worker; không sử dụng database sản phẩm.

## Đánh giá offline

```powershell
Set-Location verification
..\.venv\Scripts\python.exe -m scripts.evaluate --runs 3
```

Evaluation cũng tạo database tạm. Kết quả mặc định lưu tại `verification/artifacts/`,
không phụ thuộc thư mục hiện hành. `--output` tùy chỉnh được tính từ thư mục hiện hành.

## Demo và kiểm tra hệ thống đang chạy

Chỉ khởi động stack kiểm thử riêng dưới đây, không nạp dữ liệu vào sản phẩm. Các lệnh chạy trong `verification/`:

```powershell
docker compose --env-file ../product/.env up --build -d
..\.venv\Scripts\python.exe -m scripts.generate_demo
..\.venv\Scripts\python.exe -m scripts.seed_demo
..\.venv\Scripts\python.exe -m scripts.check_stack --result artifacts/demo-result.json
..\.venv\Scripts\python.exe -m scripts.check_ui
```

`seed_demo` ghi dataset và investigation mô phỏng vào API kiểm thử ở cổng 18000.
`check_stack` và `check_ui` cũng có thao tác cập nhật dữ liệu thử. Cả ba script đọc
`/health` và từ chối thao tác nếu API không có `environment: verification`.
Giao diện kiểm thử ở `http://localhost:18501`; sản phẩm ở `http://localhost:8501`.
Hai stack dùng project, network và volume PostgreSQL riêng, có thể chạy đồng thời.

File `--env-file ../product/.env` cung cấp cấu hình khi khởi động Compose; không copy
API key vào dữ liệu log. Test migration PostgreSQL chạy bằng
`python -m scripts.check_postgres_migration` với `DATABASE_URL` trỏ vào database kiểm tra;
script tạo và xóa schema tạm trong database đó.

Nếu chỉ muốn tự tay thử sản phẩm, không cần chạy các script trên. Làm theo
[hướng dẫn thao tác thủ công](../docs/MANUAL_PRODUCT_TEST.md).

## Provider thật

Kiểm tra luồng AI với log mô phỏng và SQLite tạm (chạy trong `verification/`):

```powershell
..\.venv\Scripts\python.exe -m scripts.check_ai_provider --scope sysmon --output artifacts/ai-sysmon.json
..\.venv\Scripts\python.exe -m scripts.check_ai_provider --scope combined --output artifacts/ai-combined.json
```

Lệnh này không gọi API sản phẩm và không dùng database sản phẩm, nhưng có phát sinh
lượt gọi provider thật. Nó chỉ thành công khi các agent và bản đề xuất đều hoàn tất.
`--trace-output artifacts/ai-responses.json` có thể lưu phản hồi thô khi cần chẩn đoán;
chế độ trace này chỉ áp dụng cho dữ liệu mô phỏng do script tự tạo.

`scripts.provider_smoke` và `scripts.evaluate --mode gemini`/`deepseek` sử dụng API key
từ `product/.env`, có phát sinh lượt gọi provider. Không chạy provider trong test offline.
Xem [phương pháp đánh giá](../docs/EVALUATION.md).

Log mẫu nằm trong `logs/samples/`, log tự thu trong `logs/captures/`, dữ liệu cũ trong `logs/archive/`; kết quả, database thử và bản backup cũ nằm trong
`artifacts/` và được bỏ qua khi commit. Helper test dùng chung nằm trong `tests/helpers.py`.
