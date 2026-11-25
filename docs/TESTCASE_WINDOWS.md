# Kiểm thử log đã tải trong thư mục testcase

## Thử một EVTX trên giao diện

1. Mở [giao diện kiểm thử](http://localhost:18501) hoặc [sản phẩm](http://localhost:8501). Chọn **Nhập log → Chọn log từ máy**.
2. Thử tệp `testcase/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx`. Giữ **Tự nhận diện**. Bảng xem trước phải hiện **Sysmon · Endpoint**, **1 bản ghi** và SHA-256 của tệp.
3. Chọn **Lưu 1 tệp → Phân tích các tệp đã lưu → Offline → Phân tích log**. Trong **Bằng chứng**, mở bản ghi và so `provider`, `channel`, `event_record_id`, `time_created` và `event_data` với Event Viewer. Trường `xml` chứa XML giải mã của chính sự kiện.
4. Trong PowerShell ở thư mục gốc dự án, dùng Windows để kiểm độc lập.

```powershell
$sample = Resolve-Path '.\testcase\Persistence\evasion_persis_hidden_run_keyvalue_sysmon_13.evtx'
Get-FileHash -Algorithm SHA256 -LiteralPath $sample
Get-WinEvent -Path $sample -Oldest | Select-Object ProviderName, Id, RecordId, MachineName, TimeCreated
Get-WinEvent -Path $sample -Oldest | ForEach-Object { $_.ToXml() }
```

PowerShell mặc định hiển thị `TimeCreated` theo giờ máy. Để so trực tiếp với giao diện, đọc `System/TimeCreated/@SystemTime` trong XML. “Vị trí” đếm từ 1 trong tệp đã nhập. Windows có thể gán `RecordId` lớn hơn nhiều.

## Chọn đúng đầu vào

| Trong thư mục | Cách dùng |
|---|---|
| EVTX trong `Persistence/` và `Command and Control/` | Chọn trực tiếp, kể cả Security, BITS, Application Experience hoặc Terminal Services. Kênh ngoài Sysmon có thể tra bằng chứng và thời gian. Luật Persistence hiện dùng Sysmon |
| Năm tệp Windows JSON ở cấp đầu | Chọn nguyên tệp. Dòng Sysmon được nhận theo provider, các provider khác mang nguồn Windows Event Log. Ở tệp hỗn hợp, bảng xem trước hiện số bản ghi của mỗi nguồn |
| IIS `.log`, Apache access `.txt` | Chọn nguyên tệp. Có thời gian, IP máy khách, trạng thái HTTP và dòng gốc để đối chiếu |
| PCAP | Dùng log Zeek đã trích tại `verification/artifacts/testcase-zeek/conn.log` và `dns.log` trong lần kiểm tra này. Script bên dưới cũng tự đọc lại PCAP bằng Zeek ngoại tuyến |
| `readme.md` | Thuyết minh của bộ mẫu |

Có thể chọn đến 50 tệp một lượt lưu và đến 20 tệp trong một lượt phân tích. Để đánh giá theo ca, chọn một tệp hoặc các nguồn có cùng máy và cửa sổ thời gian. Hash trùng và cùng nguồn sẽ dùng lại dataset đã lưu. Kho sản phẩm và kho kiểm thử tách riêng.

## Kết quả chạy trên bộ tệp hiện có

| Đầu vào gốc | Số tệp | Bản ghi đã nhập trong kiểm thử |
|---|---:|---:|
| Windows EVTX | 28 | 2.380. Số bản ghi từng tệp khớp với `Get-WinEvent -Oldest` |
| Windows JSON OTRF | 5 | 43.573 |
| IIS và Apache access | 2 | 4.298 + 2.661 |
| PCAP | 1 | 110 kết nối và 130 bản ghi DNS do Zeek trích xuất |

Mỗi đầu vào đã qua xem trước, kiểm SHA-256 của tệp nhập, lưu vào PostgreSQL kiểm thử, truy lại bằng chứng qua API và chạy điều tra Offline. Tệp PCAP tạo hai dataset tương ứng hai log Zeek. Báo cáo JSON ghi tên tệp, số bản ghi nhập, số bản ghi thực sự được điều tra, số phát hiện và investigation ID. [Báo cáo theo từng tệp](../verification/artifacts/downloaded-logs.json)

Tệp `cmd_userinitmprlogonscript_batch_2020-10-1922471810.json` có 122 dòng. 108 sự kiện Sysmon có `UtcTime`. 14 dòng khác chỉ có `TimeCreated` thiếu múi giờ. Giao diện báo số dòng bỏ qua trước khi lưu. Với OTRF, ứng dụng ưu tiên `UtcTime`, tiếp theo là `TimeCreated` có múi giờ, rồi đến `@timestamp` của bộ thu. Các trường gốc được giữ để kiểm lại.

Tệp JSON lớn nhất có **80.321.735 byte**. Cả **40.569 bản ghi** được nhập. Lượt phân tích toàn khoảng đã xét **1.000 bản ghi** theo giới hạn cấu hình. Để kiểm tra một dấu vết cụ thể trong tệp lớn, thu hẹp giờ và host. Số phát hiện phản ánh luật và phạm vi đã chạy. Tên tệp mô tả kịch bản của tác giả.

## Chạy lại toàn bộ

Từ PowerShell ở thư mục gốc, với Docker và môi trường Python của dự án:

```powershell
uv pip install --python .\.venv\Scripts\python.exe -r product/requirements.txt -r verification/requirements.txt -r product/frontend/requirements.txt
docker compose --env-file product/.env -f verification/compose.yaml up -d --build
Invoke-RestMethod http://127.0.0.1:18000/health
```

Khi health trả về `environment = verification`, tạo bảng số lượng bằng bộ đọc gốc Windows rồi chạy kiểm thử. Script dùng ảnh `zeek/zeek:lts` để đọc PCAP với mạng container bị tắt.

```powershell
$counts = @{}
Get-ChildItem .\testcase -Recurse -Filter '*.evtx' | ForEach-Object {
    $counts[$_.Name] = @(Get-WinEvent -Path $_.FullName -Oldest -ErrorAction Stop).Count
}
$countFile = Join-Path $env:TEMP 'downloaded-evtx-native-counts.json'
$counts | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath $countFile
Push-Location verification
try {
    ..\.venv\Scripts\python.exe -m scripts.check_downloaded_logs --windows-counts $countFile
} finally { Pop-Location }
.\.venv\Scripts\python.exe -m pytest -q -c verification/pytest.ini
```

Hai nguồn bộ mẫu người dùng cung cấp là [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets/tree/master/datasets/atomic/windows/persistence/host) và [EVTX Attack Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).
