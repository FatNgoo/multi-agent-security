# Từ một kết nối trên máy thật đến bản ghi trên dashboard

Bạn có thể thử với một yêu cầu HTTP từ máy Windows đến một máy Linux do bạn quản lý. Một lần truy cập đủ để kiểm tra thu thập, nhập tệp và đối chiếu hai nguồn. Ghi lại IP thực của hai máy, giờ UTC và cổng sử dụng. Mỗi lượt thử dùng một thư mục mới.

| Nơi thu | Bản giữ để kiểm chứng | Tệp nhập vào ứng dụng | Dấu vết cần tìm |
|---|---|---|---|
| Windows có Sysmon | `sysmon-original.evtx` | `sysmon-001.xml` và các phần tiếp theo | Tên máy, kênh, EventRecordID, thời điểm, Event ID 3, tiến trình và hai đầu kết nối |
| Card mạng của máy Linux nhận HTTP | `traffic.pcap` | Zeek `conn.log`, có thể thêm `http.log` | Thời điểm bắt đầu, uid, IP/cổng hai đầu, giao thức. HTTP còn có method và URI |
| Ứng dụng | SHA-256 của từng tệp đầu vào | Bản ghi đã phân tích cú pháp trong database | Tên tệp, vị trí, thời gian UTC, trường gốc và evidence ID |

## 1. Tạo một kết nối dễ nhận ra

Windows cần Sysmon đang ghi kênh `Microsoft-Windows-Sysmon/Operational` và cấu hình thu **NetworkConnect (ID 3)**. Microsoft cho biết sự kiện này mặc định bị tắt. Nếu trên máy đã có cấu hình của người quản trị, hãy kiểm tra cấu hình hiện tại. Linux cần Python, tcpdump và Zeek. Có thể chạy Zeek bằng Docker theo mục 8 của hướng dẫn lab. [Sysmon của Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) · [Bố trí máy và công cụ](REAL_MACHINE_LAB.md)

Trên Linux, đặt IP theo mạng của bạn. Chạy khối sau trong cùng một terminal. Thư mục phục vụ HTTP rỗng để bạn dễ nhận biết đúng lần truy cập.

```bash
WIN_IP=192.168.56.10
LINUX_IP=192.168.56.20
LAB_IF=enp0s8
CASE_DIR="$HOME/log-check-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$CASE_DIR/web" "$CASE_DIR/zeek"
ip -brief address show "$LAB_IF"
date -u
python3 -m http.server 8008 --bind "$LINUX_IP" --directory "$CASE_DIR/web" > "$CASE_DIR/server.txt" 2>&1 &
SERVER_PID=$!
sudo tcpdump -ni "$LAB_IF" -s 0 -w "$CASE_DIR/traffic.pcap" "host $WIN_IP and tcp port 8008"
```

Chờ tcpdump báo đang lắng nghe. Trên Windows, mở PowerShell có quyền đọc kênh Sysmon. Giữ nguyên cửa sổ để dùng tiếp các biến.

```powershell
$labUrl = 'http://192.168.56.20:8008/'
$labCase = Join-Path $env:USERPROFILE ('log-check-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
New-Item -ItemType Directory -Path $labCase -ErrorAction Stop | Out-Null
$fromUtc = [DateTime]::UtcNow.AddSeconds(-2)
curl.exe --noproxy "*" --max-time 8 --silent --show-error --output NUL --write-out "%{http_code}" $labUrl
$toUtc = [DateTime]::UtcNow.AddSeconds(2)
$fromUtc.ToString('o')
$toUtc.ToString('o')
```

Kỳ vọng HTTP 200. Trên Linux, nhấn **Ctrl+C** trong terminal tcpdump sau khi Windows nhận phản hồi. Chạy `kill "$SERVER_PID"` trong cùng terminal để dừng đúng máy chủ thử vừa mở. Nếu kết nối lỗi, giữ kết quả riêng và ghi mã lỗi.

## 2. Xuất EVTX và XML từ cùng cửa sổ thời gian

Trong cửa sổ PowerShell ở bước 1, tạo manifest thời gian rồi chạy script thu log có sẵn trong repo. Thay đường dẫn script nếu bạn chép nó sang chỗ khác.

```powershell
@{
    case_id = Split-Path $labCase -Leaf
    start_utc = $fromUtc.ToString('o')
    end_utc = $toUtc.ToString('o')
} | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $labCase 'scenario.json')
& .\verification\lab\Export-LabLogs.ps1 -CaseDirectory $labCase
$sysmonDir = Join-Path $labCase 'sysmon'
Get-Content -LiteralPath (Join-Path $sysmonDir 'collection.json')
Get-ChildItem -LiteralPath $sysmonDir -Filter '*.xml' | Get-FileHash -Algorithm SHA256
```

Script đợi Sysmon ghi xong, giữ EVTX của cả khoảng, rồi xuất XML theo nhóm Event ID 1, 3, 11, 12, 13, 14, 22. Số sự kiện trong các phần XML phải cộng thành `event_count` trong `collection.json`. EVTX có thể chứa thêm các ID khác. Trên máy bận, cùng một giây có thể có nhiều sự kiện nền.

## 3. Tạo log Zeek từ PCAP vừa bắt

Trong terminal Linux ở bước 1, chạy Zeek đã cài sẵn. Chạy lệnh từ thư mục mới của ca để tệp đầu ra nằm cạnh nhau.

```bash
cd "$CASE_DIR/zeek"
zeek -C -r "$CASE_DIR/traffic.pcap" LogAscii::use_json=T
sha256sum "$CASE_DIR/traffic.pcap" ./*.log > "$CASE_DIR/linux-sha256.txt"
jq -c 'select(."id.resp_p" == 8008)' conn.log
tcpdump -nn -tt -r "$CASE_DIR/traffic.pcap" "tcp port 8008"
```

`conn.log` chứa một dòng JSON cho từng kết nối. Ví dụ về **hình dạng** dữ liệu rút gọn, dùng giá trị minh họa:

```json
{"ts":1795478400.123456,"uid":"CExample123","id.orig_h":"192.168.56.10","id.orig_p":51842,"id.resp_h":"192.168.56.20","id.resp_p":8008,"proto":"tcp","conn_state":"SF"}
```

Với ca của bạn, thay toàn bộ giá trị trên bằng kết quả `jq` thực đo. `ts` là giây Unix. Để xem thời gian gói đầu của kết nối, tìm bộ IP/cổng tương ứng trong kết quả tcpdump. Nếu Zeek tạo `http.log`, tìm cùng `uid` để xem `method` và `uri`. `uid` liên kết log trong cùng lượt chạy Zeek. Khi đọc lại PCAP ở lượt khác, hãy so IP/cổng, giao thức và thời gian. [Định nghĩa và ví dụ conn.log của Zeek](https://docs.zeek.org/en/current/reference/logs/conn.html)

### Một bản ghi công khai đã đối chiếu qua ứng dụng

Trong cơ sở dữ liệu kiểm thử riêng, dòng đầu của ví dụ `conn.log` do Zeek công bố cho kết quả dưới đây. Bạn có thể chép nguyên **một dòng JSON đầy đủ** từ mục *Inspecting the conn.log* để tự kiểm lại. [Bản ghi gốc do Zeek công bố](https://docs.zeek.org/en/current/reference/logs/conn.html#inspecting-the-conn-log)

| Kiểm tra | Kết quả đo được |
|---|---|
| Xem trước | Nhận diện `zeek_conn`, 1 bản ghi. Kho tệp vẫn trống đến khi bấm lưu |
| Giờ trên dashboard | `1591367999.305988` thành `2020-06-05 14:39:59.305988 UTC` |
| Tra trường gốc | `uid=CMdzit1AMNsmfAIiQc`, UDP từ `192.168.4.76:36844` đến `192.168.4.1:53`. Toàn bộ trường JSON đầu vào khớp khi đọc lại qua evidence ID |

## 4. Đối chiếu với sản phẩm

1. Chép XML và các log Zeek sang máy chạy sản phẩm. Mở **Nhập log**, chọn nhiều tệp cùng lúc. Kiểm số dòng, khoảng UTC, SHA-256 và nguồn ở bảng **Xem trước**. Với Zeek ASCII, giữ nguyên header `#path`, `#fields`, `#types`.
2. So SHA-256 hiển thị với `Get-FileHash` hoặc `sha256sum` của **chính tệp sẽ nhập**. XML, EVTX, PCAP và conn.log mỗi tệp có hash riêng. Chọn **Lưu**. Với cùng nội dung byte và nguồn, giao diện dùng lại dataset đã có.
3. Mở **Tổng quan**. Chọn nguồn và khoảng thời gian. “24 giờ cuối” tính từ sự kiện mới nhất của nguồn đã chọn, kể cả khi bạn mở lại log cũ. Tổng trên biểu đồ vòng bằng tổng các cột thời gian trong phạm vi. Các mức cảnh báo tính trên các lượt phân tích đã lưu.
4. Trong **Sự kiện gần nhất**, mở **Đối chiếu bản ghi gốc**. Với XML, “Vị trí” đếm phần tử Event từ 1. Với Zeek và JSONL, đó là số dòng vật lý từ 1, gồm cả header trước dòng dữ liệu. Bảng này hiển thị 12 sự kiện mới nhất. Nếu sự kiện nằm sâu hơn, chọn đúng tệp, giới hạn thời gian trong **Phân tích**, rồi xem tab **Bằng chứng**.
5. Với Sysmon, lấy `computer`, `channel` và `event_record_id` trong trường gốc của bản nhập XML mới. Kiểm lại Record ID trong EVTX bằng lệnh dưới. Nếu tệp XML gốc thiếu các trường này hoặc bản nhập có từ trước khi giao diện được cập nhật, tra theo thời điểm, tên máy, Event ID và các trường EventData.

```powershell
$record = Read-Host 'EventRecordID lấy từ giao diện'
$recordId = [long]$record
Get-WinEvent -Path (Join-Path $sysmonDir 'sysmon-original.evtx') -FilterXPath "*[System[EventRecordID=$recordId]]" |
    ForEach-Object { $_.ToXml() }
```

Từ ID 3, ghi lại `Image`, `ProcessGuid`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `Protocol` và `UtcTime`. Dùng `ProcessGuid` để tra tiến trình trong Sysmon. Qua Zeek, so hai đầu IP/cổng, giao thức và chênh lệch giữa thời điểm ID 3 với `ts`. Một bên ghi hoạt động của tiến trình, bên kia ghi gói mạng nên hai đồng hồ có thể lệch. Địa chỉ cũng có thể thay đổi nếu cảm biến nằm sau NAT. Ghi độ lệch thực tế và vị trí bắt.

Nếu chỉ thấy Zeek, kiểm tra Sysmon có bật ID 3 và có loại trừ tiến trình đang thử. Nếu chỉ thấy Sysmon, kiểm tra card mạng, bộ lọc capture và số gói tcpdump. Nếu đã thấy một cặp khớp, bạn đã kiểm tra được đường đi từ hành động thật đến dashboard. Một yêu cầu HTTP thông thường có thể kết thúc với **0 cảnh báo**.
