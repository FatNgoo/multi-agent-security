# Tự chạy và kiểm thử sản phẩm từ trạng thái sạch

## 1. Vì sao build xong lại thấy log?

Build tạo image chứa mã ứng dụng; nó không xóa database. Trước đây các script demo và
kiểm tra giao diện đã nạp log mẫu qua API đang phục vụ sản phẩm. PostgreSQL lưu dữ liệu
trong volume nên khi bạn build lại, giao diện tiếp tục đọc các dataset, kết quả và cảnh
báo đó. Backend không tự tạo dataset khi khởi động.

Ngày 21/11/2026, dữ liệu cũ gồm 10 dataset, 46 event, 12 investigation và 10 cảnh báo đã
được lưu riêng. Sản phẩm hiện chuyển sang project/volume mới để bạn bắt đầu trống.
Không xóa hoặc nạp lại dữ liệu vào sản phẩm để kiểm chứng tự động sau bước tách này.

## 2. Ba môi trường dữ liệu tách biệt

| Môi trường | Compose project | API | Giao diện | Volume PostgreSQL |
|---|---|---|---|---|
| Sản phẩm bạn tự thao tác | `multi-agent-security-product` | `http://localhost:8000` | `http://localhost:8501` | `multi-agent-security-product_pgdata` |
| Demo/kiểm thử tự động | `multi-agent-security-verification` | `http://localhost:18000` | `http://localhost:18501` | `multi-agent-security-verification_pgdata` |
| Bản cũ lưu lại, đang dừng | `multi-agent-security` | Không phục vụ | Không phục vụ | `multi-agent-security_pgdata` |

API, frontend và database mới ở môi trường sản phẩm dùng cùng volume qua các lần build.
Sau khi bạn tự upload, lần build tiếp theo vẫn có dữ liệu đó; đây là việc lưu bền vững
bình thường. Nếu thật sự muốn một bộ dữ liệu trắng khác, tạo project name mới theo mục 9.

Không chạy lại project cũ ở cổng 8000/8501 cùng sản phẩm mới vì sẽ trùng cổng.

## 3. Các file log nằm ở đâu?

```text
product/                          # Code và cấu hình sản phẩm, không chứa log mẫu
verification/
  logs/
    samples/                      # Tệp mẫu, chỉ upload nếu bạn chủ động chọn
    captures/<case-id>/            # Log tự thu, metadata và report của ca
    archive/legacy-20261121T142944Z/
      database.dump               # Backup database đầy đủ
      dump-contents.txt            # Danh mục đọc được từ backup
      datasets.json               # Danh sách dataset cũ
      <UUID>.stored-events.jsonl   # Bản xuất event đã lưu trong DB
      archive-info.json           # Thống kê và thông tin lưu trữ
      sha256.json                 # Hash các file backup/xuất
  artifacts/                      # Kết quả test, evaluation và backup phát triển cũ
```

Các record xuất từ DB không thay cho EVTX/PCAP hay file log gốc nguyên byte. Với lần thu
mới, lưu file gốc vào `captures/` **trước khi upload**, kèm SHA-256 để kiểm chứng lại.
Khóa API chỉ nằm trong `product/.env`, không copy vào thư mục log hoặc gói bằng chứng.

## 4. Khởi chạy sản phẩm

Mở Docker Desktop, đợi engine sẵn sàng. Từ root repository trên PowerShell:

```powershell
Set-Location F:\TLCN_ATTT\Projects\multi-agent-security\product
docker compose config --quiet
docker compose up --build -d
docker compose ps
Invoke-RestMethod http://127.0.0.1:8000/health
```

Nếu là một bản clone mới và chưa có `.env`, dùng `Copy-Item .env.example .env`, đặt
`POSTGRES_PASSWORD` trước khi chạy. Giữ nguyên `.env` đã có; không chép mẫu đè API key.

Health phải có `status: healthy`, `environment: product`. Mở `http://localhost:8501`,
nhấn Ctrl+F5 để bỏ phiên giao diện cũ. Với database mới, **Tổng quan** hiển thị 0 bản ghi. Nút **Nhập log** mở màn hình xem trước. Mục **Theo dõi** cho xem lịch sử và cảnh báo.

Bạn có thể đọc trạng thái mà không ghi dữ liệu:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/datasets
Invoke-RestMethod http://127.0.0.1:8000/api/v1/investigations
Invoke-RestMethod http://127.0.0.1:8000/api/v1/metrics
```

Không chạy `seed_demo`, `check_stack`, `check_ui` để thử sự trống của sản phẩm. Các lệnh
đó phục vụ môi trường verification, có thể tạo/cập nhật dữ liệu trong môi trường đó.
Chúng đã được đổi mặc định sang cổng 18000 và từ chối API không mang nhãn verification.

## 5. Lần thử đầu: tự upload một file

Bạn có hai lựa chọn; thao tác upload hoàn toàn do bạn thực hiện:

- Log thật: làm theo [lab Windows–Linux chi tiết](REAL_MACHINE_LAB.md), copy bằng chứng
  về `verification/logs/captures/<case-id>/` và kiểm tra thời gian/host từ chính log.
- Tệp mẫu để làm quen giao diện: mở `verification/logs/samples/`. Những file này luôn
  nằm riêng trên ổ đĩa và không xuất hiện trong sản phẩm cho tới khi bạn upload.

Mở **Nhập log**, chọn các tệp, kiểm tra nguồn, số bản ghi và thời điểm ở bảng xem trước rồi bấm **Lưu**. Khi cần chỉ định nguồn thủ công, mở **Điều chỉnh nguồn**.

| File | Loại log cần chọn |
|---|---|
| Sysmon Event Viewer `*.xml` hoặc JSONL schema ứng dụng | Sysmon |
| Zeek `conn.log`/JSONL/TSV | Zeek · Kết nối |
| Zeek `dns.log`/JSONL/TSV | Zeek · DNS |
| Zeek `http.log`/JSONL/TSV | Zeek · HTTP |

Không upload `.evtx`, `.pcap`, `database.dump`, report hay `*.stored-events.jsonl` như
log đầu vào. Giữ các file này để lưu trữ/đối chiếu. Giới hạn mặc định mỗi file là
5.000.000 byte. Sysmon XML cần một `<Event>` hoặc `<Events>` hợp lệ; Zeek JSON cần
mỗi dòng một object, không phải mảng JSON.

Ghi lại tên tệp, số bản ghi và SHA-256. Giao diện dùng lại dataset khi nhập cùng nội dung và nguồn. API trực tiếp hỗ trợ tạo dataset riêng khi bỏ tùy chọn `reuse_existing`. Các tệp khác hash vẫn có thể chứa sự kiện trùng hoặc khoảng thu chồng lấn. [Cách đối chiếu với máy thật](DOI_CHIEU_LOG.md).

Sau upload, số tệp log tăng. **Cảnh báo và kết quả chưa tự xuất hiện**: bạn còn phải
bắt đầu một lượt phân tích. Điều này giúp bạn kiểm soát từng thao tác thử nghiệm.

## 6. Tự chạy phân tích

Vào **Phân tích** và chọn chính các file vừa nhập. Mặc định form lấy thời gian bao phủ
các file. Nếu cần giới hạn, mở **Phạm vi và tùy chọn**:

1. Host phải đúng tên trong Sysmon, kể cả FQDN nếu có.
2. IP phải là IP máy nguồn trong log, không phải IP server nhận heartbeat.
3. Thời gian trên form là UTC. Không copy khoảng thời gian demo cho log thu hôm khác.
4. Chỉ xác nhận mapping host–IP khi bạn biết chúng thuộc cùng máy trong khoảng đó.
5. Chọn Offline lần đầu để kiểm tra luồng mà không gọi API AI.
6. Bấm **Phân tích log**, đợi hoàn thành và lưu investigation UUID.

Tab **Nhận định** hiển thị dấu hiệu Persistence, C2, liên kết và toàn bộ biện pháp đề xuất. Trong **Bằng chứng**, đối chiếu thời gian, liên kết và log gốc. Trong **Báo cáo**, tải JSON hoặc Markdown.

Thông báo Offline có nghĩa là phân tích bằng luật/thống kê, không có LLM; log đầu vào
vẫn là log bạn tự upload. Không coi chưa có finding là chứng minh máy an toàn: kiểm tra
scope, nguồn log và cảnh báo thiếu/truncation trước.

### Nếu tự thử với bộ sample đi kèm

Nhập `synthetic-sysmon.jsonl` dưới source Sysmon và `synthetic-zeek_conn.jsonl` dưới
source Zeek · Kết nối. Chọn đúng hai dataset đó; host `WIN-LAB-01`, IP `192.0.2.10`,
khoảng `2026-10-14T08:00:00Z` → `2026-10-14T09:00:00Z`, xác nhận mapping cùng máy.
Đây là dữ liệu mô phỏng có nhãn. Dùng nó để học thao tác, không báo cáo như log thu từ
một vụ tấn công thật. Không cần upload sample nếu bạn muốn chỉ dùng log tự thu.

## 7. Tự so sánh AI

Sau khi Offline cho evidence đúng, tạo lượt mới với **cùng dataset và scope**, đổi mode
sang Gemini hoặc DeepSeek theo API key đã cấu hình. Chiến lược Heuristic luôn Offline;
giữ Multi-agent nếu muốn AI hỗ trợ các bước chuyên trách và đề xuất xử lý tổng hợp.

Mode provider có thể gửi dữ liệu log liên quan tới dịch vụ ngoài và phát sinh phí;
dùng dữ liệu lab được phép gửi. Trong kết quả, kiểm tra nguồn đề xuất là AI hay playbook
thay thế. Timeout, thiếu key, hết budget hoặc output không hợp lệ phải được ghi nhận
là giới hạn thử nghiệm, không đánh dấu AI đã thành công.

### Khi AI báo lỗi

Trong **Bằng chứng → Thông tin kỹ thuật & hoạt động AI**, mở từng agent để xem lỗi cụ thể:

| Mã | Ý nghĩa và bước kiểm tra |
|---|---|
| `timeout` | Model chưa trả lời kịp; kiểm tra thời gian chờ, mạng và trạng thái dịch vụ |
| `authentication` / `missing_key` | Kiểm tra key và quyền model trong `product/.env` |
| `model_not_found` | Đối chiếu đúng tên model và Base URL; không sửa log để xử lý lỗi này |
| `rate_limit` | Kiểm tra quota, hạn mức và giảm số lượt chạy đồng thời |
| `connection` / `provider_unavailable` | Kiểm tra mạng/proxy hoặc dịch vụ provider |
| `budget_exhausted` | Hết lượt gọi, token hoặc thời gian được cấp cho bước AI |
| `invalid_output` / `output_truncated` | JSON/tham chiếu chưa hợp lệ hoặc output bị cắt; không coi là AI thành công |

Giới hạn hiện dùng: 90 giây mỗi yêu cầu, 600 giây toàn lượt, tối đa một retry cho lỗi
tạm thời trong ngân sách tổng. Tập nhỏ thường cần một lượt gọi cho mỗi agent; tập nhiều
nguồn có thể mất vài phút. Nhãn “đang phân tích” trong thời gian này không tự chứng minh
ứng dụng bị treo. Nếu đổi `.env`, tạo lại riêng API bằng
`docker compose up -d --force-recreate --no-deps api` từ `product/`.

Kết quả lỗi cũ được giữ nguyên để đối chiếu. Sau khi cập nhật code/cấu hình, tạo lượt
phân tích mới trên chính dataset đã nhập; không cần upload lại cùng file.

## 8. Bộ kiểm tra thủ công ngắn

| Lượt | Bạn tự làm | Điều cần quan sát |
|---|---|---|
| A | Mở sản phẩm trước upload | Không có dataset/lịch sử/cảnh báo |
| B | Upload một tệp | Chỉ tăng dữ liệu đã nhập; chưa tự điều tra |
| C | Phân tích Offline | Hoàn thành, evidence thuộc đúng dataset/scope |
| D | Tự nhập sai source hoặc file không hợp lệ | Thông báo từ chối, không có dataset nhập dở |
| E | Chọn host/time không khớp | Kết quả thiếu/không có evidence được giải thích |
| F | Phân tích Gemini/DeepSeek trên dữ liệu được phép | Trạng thái AI và nguồn đề xuất minh bạch |
| G | Mở lại lịch sử, tải báo cáo | UUID, scope và dữ liệu nhất quán |
| H | Build lại sau khi tự upload | Dữ liệu của bạn còn nguyên, không tự sinh thêm log |

Với mỗi lượt, ghi input, giờ UTC, UUID và kết quả vào `notes.md` trong thư mục ca. Nếu
không khớp mong đợi, giữ log gốc và report để phân tích thay vì xóa database rồi thử lại.

## 9. Nếu muốn thêm một lần thử trắng hoàn toàn

Không cần xóa dữ liệu đã thử. Từ `product/`, dừng môi trường hiện tại để nhường cổng,
rồi chọn tên project mới **chưa từng dùng**:

```powershell
docker compose stop
docker compose -p multi-agent-security-manual-02 up --build -d
```

Project mới có volume riêng. Lần sau quản lý nó phải dùng đúng `-p` đó:

```powershell
docker compose -p multi-agent-security-manual-02 ps
docker compose -p multi-agent-security-manual-02 stop
docker compose up -d
```

Lệnh cuối trở lại project sản phẩm mặc định, với dữ liệu bạn đã lưu ở đó. Không bỏ
`-p` giữa chừng khi quản lý một project thử riêng. Không chạy `down -v` để có trạng thái
trắng: việc đó xóa volume của project được chọn.

## 10. Chạy công cụ verification khi bạn chủ động muốn

Môi trường này có cổng khác, nên có thể chạy cạnh sản phẩm:

```powershell
# Từ root repository
Set-Location verification
docker compose --env-file ../product/.env up --build -d
Invoke-RestMethod http://127.0.0.1:18000/health
# Chỉ chạy các lệnh sau nếu chính bạn muốn nạp demo vào môi trường kiểm thử
..\.venv\Scripts\python.exe -m scripts.seed_demo
..\.venv\Scripts\python.exe -m scripts.check_stack --result artifacts/demo-result.json
..\.venv\Scripts\python.exe -m scripts.check_ui
```

Health phải trả `environment: verification`; giao diện test ở `http://localhost:18501`.
Không đổi `--api-url` về cổng 8000: guard sẽ từ chối. Không copy volume verification
sang sản phẩm, vì làm vậy sẽ mang dữ liệu demo theo.

## 11. Lưu trữ và mở lại dữ liệu trước khi tách

Archive nằm tại `verification/logs/archive/legacy-20261121T142944Z/`. File dump đã được
đọc danh mục bằng `pg_restore --list`; số record xuất từng dataset được đối chiếu với
database. Giữ volume cũ `multi-agent-security_pgdata`; các container cũ đã được dừng.

Để xem dữ liệu cũ mà không đụng database sản phẩm mới, dừng project sản phẩm để nhường
cổng, rồi mở project cũ bằng tên rõ ràng:

```powershell
# Đang ở product/
docker compose stop
docker compose -p multi-agent-security start
```

Sau khi xem xong:

```powershell
docker compose -p multi-agent-security stop
docker compose up -d
```

Không dùng `up --build` để mở bản cũ theo hướng dẫn này; `start` dùng lại đúng container
đã dừng và volume cũ. Archive là bản sao bổ sung, không phải dữ liệu mặc định của sản phẩm.
