# Nghiên cứu và xây dựng hệ thống AI hỗ trợ phát hiện và điều tra chuỗi hành vi Persistence – Command and Control từ log Sysmon và Zeek

Ứng dụng nghiên cứu chạy local với FastAPI, Streamlit giao diện sáng, PostgreSQL/SQLite và LangGraph. Luồng chính gồm nhập log, chọn dữ liệu, phân tích, đối chiếu bằng chứng, đánh giá mức nguy hiểm và đề xuất xử lý.

## Cấu trúc thư mục

```text
product/                    # Sản phẩm, chạy độc lập
  app/                      # FastAPI: agents, ingestion, db, schemas, tools, services
  frontend/                 # Streamlit, CSS, cấu hình và Dockerfile frontend
  requirements.txt          # Thư viện backend
  Dockerfile                # Image backend, không chứa test hay fixtures
  compose.yaml              # PostgreSQL + API + frontend
  .env                      # Cấu hình và API key (không commit)
verification/               # Toàn bộ kiểm thử, demo và đánh giá
  tests/                    # Regression tests, helpers và database tạm
  scripts/                  # Tạo demo, evaluation, kiểm tra stack/UI/provider
  logs/                     # Log nằm riêng: samples/, captures/, archive/
  compose.yaml              # Stack kiểm thử riêng, cổng 18000/18501
  artifacts/                # Kết quả, log, database thử và backup (không commit)
  requirements.txt          # Thư viện sản phẩm + công cụ kiểm thử
  pytest.ini                # Đường dẫn import và cấu hình pytest
docs/                       # Tài liệu chung
```

Backend dùng entrypoint `app.main:app`. `product/` không import hay đọc dữ liệu từ
`verification/`; kiểm thử được phép import backend hoặc gọi API. Thư mục `.venv/`
ở gốc chỉ là môi trường Python phát triển dùng chung. Xem
[hướng dẫn kiểm thử](verification/README.md) để chạy demo và evaluation.

## Tự kiểm thử sản phẩm từ trạng thái sạch

Xem [hướng dẫn tự chạy, tự upload và tự kiểm thử](docs/MANUAL_PRODUCT_TEST.md).
Sản phẩm dùng database riêng, không tự nạp log mẫu. Log cũ được lưu trong
`verification/logs/archive/`; file mẫu và log tự thu nằm trong `verification/logs/`.
Build lại giữ dữ liệu bạn đã upload, không tự sinh dataset mới.

## Lab trên máy thật

Xem [hướng dẫn dựng lab Windows–Linux, thu Sysmon/PCAP/Zeek và phân tích log thật](docs/REAL_MACHINE_LAB.md).
Hướng dẫn gồm bố trí mạng, cài công cụ, kịch bản có kiểm soát, lưu bằng chứng gốc,
upload, đối chiếu kết quả, ca đối chứng và dọn lab. Script hỗ trợ nằm tại
`verification/lab/`; không nằm trong image sản phẩm và không tự chạy khi khởi động.

## Chạy với Docker Desktop

Từ root repository trên Windows PowerShell, chuyển vào `product/` và tạo `.env` từ mẫu nếu chưa có và cấu hình `POSTGRES_PASSWORD`. Giữ bản `.env` hiện có khi nâng cấp.

```powershell
Set-Location product
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

- Frontend tại http://localhost:8501
- OpenAPI tại http://localhost:8000/docs
- Health tại http://localhost:8000/health

API tự chạy migration additive khi khởi động. Dữ liệu PostgreSQL được lưu trong named volume `pgdata`. Sao lưu database trước khi nâng cấp instance có dữ liệu quan trọng. Lệnh `docker compose down -v` sẽ xóa volume.

Sản phẩm dùng project `multi-agent-security-product` và volume riêng. Stack demo dùng
`verification/compose.yaml`, API cổng 18000 và UI 18501, không dùng chung database.
Không chạy script nạp demo vào sản phẩm. Xem [hướng dẫn kiểm thử](verification/README.md).

## Chạy Python local

```powershell
uv venv .venv --python 3.12
uv pip install -r product/requirements.txt
uv pip install -r product/frontend/requirements.txt
Set-Location product
$env:DATABASE_URL = 'sqlite:///./local-dev.db'
$env:AGENT_MODE = 'offline'
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Mở PowerShell thứ hai tại root repository để chạy frontend với theme đúng đường dẫn.

```powershell
$env:API_BASE_URL = 'http://127.0.0.1:8000'
Set-Location product/frontend
..\..\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

SQLite phục vụ phát triển và tests. Compose cấu hình PostgreSQL cho stack container.

## Demo tổng hợp

Chỉ chạy phần này khi bạn chủ động muốn demo trong môi trường verification riêng. Khởi động stack kiểm thử rồi tạo fixtures và chạy một investigation offline qua background queue. Dữ liệu được tạo là mô phỏng có nhãn, sử dụng các dải IP dành cho tài liệu.

```powershell
# Từ root repository
Set-Location verification
docker compose --env-file ../product/.env up --build -d
..\.venv\Scripts\python.exe -m scripts.generate_demo
..\.venv\Scripts\python.exe -m scripts.seed_demo
```

Mở giao diện kiểm thử `http://localhost:18501`, vào **Theo dõi → Lịch sử phân tích**, chọn investigation vừa tạo rồi mở kết quả. Case có Run Key, Sysmon network events và Zeek connections định kỳ. Kết quả kỳ vọng có finding Persistence, periodic connections, supported correlations, mức triage High và alert có timing. Dữ liệu này dùng để kiểm tra logic và trình diễn.

Để nhập thủ công, mở **Nhập log**, kiểm tra nguồn và SHA-256 ở bảng xem trước rồi chọn **Lưu**.

| File | Source |
|---|---|
| `verification/logs/samples/synthetic-sysmon.jsonl` | `sysmon` |
| `verification/logs/samples/synthetic-zeek_conn.jsonl` hoặc `synthetic-conn.tsv` | `zeek_conn` |
| `verification/logs/samples/synthetic-zeek_dns.jsonl` | `zeek_dns` |
| `verification/logs/samples/synthetic-zeek_http.jsonl` | `zeek_http` |

Khoảng thời gian demo là `2026-10-14T08:00:00Z` đến `2026-10-14T09:00:00Z`. Trong form **Điều tra**, chọn datasets, nhập host `WIN-LAB-01`, IP `192.0.2.10` và bật xác nhận hai giá trị thuộc cùng thiết bị. Dùng bộ chọn ngày/giờ UTC để đặt khoảng thời gian. Khi có nhiều thiết bị hoặc IP thay đổi, có thể nhập mapping trong **Ngữ cảnh bổ sung** như sau.

```json
[
  {
    "host": "WIN-LAB-01",
    "ip": "192.0.2.10",
    "start_time": "2026-10-14T08:00:00Z",
    "end_time": "2026-10-14T09:00:00Z"
  }
]
```

## Chức năng hiện có

- Nhập trực tiếp EVTX và Windows JSON Lines OTRF (mặc định 100 MiB/tệp). Trường nguồn được xác định theo từng bản ghi. [Hướng dẫn kiểm thử thư mục testcase](docs/TESTCASE_WINDOWS.md).
- Sysmon Windows Event XML và JSONL schema đơn giản với `timestamp`, `host`, `event_id`, `description` cùng các trường bổ sung.
- Zeek `conn`, `dns`, `http` JSON Lines và TSV có `#fields`/`#types`, upload atomic tối đa 5 MB.
- Evidence UUID, raw fields/dòng JSONL hoặc TSV, SHA-256 file, record position, provenance và UTC.
- Query đa dataset, host/IP/time scope, pagination và coverage/truncation metadata.
- Shared tools cho events, process lineage, beacon statistics và ATT&CK retrieval.
- Source-aware Supervisor, Persistence/C2/Correlation stages, bounded provider tool calling và evidence verification.
- Severity/confidence riêng biệt, reason/limitations, conditional response playbook và analyst review audit.
- Alert thresholds, detection-to-alert-creation latency, acknowledgment và dashboard p50/p95.
- Database-backed jobs, cancellation, worker leases và xử lý job bị gián đoạn.
- UI nền sáng, diễn biến theo thời gian, bằng chứng, liên kết, hoạt động AI, báo cáo JSON/Markdown và lịch sử.
- Evaluation runner với heuristic/Single-Agent/Multi-Agent trên cùng dữ liệu mô phỏng.

## Không gian điều tra

Trang mặc định **Tổng quan** có biểu đồ phân bố theo nguồn, tần suất theo UTC, loại sự kiện phổ biến và bảng tra trường gốc. Cảnh báo tổng hợp từ các lượt phân tích. Bố cục sáng, thanh điều hướng ngang và nhóm chỉ số dựa trên [ảnh Overview của Wazuh](https://documentation.wazuh.com/current/_images/data-visualization1.png).

- **Nhập log** nhận nhiều tệp, nhận diện nguồn, xem trước khoảng thời gian và dùng lại tệp trùng. [Thu và đối chiếu một kết nối trên máy thật](docs/DOI_CHIEU_LOG.md).
- **Phân tích** cho phép chọn tệp và chạy Offline, Gemini hoặc DeepSeek. Máy, IP, thời gian và chiến lược nằm trong **Phạm vi và tùy chọn**.
- **Nhận định** hiển thị dấu hiệu trên máy, trên mạng, liên kết giữa hai nguồn và các bước xử lý. Tab **Bằng chứng** chứa log gốc, diễn biến theo thời gian và hoạt động AI. Tab **Báo cáo** cho tải Markdown hoặc JSON.
- **Theo dõi** cho mở lại lịch sử, xử lý cảnh báo, xem tệp đã nhập, thống kê và tra cứu ATT&CK.

Thử thủ công với [13 kịch bản có log và kết quả kỳ vọng](verification/logs/cases/README.md). Xem [đánh giá trước và sau khi sửa](docs/EVALUATION.md).

## Provider và budget

Màn hình investigation cho phép chọn `offline`, `gemini` hoặc `deepseek`. Key được cấu hình ở backend qua `product/.env`. `AGENT_MODE` là mặc định cho API caller không truyền mode. `strategy=heuristic` luôn dùng pipeline offline.

Sau khi kiểm chứng bằng chứng và đánh giá rủi ro, agent `response` tổng hợp một bản
đề xuất xử lý bằng tiếng Việt cho toàn bộ cuộc điều tra. Mỗi bước gồm hành động,
điều kiện áp dụng, cách kiểm tra kết quả và evidence IDs. Chế độ Gemini/DeepSeek dùng
provider hiện có; một lượt gọi trong ngân sách tổng được dành cho bước này, không tự
tăng giới hạn. Chế độ Offline gộp playbook thành một bản đề xuất và ghi rõ không gọi AI.
Nếu provider lỗi, hết ngân sách hoặc tham chiếu evidence không hợp lệ, hệ thống hiển thị
playbook thay thế cùng trạng thái thực tế. Kết quả lưu thêm `response_plan`; Markdown
xuất một bản đề xuất tổng hợp. Kết quả cũ vẫn đọc được nhưng cần chạy lượt mới để có bản AI.
Đề xuất chỉ được hiển thị và lưu báo cáo, không tự thực thi thay đổi máy/mạng.

Các cấu hình chính gồm `MAX_RECORDS`, `MAX_TOOL_CALLS`, `MAX_AGENT_ITERATIONS`, `LLM_TIMEOUT_SECONDS`, `MAX_LLM_CALLS`, `MAX_LLM_TOKENS`, `MAX_OUTPUT_TOKENS`, `INVESTIGATION_TIMEOUT_SECONDS`, `MAX_CONCURRENT_JOBS`, `ALERT_MIN_SEVERITY`, `ALERT_MIN_CONFIDENCE`, `BEACON_MIN_CONNECTIONS` và `BEACON_MAX_CV`.

Provider lỗi hoặc output sai evidence refs được ghi trạng thái trong `assessments`. Kết quả deterministic vẫn đi kèm cảnh báo về phần AI còn thiếu. Token budget dừng lượt gọi tiếp theo dựa trên usage provider báo về. Raw logs là dữ liệu untrusted. Chỉ gửi dữ liệu được phép tới provider.

Luồng provider hiện gửi bằng chứng đã truy xuất ngay trong yêu cầu đầu. Với tập evidence
nhỏ đã được cung cấp đủ, mỗi agent có thể kết luận trong một lượt gọi; tập lớn vẫn có
vòng gọi công cụ có giới hạn. Gemini dùng JSON Schema cho kết quả và mức reasoning
`low`; tham số tương thích được đối chiếu theo
[tài liệu Gemini](https://ai.google.dev/gemini-api/docs/openai). Schema và evidence IDs
vẫn được kiểm tra ở backend, không chấp nhận nhận định chỉ vì HTTP trả 200.

Cấu hình đề xuất hiện tại: `LLM_TIMEOUT_SECONDS=90`, `INVESTIGATION_TIMEOUT_SECONDS=600`,
`MAX_AGENT_ITERATIONS=2`, `MAX_OUTPUT_TOKENS=3000`, `LLM_MAX_RETRIES=1`,
`GEMINI_REASONING_EFFORT=low`. Mỗi lần thử lại đều tính vào `MAX_LLM_CALLS`; lỗi key/model
không được retry. Một lượt gọi và khoảng thời gian tương ứng được dành cho agent đề xuất.
Lỗi timeout, quota, kết nối, model, JSON và output bị cắt có `error_code`/`error_message`
riêng bằng tiếng Việt. Không tự đổi model hoặc API key.

Để chủ động kiểm tra AI thật bằng dữ liệu mô phỏng trong SQLite tạm, không ghi vào sản phẩm:

```powershell
# Từ root repository
Set-Location verification
..\.venv\Scripts\python.exe -m scripts.check_ai_provider --mode gemini --scope sysmon
# Ca đầy đủ nhiều nguồn (có thể mất vài phút)
..\.venv\Scripts\python.exe -m scripts.check_ai_provider --mode gemini --scope combined
```

Lệnh có gọi provider thật và phát sinh lượt dùng API. Kết quả mặc định lưu trong
`verification/artifacts/ai-provider-check.json`; mã thoát khác 0 nếu có agent chưa hoàn tất.

## API

| Endpoint | Chức năng |
|---|---|
| `POST /api/v1/logs/preview` | Kiểm tệp, nguồn, số bản ghi, thời gian và SHA-256 trước khi lưu |
| `POST /api/v1/logs/upload` | Multipart `file`, `source_type`, `reuse_existing`. UI bật dùng lại tệp cùng nội dung và nguồn |
| `GET /api/v1/overview` | Tổng hợp trên log đã nhập, lọc theo `source` và số giờ `hours` |
| `GET /api/v1/datasets` | Pagination `limit`, `offset`, header `X-Total-Count` |
| `GET /api/v1/events` | Dataset, host/IP, time, pagination và `X-Has-More` |
| `GET /api/v1/evidence/{id}` | Raw và normalized evidence |
| `POST /api/v1/investigations` | Tạo background job, HTTP 202 |
| `GET /api/v1/investigations` | Lịch sử |
| `GET /api/v1/investigations/{id}` | Trạng thái, tiến độ và kết quả |
| `POST /api/v1/investigations/{id}/cancel` | Yêu cầu hủy |
| `GET /api/v1/investigations/{id}/report` | JSON hoặc `format=markdown` |
| `PATCH /api/v1/investigations/{id}/findings/{finding_id}` | Analyst severity/recommendation review |
| `GET /api/v1/investigations/{id}/audit` | Lịch sử review |
| `GET/PATCH /api/v1/alerts[/{id}]` | Danh sách và cập nhật cảnh báo |
| `GET /api/v1/metrics` | Dashboard và phân phối latency |
| `GET /api/v1/knowledge` | ATT&CK lookup |
| `POST /api/v1/investigate` | Luồng synchronous tương thích caller v0.4 |

Request investigation nhận `dataset_ids` hoặc `dataset_id` cũ, `start_time`, `end_time`, tùy chọn `host`, `ip`, `host_mappings`, `benign_destinations`, `asset_criticality`, `strategy` và `mode`. Timestamp cần có timezone. Khi chọn datasets/time mà để trống host/IP, phạm vi gồm mọi host trong datasets đã chọn.

## Kiểm thử và evaluation

```powershell
# Từ root repository
Set-Location verification
..\.venv\Scripts\python.exe -m pytest -q
..\.venv\Scripts\python.exe -m scripts.evaluate --runs 3 --output artifacts/evaluation-offline.json
..\.venv\Scripts\python.exe -m scripts.check_ui
```

Tests dùng database tạm riêng. `scripts.check_ui` chỉ chấp nhận API verification ở cổng 18000 đang chạy cùng artifact từ `scripts.seed_demo`; có thể truyền `--result` để chọn artifact thuộc đúng database. Script tạo một cuộc điều tra mô phỏng mới rồi kiểm tra form, lọc bằng chứng, lưu đánh giá, đọc biện pháp tổng hợp, tiếp nhận cảnh báo và báo cáo; các cập nhật chỉ áp dụng cho cuộc mô phỏng mới này. Kết quả kiểm tra mặc định ở `verification/artifacts/ui-check.json`. AppTest kiểm tra chức năng, chưa thay thế việc kiểm tra hình ảnh desktop/mobile trên trình duyệt. Evaluation lưu nguồn dữ liệu, nhãn, per-run metrics và limitations. Xem `docs/EVALUATION.md` để chạy provider experiments và diễn giải kết quả.

## Giới hạn cần xét khi sử dụng

Rubric severity và detectors hiện là research heuristics có phiên bản. Critical severity cần analyst đánh giá tác động. Corpus ATT&CK là tập curated gồm năm techniques. Correlation dùng giới hạn clock skew hai giây, weak temporal window năm phút và cần review trong môi trường NAT/DHCP. Coverage có thể bị giới hạn theo budget.

Detection-to-alert latency kết thúc khi server tạo alert, trước transaction commit và UI polling. Provider narrative vẫn cần kiểm tra nội dung bằng chứng. Độ chính xác và false positives trên log thực tế cần ground truth và đánh giá bổ sung. Ứng dụng hiện hướng đến analyst local, bind loopback và dùng chung local analyst identity.

Xem `docs/ARCHITECTURE.md` cho schema, worker lifecycle, correlation và nguồn kiến thức. Hướng dẫn thiết kế giao diện nằm trong `DESIGN-red-team.md`.
