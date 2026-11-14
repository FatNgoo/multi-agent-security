# Nghiên cứu và xây dựng hệ thống AI hỗ trợ phát hiện và điều tra chuỗi hành vi Persistence – Command and Control từ log Sysmon và Zeek

Ứng dụng nghiên cứu chạy local với FastAPI, Streamlit Dark Crimson, PostgreSQL/SQLite và LangGraph. Luồng chính gồm upload, chuẩn hóa, chọn datasets/phạm vi, điều tra, đối chiếu evidence, đánh giá mức nguy hiểm, cảnh báo và đề xuất xử lý.

## Chạy với Docker Desktop

Từ root repository trên Windows PowerShell, tạo `.env` từ mẫu nếu chưa có và cấu hình `POSTGRES_PASSWORD`. Giữ bản `.env` hiện có khi nâng cấp.

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

- Frontend tại http://localhost:8501
- OpenAPI tại http://localhost:8000/docs
- Health tại http://localhost:8000/health

API tự chạy migration additive khi khởi động. Dữ liệu PostgreSQL được lưu trong named volume `pgdata`. Sao lưu database trước khi nâng cấp instance có dữ liệu quan trọng. Lệnh `docker compose down -v` sẽ xóa volume.

Để kiểm tra bằng stack tách biệt với database đang sử dụng, dùng project name riêng. Các cổng mặc định cần đang trống.

```powershell
docker compose -p multi-agent-security-verify up --build -d
```

## Chạy Python local

```powershell
uv venv .venv --python 3.12
uv pip install -r requirements.txt
uv pip install -r frontend/requirements.txt
$env:DATABASE_URL = 'sqlite:///./local-dev.db'
$env:AGENT_MODE = 'offline'
.\.venv\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000
```

Mở PowerShell thứ hai tại root repository để chạy frontend với theme đúng đường dẫn.

```powershell
$env:API_BASE_URL = 'http://127.0.0.1:8000'
Set-Location frontend
..\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

SQLite phục vụ phát triển và tests. Compose cấu hình PostgreSQL cho stack container.

## Demo tổng hợp

Sau khi API đang chạy, dùng các lệnh sau để tạo fixtures và chạy một investigation offline qua background queue. Dữ liệu được tạo là mô phỏng có nhãn, sử dụng các dải IP dành cho tài liệu.

```powershell
.\.venv\Scripts\python.exe -m scripts.generate_demo
.\.venv\Scripts\python.exe -m scripts.seed_demo
```

Mở **Lịch sử & báo cáo**, chọn investigation vừa tạo rồi mở kết quả. Case có Run Key, Sysmon network events và Zeek connections định kỳ. Kết quả kỳ vọng có finding Persistence, periodic connections, supported correlations, mức triage High và alert có timing. Dữ liệu này dùng để kiểm tra logic và trình diễn.

Để upload thủ công, dùng màn hình **Datasets** và chọn đúng source cho từng file.

| File | Source |
|---|---|
| `data/fixtures/synthetic-sysmon.jsonl` | `sysmon` |
| `data/fixtures/synthetic-zeek_conn.jsonl` hoặc `synthetic-conn.tsv` | `zeek_conn` |
| `data/fixtures/synthetic-zeek_dns.jsonl` | `zeek_dns` |
| `data/fixtures/synthetic-zeek_http.jsonl` | `zeek_http` |

Khoảng thời gian demo là `2026-10-14T08:00:00Z` đến `2026-10-14T09:00:00Z`. Khi chọn host `WIN-LAB-01`, thêm mapping sau trong form investigation.

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

- Sysmon Windows Event XML và JSONL schema đơn giản với `timestamp`, `host`, `event_id`, `description` cùng các trường bổ sung.
- Zeek `conn`, `dns`, `http` JSON Lines và TSV có `#fields`/`#types`, upload atomic tối đa 5 MB.
- Evidence UUID, raw fields/dòng JSONL hoặc TSV, SHA-256 file, record position, provenance và UTC.
- Query đa dataset, host/IP/time scope, pagination và coverage/truncation metadata.
- Shared tools cho events, process lineage, beacon statistics và ATT&CK retrieval.
- Source-aware Supervisor, Persistence/C2/Correlation stages, bounded provider tool calling và evidence verification.
- Severity/confidence riêng biệt, reason/limitations, conditional response playbook và analyst review audit.
- Alert thresholds, detection-to-alert-creation latency, acknowledgment và dashboard p50/p95.
- Database-backed jobs, cancellation, worker leases và xử lý job bị gián đoạn.
- UI Dark Crimson, timeline, evidence viewer, relationships, provider traces, JSON/Markdown reports và lịch sử.
- Evaluation runner với heuristic/Single-Agent/Multi-Agent trên cùng dữ liệu mô phỏng.

## Provider và budget

Màn hình investigation cho phép chọn `offline`, `gemini` hoặc `deepseek`. Key được cấu hình ở backend qua `.env`. `AGENT_MODE` là mặc định cho API caller không truyền mode. `strategy=heuristic` luôn dùng pipeline offline.

Các cấu hình chính gồm `MAX_RECORDS`, `MAX_TOOL_CALLS`, `MAX_AGENT_ITERATIONS`, `LLM_TIMEOUT_SECONDS`, `MAX_LLM_CALLS`, `MAX_LLM_TOKENS`, `MAX_OUTPUT_TOKENS`, `INVESTIGATION_TIMEOUT_SECONDS`, `MAX_CONCURRENT_JOBS`, `ALERT_MIN_SEVERITY`, `ALERT_MIN_CONFIDENCE`, `BEACON_MIN_CONNECTIONS` và `BEACON_MAX_CV`.

Provider lỗi hoặc output sai evidence refs được ghi trạng thái trong `assessments`. Kết quả deterministic vẫn đi kèm cảnh báo về phần AI còn thiếu. Token budget dừng lượt gọi tiếp theo dựa trên usage provider báo về. Raw logs là dữ liệu untrusted. Chỉ gửi dữ liệu được phép tới provider.

## API

| Endpoint | Chức năng |
|---|---|
| `POST /api/v1/logs/upload` | Multipart `file` và `source_type` |
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
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m evaluation.run --runs 3 --output artifacts/evaluation-offline.json
.\.venv\Scripts\python.exe -m scripts.check_ui
```

Tests dùng database tạm riêng. `scripts.check_ui` cần API đang chạy cùng artifact từ `scripts.seed_demo`. Evaluation lưu nguồn dữ liệu, nhãn, per-run metrics và limitations. Xem `docs/EVALUATION.md` để chạy provider experiments và diễn giải kết quả.

## Giới hạn cần xét khi sử dụng

Rubric severity và detectors hiện là research heuristics có phiên bản. Critical severity cần analyst đánh giá tác động. Corpus ATT&CK là tập curated gồm năm techniques. Correlation dùng giới hạn clock skew hai giây, weak temporal window năm phút và cần review trong môi trường NAT/DHCP. Coverage có thể bị giới hạn theo budget.

Detection-to-alert latency kết thúc khi server tạo alert, trước transaction commit và UI polling. Provider narrative vẫn cần kiểm tra nội dung bằng chứng. Độ chính xác và false positives trên log thực tế cần ground truth và đánh giá bổ sung. Ứng dụng hiện hướng đến analyst local, bind loopback và dùng chung local analyst identity.

Xem `docs/ARCHITECTURE.md` cho schema, worker lifecycle, correlation và nguồn kiến thức. Hướng dẫn thiết kế giao diện nằm trong `DESIGN-red-team.md`.
