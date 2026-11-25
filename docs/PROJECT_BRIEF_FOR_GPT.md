# HỒ SƠ DỰ ÁN CHO GPT VIẾT ĐỀ CƯƠNG CHI TIẾT TIỂU LUẬN

**Tên đề tài đang sử dụng:** Nghiên cứu và xây dựng hệ thống AI hỗ trợ phát hiện và điều tra chuỗi hành vi Persistence – Command and Control từ log Sysmon và Zeek.

**Tên gợi ý nếu cần làm rõ kiến trúc:** Nghiên cứu và xây dựng hệ thống AI đa tác tử hỗ trợ điều tra chuỗi hành vi Persistence – Command and Control dựa trên tương quan log Sysmon và Zeek.

**Ngày tổng hợp:** 23/11/2026, múi giờ Asia/Bangkok (UTC+7).

**Mục đích:** Một tài liệu độc lập để tải lên GPT, giúp GPT hiểu sản phẩm, cơ sở kỹ thuật, phương pháp thực nghiệm, kết quả đã có và khoảng trống cần bổ sung trước khi viết đề cương. Không cần có quyền truy cập repository để hiểu các thông tin chính trong file này.

**Nguồn căn cứ:** Mã nguồn hiện tại trong `product/`, mã kiểm thử trong `verification/`, README, tài liệu kiến trúc/đánh giá/lab, artifact thực nghiệm cục bộ. Đã chạy lại bộ test và đánh giá Offline trên mã hiện tại ngày 23/11/2026. Không gọi lại provider thật chỉ để lập tài liệu này.

**Phạm vi riêng tư:** Không chứa API key, mật khẩu database, nội dung `.env`, log người dùng đã tự upload, database dump hoặc thông tin định danh máy cá nhân. IP/host/path trong ví dụ dưới đây là dữ liệu lab hoặc fixture.

**Cập nhật ngày 24/11/2026.** Bản hiện hành dùng dashboard sáng với thanh điều hướng navy, phân bố nguồn log, ba ô dấu vết/liên kết và biểu đồ thời gian. Thư viện kiểm thử thêm 13 ca JSONL (61 bản ghi), nâng tổng số ca đánh giá lên 17. Các phần ghi số liệu ngày 21–23/11 bên dưới là mốc lịch sử.

Trên cùng 17 ca, số ca khớp tập luật và mức ưu tiên tăng từ 13 lên 17 sau khi sửa cách phân biệt tạo, xóa và truy vấn. Tập loại liên kết khớp 17/17 ở cả hai phiên bản. Lần chạy sau có 153 lượt Offline trên ba chiến lược, gồm ba lần lặp cho từng ca và chiến lược. Có 93 kiểm thử pytest đạt. Playbook có bước cô lập/khắc phục ở 2/17 ca sau sửa so với 11/17 trước đó. Tham chiếu trong các bước xử lý của 153 lượt đều trỏ tới bằng chứng trong phạm vi.

Agent ưu tiên bản ghi gắn với dấu vết và khóa liên kết khi giới hạn độ dài đầu vào. Agent đề xuất kiểm tra mã tham chiếu đối với bản ghi thực sự được trình bày. Trong ca DeepSeek dùng log mô phỏng, lần đầu agent đề xuất trả limitations dạng chuỗi và hệ thống dùng hướng dẫn cục bộ. Sau khi xử lý trường hợp một giới hạn đơn lẻ, lần thử tiếp theo DeepSeek hoàn tất cả bốn bước agent trong 27,8 giây, có bốn lượt gọi. Các phép đo này chưa chấm độ chính xác ngữ nghĩa của AI ngoài thực tế.

## 1. Quy ước để sử dụng tài liệu đúng

Các nội dung được phân biệt như sau:

- **Đã triển khai:** Đọc được cơ chế tương ứng trong mã nguồn hiện tại.
- **Đã kiểm chứng:** Có kết quả test/artifact được kiểm tra; không tự mở rộng kết luận ra ngoài điều kiện đo.
- **Cần thực nghiệm:** Có thiết kế hoặc hướng dẫn nhưng chưa đủ bằng chứng kết quả trong hồ sơ.
- **Đề xuất:** Gợi ý cho tiểu luận hoặc hướng phát triển; không phải chức năng đã có.

Nếu tài liệu lịch sử và mã hiện tại khác nhau, ưu tiên mã hiện tại và kết quả đo có ngày cụ thể. Không trộn kết quả của các thời điểm thành một phép đo chung.

Những diễn đạt phải tránh trong tiểu luận:

1. Không nói hệ thống đã chứng minh phát hiện chính xác 100% tấn công thực tế.
2. Không nói Multi-agent vượt Single-agent chỉ từ kết quả Offline.
3. Không gọi log mô phỏng là bằng chứng của một vụ xâm nhập thật.
4. Không gọi tương quan theo thời gian là quan hệ nhân quả.
5. Không nói LLM tự quyết định toàn bộ finding, mức nguy hiểm hoặc điều khiển máy đích.
6. Không nói đã huấn luyện/fine-tune mô hình, có vector database hoặc RAG ngữ nghĩa nếu không bổ sung triển khai tương ứng.
7. Không nói các agent của cùng investigation đang thực thi song song: graph hiện tại chủ yếu tuần tự, có rẽ nhánh.
8. Không coi mọi khả năng của LangGraph là khả năng dự án đã sử dụng.

## 2. Tóm tắt dự án trong một trang

Đây là ứng dụng nghiên cứu chạy local dành cho người phân tích an toàn thông tin. Người dùng tự đưa vào các file log Sysmon của Windows và log mạng Zeek, chọn dữ liệu, máy/IP và thời gian, rồi khởi tạo một investigation. Hệ thống chuẩn hóa sự kiện, truy vấn trong phạm vi đã chọn, tìm các dấu hiệu Persistence/C2 bằng luật và thống kê, đối chiếu bằng chứng endpoint–network, đánh giá mức ưu tiên điều tra và tổng hợp biện pháp xử lý.

Backend dùng Python/FastAPI, điều phối bằng LangGraph, lưu dữ liệu trong PostgreSQL khi chạy Docker hoặc SQLite khi phát triển/kiểm thử. Frontend là Streamlit nền sáng trắng–xanh. Gemini và DeepSeek được tích hợp qua SDK OpenAI-compatible; Offline không gọi LLM.

Kiến trúc có Supervisor, Persistence, C2, Correlation và Response advisor. Supervisor chọn luồng dựa trên nguồn log thực sự có trong phạm vi. Các agent dùng công cụ chỉ đọc, cùng chia sẻ ngân sách bản ghi, tool, lượt gọi mô hình, token và thời gian. LLM nhận bằng chứng có UUID, trả nhận định hoặc đề xuất có tham chiếu, và backend kiểm tra các ID trước khi chấp nhận.

**Phân công cốt lõi:** Luật/thống kê Python tạo finding và correlation; rubric Python xác định severity; LLM hỗ trợ diễn giải, nhận định và đề xuất. Vì vậy, đây là hệ thống kết hợp phân tích xác định với suy luận ngôn ngữ có kiểm chứng tham chiếu, không phải detector học máy được huấn luyện từ đầu.

Kết quả đầu ra gồm finding, evidence, liên kết, mức nguy hiểm, độ tin cậy, giới hạn kết luận, bản đề xuất tổng hợp, cảnh báo, timeline, hoạt động AI và báo cáo JSON/Markdown. Biện pháp chỉ được hiển thị cho người vận hành, không tự cô lập máy, chặn IP hoặc xóa cấu hình.

Tới thời điểm tổng hợp, có 78 test đạt; một đợt đánh giá Offline mới gồm 36 lượt trên bốn kịch bản đạt đối chiếu rule set/severity/relationship theo ground truth mô phỏng. Hai ca gọi Gemini thật trên log mô phỏng đã hoàn thành ngày 21/11/2026. Chưa có kết quả đủ để kết luận ưu thế khoa học của Multi-agent hoặc khả năng phát hiện trên môi trường vận hành thật.

## 3. Bài toán và động cơ nghiên cứu

### 3.1. Bài toán cụ thể

Một thay đổi cấu hình tự chạy trên Windows có thể là hành vi quản trị hợp lệ hoặc dấu hiệu Persistence. Một chuỗi kết nối đều đặn có thể là heartbeat hợp lệ hoặc một dấu hiệu cần điều tra về C2. Xem từng nguồn riêng rẽ dễ thiếu ngữ cảnh. Dự án tìm cách ghép bằng chứng của hai lớp quan sát:

- **Endpoint:** Tiến trình, registry, cấu hình tự chạy và kết nối do tiến trình tạo.
- **Network:** Luồng kết nối, chu kỳ truy cập, DNS và HTTP mà sensor nhìn thấy.

Đầu ra cần giải thích được: dấu hiệu nào được quan sát, dựa trên bản ghi nào, hai nguồn có nối được hay chỉ gần nhau theo thời gian, còn thiếu gì để kết luận, và bước xử lý tiếp theo là gì.

### 3.2. Khoảng trống mà dự án muốn khảo sát

Đây là **động cơ/giả thuyết thiết kế**, chưa phải kết luận từ tổng quan nghiên cứu có hệ thống:

- Thiếu ngữ cảnh khi chỉ dựa vào log endpoint hoặc chỉ log network.
- Nhận định bằng ngôn ngữ dễ đọc có thể thiếu khả năng truy ngược evidence.
- Kết quả AI có thể bịa tham chiếu, suy diễn từ tính chu kỳ hoặc gặp lỗi provider.
- Luồng điều tra nhiều bước cần giới hạn chi phí/thời gian và ghi nhận trạng thái không hoàn tất.
- Cần tách môi trường sản phẩm với dữ liệu demo để người dùng kiểm thử có kiểm soát.

Khi viết tổng quan, cần tìm tài liệu khoa học để kiểm chứng các khoảng trống này, không giả định mọi hệ thống khác đều thiếu các khả năng trên.

## 4. Mục tiêu, câu hỏi nghiên cứu và sản phẩm đầu ra

### 4.1. Mục tiêu tổng quát

Thiết kế và xây dựng một nguyên mẫu hỗ trợ người phân tích phát hiện dấu hiệu và điều tra mối liên hệ Persistence–C2 từ log đa nguồn, có thể truy ngược bằng chứng và nêu rõ độ không chắc chắn.

### 4.2. Mục tiêu cụ thể

1. Tiếp nhận và chuẩn hóa các định dạng Sysmon/Zeek đã hỗ trợ.
2. Lưu nguồn gốc dữ liệu, thời gian UTC, vị trí bản ghi và evidence UUID.
3. Xây dựng detector Persistence và các chỉ báo network cần điều tra.
4. Ghép endpoint–network bằng ProcessGuid, host, 5-tuple và thời gian.
5. Điều phối các tác tử chuyên trách với trạng thái chung và công cụ chỉ đọc.
6. Ràng buộc nhận định/đề xuất AI với evidence đã cung cấp.
7. Hiển thị kết quả, cảnh báo và hướng xử lý tổng hợp trên giao diện dễ quan sát.
8. Đánh giá chức năng, bằng chứng, độ trễ và giới hạn bằng kịch bản tái lập.

### 4.3. Câu hỏi nghiên cứu đề xuất

| Mã | Câu hỏi | Trạng thái bằng chứng |
|---|---|---|
| RQ1 | Chuẩn hóa và truy vấn đa nguồn có giữ được provenance và tránh rò phạm vi không? | Có test chức năng và một số artifact tích hợp |
| RQ2 | Khi nào có thể đối chiếu process–flow và khi nào chỉ nên đưa giả thuyết? | Có luật, ca combined/ambiguous và test |
| RQ3 | AI có tạo nhận định và đề xuất gắn với evidence hợp lệ được không? | Có test giả lập và hai ca Gemini thật trên dữ liệu mô phỏng |
| RQ4 | Multi-agent có giúp chất lượng nhận định tốt hơn một specialist tổng hợp không? | Chưa đủ dữ liệu; cần thí nghiệm provider có nhãn đánh giá ngữ nghĩa |
| RQ5 | Các giới hạn token, call, time và lỗi provider ảnh hưởng chất lượng/độ trễ thế nào? | Có cơ chế và test lỗi; chưa có benchmark quy mô lớn |
| RQ6 | Tính chu kỳ có bị hiểu nhầm thành C2 ở lưu lượng hợp lệ không? | Có ca benign; cần thêm dữ liệu thực tế và đo false positive |

### 4.4. Sản phẩm đã có

- Mã backend và giao diện, Dockerfiles và cấu hình Compose.
- Parser, normalizer, detector, correlation, risk rubric và playbook.
- Workflow có các agent, provider runtime và kiểm tra tham chiếu.
- API, hàng đợi investigation, database và báo cáo.
- Test suite, bộ sinh kịch bản, evaluation runner và script kiểm tra provider.
- Bộ công cụ lab Windows và hướng dẫn thu Sysmon/PCAP/Zeek.
- Tài liệu kiến trúc, hướng dẫn tự thao tác và tách dữ liệu/môi trường.

## 5. Đối tượng, phạm vi và ngoài phạm vi

| Nhóm | Phạm vi hiện tại |
|---|---|
| Đối tượng | Log Sysmon, Zeek conn/dns/http; hành vi tự chạy và hoạt động mạng có liên quan |
| Hệ điều hành endpoint chính | Windows có Sysmon |
| Dạng phân tích | Nhập file rồi điều tra trong khoảng thời gian; chưa phải luồng thu liên tục toàn doanh nghiệp |
| Người dùng | Analyst local, danh tính dùng chung, thao tác thủ công |
| Nhóm Persistence | Run Keys/Startup, Scheduled Task, Windows Service; một số thay đổi registry chung |
| Nhóm network | Chu kỳ kết nối từ conn.log; DNS label dài; HTTP/DNS làm ngữ cảnh |
| AI | Gemini/DeepSeek qua API; có Offline; không huấn luyện mô hình mới |
| Hành động xử lý | Đưa đề xuất và lưu đánh giá; không tự thực thi remediation |
| Kiến thức ATT&CK | Corpus nhỏ gồm 5 sub-technique, truy hồi từ khóa |

Ngoài phạm vi đã kiểm chứng: toàn bộ kỹ thuật Persistence/C2 của ATT&CK, giải mã TLS, điều tra memory/disk forensic đầy đủ, phân tích malware sandbox, EDR/XDR/SIEM thương mại, multi-tenant authentication/RBAC, vận hành phân tán lớn, khẳng định độ chính xác trên tấn công thực tế.

## 6. Công nghệ và môi trường

| Thành phần | Công nghệ | Vai trò thực tế |
|---|---|---|
| Backend | Python 3.12 trong Docker; FastAPI, Uvicorn | HTTP API và lifecycle worker |
| Validation | Pydantic, pydantic-settings | Schema, điều kiện dữ liệu và cấu hình |
| Orchestration | LangGraph | StateGraph với node/edge có điều kiện |
| Provider client | openai Python SDK | Gọi endpoint tương thích của Gemini/DeepSeek |
| Data layer | SQLAlchemy, psycopg | ORM/query và kết nối PostgreSQL |
| Database | PostgreSQL 16; SQLite | Docker runtime; local và test tạm |
| Frontend | Streamlit | Giao diện tương tác |
| Hiển thị dữ liệu | Pandas, Altair | Bảng, timeline, thống kê |
| XML | defusedxml | Đọc XML và từ chối DTD/entities |
| Test | Pytest, FastAPI TestClient, Streamlit AppTest | Unit/integration và kiểm thử tương tác |
| Deployment local | Docker Compose, uv | Đóng gói và cài dependencies |
| Lab | PowerShell, Sysmon, tcpdump, Zeek, Python HTTP server | Phát sinh/thu hành vi mô phỏng có kiểm soát |

Các dependency chính được khai báo bằng khoảng version, không phải toàn bộ đều khóa cứng. Image lấy `uv:latest` và image Zeek lab có thể dùng tag LTS, vì vậy cần ghi version/digest nếu muốn tái lập thí nghiệm nghiêm ngặt.

Phiên bản thư viện được ghi trong artifact evaluation ngày 23/11/2026: FastAPI 0.143.0, LangGraph 1.2.14, OpenAI SDK 2.54.0, SQLAlchemy 2.1.4, Pydantic 2.14.1. Đây là môi trường đã chạy phép đo Offline đó, không mặc nhiên đại diện mọi container/máy.

## 7. Cấu trúc repository và vai trò

```text
project/
├── product/
│   ├── app/
│   │   ├── main.py                    # FastAPI và endpoints
│   │   ├── config.py                  # Settings
│   │   ├── common.py                  # UTC và structured logging
│   │   ├── agents/
│   │   │   ├── supervisor_agent.py    # Chọn nhánh dựa trên source
│   │   │   ├── persistence_agent.py   # Điều tra Persistence
│   │   │   ├── c2_agent.py            # Network indicators
│   │   │   ├── correlation_agent.py   # Liên hệ các nguồn
│   │   │   ├── response_agent.py      # Bản đề xuất tổng hợp
│   │   │   ├── specialists.py         # Context và vòng tool/assessment
│   │   │   └── provider_runtime.py    # Retry, budget, JSON, diagnostics
│   │   ├── ingestion/                # Parser và normalizer
│   │   ├── db/                       # Models, connection, migration
│   │   ├── schemas/                  # Request/response/domain/state
│   │   ├── tools/                    # Truy vấn, thống kê, detector, ATT&CK
│   │   └── services/                 # Jobs, workflow, risk, báo cáo, playbook
│   ├── frontend/
│   │   ├── app.py                    # Các màn hình Streamlit
│   │   ├── style.css                 # Nền sáng, bố cục và typography
│   │   ├── .streamlit/config.toml    # Theme light
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── compose.yaml
│   └── .env.example                  # Chỉ mẫu, không phải key thật
├── verification/
│   ├── tests/                       # Tests và helpers
│   ├── scripts/                     # Demo, evaluation, provider/stack/UI checks
│   ├── lab/                         # PS scripts và Sysmon lab config
│   ├── logs/
│   │   ├── samples/                 # File mẫu, không tự nạp
│   │   ├── captures/                # File tự thu theo mã ca
│   │   └── archive/                 # Backup/exports cũ, không đưa cho GPT
│   ├── artifacts/                   # Kết quả test/evaluation, không đưa tất cả lên GPT
│   ├── compose.yaml                 # Môi trường test riêng
│   ├── requirements.txt
│   └── pytest.ini
├── docs/                            # Tài liệu hệ thống, lab, vận hành
├── README.md
└── DESIGN-red-team.md                # Tham chiếu giao diện tối lịch sử
```

Quy tắc phụ thuộc: `verification` được import hoặc gọi API của `product`; `product` không import test, không đọc fixture và không cần thư mục verification để build/chạy. `app/tools/` là công cụ của sản phẩm, không phải thư mục test.

## 8. Luồng xử lý tổng thể

```text
Người dùng tự upload file
  → Kiểm tra định dạng, kích thước và bản ghi
  → Chuẩn hóa + UUID evidence + hash file + metadata
  → Lưu dataset/events
  → Người dùng chọn scope và tạo investigation
  → Database queue/worker
  → Supervisor
  → Persistence nếu có Sysmon
  → C2 nếu có Zeek
  → Correlation nếu có cả endpoint và network
  → Verification tham chiếu + risk rubric
  → Response advisor / local fallback
  → Report, alert và lưu kết quả
  → Giao diện đối chiếu, analyst review, tải báo cáo
```

Trong mã `workflow.py`, nhánh thực thi chính là `START → supervisor → các node phù hợp → verification → response → report → END`. Nếu không có dữ liệu khớp scope, luồng đi thẳng tới kiểm chứng/báo cáo và nêu thiếu evidence.

Tạo request investigation nhận HTTP 202 và được xử lý nền. Frontend cập nhật tiến độ khoảng mỗi 2 giây. Ngoài ra còn endpoint đồng bộ cho caller/test tương thích.

## 9. Các agent và ý nghĩa “đa tác tử” trong dự án

| Agent/bước | Đầu vào | Việc thực hiện | Đầu ra |
|---|---|---|---|
| Supervisor | Events đã giới hạn scope | Xem nguồn có mặt, lập plan và chọn nhánh bằng Python | route, plan, trạng thái khởi tạo |
| Persistence | Sysmon và ngữ cảnh trong scope | Luật tự chạy, process lineage; gọi LLM khi strategy/mode phù hợp | findings Persistence, process_tree, assessment |
| C2 | Các nguồn Zeek và findings trước đó | Beacon statistics, DNS anomaly; nhận định AI khi phù hợp | findings network, assessment |
| Correlation | Events, findings, scope mapping | Ghép ProcessGuid/5-tuple/time; AI có thể nhận findings/relations/assessment trước | relationships và assessment |
| Verification/risk | Finding, relationship và known evidence IDs | Từ chối refs không tồn tại, áp dụng rubric | risk và detected_at |
| Response advisor | Finding đã kiểm chứng, risk, relationship, evidence giới hạn | Một bản đề xuất có cấu trúc bằng tiếng Việt hoặc local fallback | response_plan |
| Report | Toàn bộ kết quả | Gắn ATT&CK, tổng hợp và xuất báo cáo | JSON/Markdown và dữ liệu lưu DB |

Supervisor không phải LLM tự lập kế hoạch mở. Việc chia vai trò và truyền trạng thái là workflow được thiết kế trước. Trong một investigation, các node trên chủ yếu nối tuần tự; khả năng có hai job cùng chạy không có nghĩa các node trong một job chạy song song.

### 9.1. Các strategy

| Strategy | Ý nghĩa đúng theo triển khai |
|---|---|
| `heuristic` | Buộc mode Offline; dùng luật/thống kê và local playbook |
| `single_agent` | Dùng một specialist LLM tổng hợp ở nhánh phù hợp; nền detector/correlation vẫn dùng chung |
| `multi_agent` | Có specialist Persistence/C2/Correlation theo dữ liệu và điều kiện; cùng một provider/model được chọn |

**Lưu ý cho so sánh khoa học:** Trong provider mode, Response advisor là bước AI chung của cả `single_agent` và `multi_agent` khi có finding. Vì vậy tên “single_agent” không có nghĩa toàn pipeline chắc chắn chỉ có một lần gọi/một vai trò LLM. Đề cương cần định nghĩa baseline là “một specialist điều tra + bước Response chung” hoặc thiết kế thêm baseline thuần một agent và ghi rõ đó là thực nghiệm tương lai.

### 9.2. Các mode

- `offline`: Không gọi LLM nhưng vẫn phân tích chính log được upload.
- `gemini`: Gọi model Gemini do backend cấu hình.
- `deepseek`: Gọi model DeepSeek do backend cấu hình.
- Tên model thực nghiệm thành công trong artifact 21/11/2026 là `gemini-3.6-flash`; không lấy tên model mặc định trong mẫu cấu hình để thay cho model đã đo.

## 10. Dữ liệu vào, chuẩn hóa và provenance

### 10.1. Sysmon

- Nhận Windows Event XML có root `<Event>` hoặc `<Events>` và provider Sysmon.
- Nhận JSON/JSONL theo schema ứng dụng: tối thiểu timestamp có timezone, host, event_id, description.
- JSON của một công cụ export bất kỳ không tự động tương thích chỉ vì phần mở rộng là `.json`.
- Alias được quy về `process_guid`, `parent_process_guid`, `image`, `parent_image`, `command_line`, `target_object`, `details`, IP/cổng và protocol.
- Dữ liệu field tùy chọn sai kiểu cũng có thể làm upload bị từ chối để bảo đảm atomicity.
- XML dùng thời gian trong `System/TimeCreated`, giữ `EventData` thành cấu trúc raw.

EVTX được giải mã trực tiếp trên backend. Với Windows JSON OTRF, hệ thống nhận diện provider theo từng dòng và đếm riêng các dòng chỉ có giờ địa phương thiếu múi giờ. Windows Event Log ngoài Sysmon và IIS/Apache access có thể dùng để tra bằng chứng. [Phạm vi và kết quả kiểm thử trên bộ log tải về](TESTCASE_WINDOWS.md).

### 10.2. Zeek

- Nguồn: `zeek_conn`, `zeek_dns`, `zeek_http`.
- Nhận JSON Lines hoặc ASCII/TSV có header `#fields`, `#types` và các khai báo phân tách.
- Kiểm tra timestamp Unix hữu hạn, UID, địa chỉ IP, cổng, protocol và một số giá trị số không âm.
- Chuẩn hóa `id.orig_h`/`id.resp_h` thành source/destination IP và cổng tương ứng.
- Zeek không tự có hostname Windows; việc quy về host cần mapping phù hợp.

### 10.3. Provenance và bảo toàn

Mỗi dataset có filename, source, thời gian nhập, số record, SHA-256 của file upload và metadata phạm vi. Mỗi event có UUID, dataset_id, record_index, UTC timestamp, raw fields và normalized fields. Với JSONL/TSV, `_raw_line` giữ nội dung dòng; XML giữ raw có cấu trúc chứ không đảm bảo giữ nguyên mọi byte XML ban đầu.

Backend không lưu file upload nguyên bản thành một kho EVTX/PCAP. Muốn bảo toàn pháp chứng, người thực nghiệm phải giữ file gốc riêng ngoài database cùng hash. `*.stored-events.jsonl` xuất từ database là bản ghi đã lưu, không phải file upload gốc nguyên byte.

Giao diện dùng lại dataset khi cả SHA-256 và nguồn trùng khớp. API trực tiếp tạo dataset riêng nếu tắt `reuse_existing` và ghi `duplicate_of` khi tìm thấy bản trước. Khi đo, chọn một bản cho mỗi tệp.

## 11. Detector và cơ chế tương quan

### 11.1. Các luật Persistence

| Rule ID | Điều kiện tiêu biểu trong mã | Ánh xạ ứng viên |
|---|---|---|
| `run_key` | Sysmon ID 12/13/14 và target chứa CurrentVersion Run/RunOnce/RunOnceEx | T1547.001 |
| `startup` | Target có đường dẫn Start Menu/Programs/Startup | T1547.001 |
| `scheduled_task` | Target có TaskCache hoặc Event 1 chạy schtasks với `/create` | T1053.005 |
| `service` | ImagePath trong registry Services hoặc Event 1 có sc.exe create/config | T1543.003 |
| `registry_change` | Event 12/13/14 không khớp nhóm Persistence cụ thể trước đó | Không mặc định gán ATT&CK |

Đây là dấu hiệu cấu hình/hành vi cần điều tra, không phải xác nhận malware. Thao tác quản trị hợp lệ có thể tạo cùng sự kiện. Mã áp dụng các nhánh `if/elif`, không phải một mô hình phân loại học từ dữ liệu.

### 11.2. Tính chu kỳ kết nối

Chỉ lấy `zeek_conn`, nhóm theo `(source_ip, dest_ip, dest_port, protocol)`, rồi sắp xếp thời gian bắt đầu kết nối:

```text
Δi = t(i+1) − ti
μ = mean(Δi)
σ = population_standard_deviation(Δi)
CV = σ / μ, nếu μ > 0
periodic = (số kết nối ≥ 6) AND (CV ≤ 0,15)
```

Ngưỡng 6 và 0,15 là mặc định cấu hình, chưa phải giá trị tối ưu đã được chứng minh trên dataset thực tế. Có cả median interval, span và danh sách evidence. Source port không nằm trong khóa nhóm vì có thể thay đổi qua mỗi TCP connection.

Finding `periodic_connection` có confidence thấp, classification là `hypothesis` hoặc `benign_possible` nếu đích nằm trong ngữ cảnh hợp lệ do người dùng cung cấp. Có thể gán ứng viên T1071.001 nếu service là http/ssl/https. Tính đều chỉ là một chỉ báo; updater và monitoring cũng có chu kỳ.

### 11.3. DNS

Rule `long_dns_label` phát hiện ít nhất một label của query dài từ 40 ký tự, gán ứng viên T1071.004 và confidence thấp. Chưa có entropy model, DNS tunneling classifier hay chứng minh payload exfiltration.

### 11.4. Liên kết mạnh được hỗ trợ

Với mỗi finding Persistence không phải registry_change chung:

1. Lấy event neo của finding và ProcessGuid của process thực hiện thay đổi.
2. Tìm Sysmon Event 3 cùng host và cùng ProcessGuid.
3. Ghép Event 3 với Zeek conn bằng đủ 5-tuple: source IP, source port, destination IP, destination port, protocol.
4. Timestamp giữa Event 3 và Zeek flow lệch không quá 2 giây.

Nếu khớp, tạo `supported_correlation`, confidence high và refs tới event Persistence, Event 3, Zeek flow.

**Giới hạn quan trọng:** Đây là liên hệ giữa process sửa cấu hình và một flow của process đó. Chưa tự chứng minh chương trình được autorun target trỏ tới đã chạy và tạo flow; chưa chứng minh causality hay mục đích C2 độc hại. NAT, đồng hồ và semantics timestamp cần xem xét.

### 11.5. Liên kết yếu

Nếu không nối được process–flow nhưng có mapping host–IP hợp lệ tại thời điểm flow và khoảng cách với event neo không quá 300 giây, tạo `hypothesis`, confidence low. Không được mô tả dạng liên kết này như cùng một tiến trình đã được chứng minh.

## 12. Scope, coverage và giới hạn dữ liệu

Investigation nhận danh sách dataset UUID, thời gian có timezone, tùy chọn host/IP, mapping host–IP theo thời gian, benign destinations, asset criticality, strategy và mode. Tối đa 20 dataset, 100 mapping và 100 benign destination trong schema hiện tại.

Truy vấn luôn ràng buộc dataset và time range. Host lọc Sysmon host; Zeek được đưa vào theo IP/mapping phù hợp. IP đơn lẻ lọc source hoặc destination. Bỏ trống host/IP có nghĩa phân tích các máy trong những dataset và khoảng thời gian đã chọn, không tự suy ra một máy duy nhất.

Mặc định `MAX_RECORDS=1000` là ngân sách tổng chia tương đối đều cho số nguồn, mỗi nguồn lấy các record sớm nhất. Ví dụ bốn nguồn có mức giới hạn khoảng 250 record/nguồn. Không phải mỗi dataset đều được lấy trọn 1000 record.

Coverage ghi `matching_records`, `returned_records`, `truncated`, `record_limit`, `per_source_limit` và chính sách lấy mẫu. Relationships bị giới hạn 500. Context gửi LLM tiếp tục được cắt gọn: tối đa khoảng 25 phần tử mỗi list, chuỗi giới hạn độ dài và có ngưỡng kích thước payload.

**Hai tầng giới hạn cần phân biệt:** Có record trong file không đồng nghĩa record đó được detector đưa vào scope; có trong scope không đồng nghĩa toàn bộ nội dung được đưa tới LLM. Khi đánh giá phải ghi cả coverage của detector và giới hạn presentation cho model.

## 13. Severity, confidence, cảnh báo và đề xuất

### 13.1. Rubric `triage-1.0`

| Trường hợp | Mức ưu tiên mặc định |
|---|---|
| Không có finding | unknown |
| Thay đổi registry chung | informational |
| DNS label dài | low |
| Periodic traffic có ngữ cảnh benign | low |
| Persistence indicator hoặc network hypothesis chưa có liên hệ mạnh | medium |
| Liên hệ được hỗ trợ với network hypothesis theo điều kiện rubric | high |
| Tài sản quan trọng cao và một số Persistence indicator | Có thể nâng medium lên high |
| critical | Có thể qua analyst review; không tự khẳng định từ luật mặc định |

Risk tổng lấy mức cao nhất của các finding. Severity mô tả ưu tiên/tác động cần triage, confidence mô tả sức mạnh bằng chứng; không phải cùng một đại lượng, cũng không phải xác suất thống kê đã hiệu chuẩn.

### 13.2. Cảnh báo

Ngưỡng mặc định là severity từ medium và confidence từ low. Một investigation có tối đa một alert theo unique constraint. Chạy investigation khác tạo lịch sử mới. Analyst có thể tiếp nhận, chuyển đang xử lý, đóng và ghi note. Kết quả/alert có thể được cập nhật mức nguy hiểm sau review có audit.

### 13.3. Bản đề xuất tổng hợp

`response_plan` gồm summary, danh sách steps, limitations, source, provider và status. Mỗi bước có title, action, condition, verification và evidence_ids. Thường hướng tới xác minh, bảo toàn, cô lập/khắc phục có điều kiện và theo dõi/phục hồi.

Giao diện hiện toàn bộ các bước trong tab Nhận định, không bắt chọn từng biện pháp. Gemini dùng JSON Schema; DeepSeek dùng JSON mode. Backend kiểm tra cấu trúc và refs của từng step với evidence đã cung cấp. Nếu lỗi/mất budget/thiếu key thì ghi rõ dùng consolidated local playbook, không giả là AI đã thành công.

Tham chiếu tồn tại không bảo đảm nội dung câu diễn giải đúng về mặt ngữ nghĩa. Đề xuất vẫn cần chuyên viên xem xét. Bản đề xuất là snapshot khi investigation kết thúc; không tự gọi lại AI chỉ vì người dùng mở màn hình hoặc chỉnh severity sau đó.

## 14. Kiến thức ATT&CK và grounding

Corpus `curated-2026-11-12` có năm sub-technique:

| ID | Tên trong corpus | Vai trò |
|---|---|---|
| T1547.001 | Registry Run Keys / Startup Folder | Ngữ cảnh tự chạy |
| T1053.005 | Scheduled Task | Ngữ cảnh tác vụ |
| T1543.003 | Windows Service | Ngữ cảnh dịch vụ |
| T1071.001 | Web Protocols | Ứng viên ánh xạ hoạt động web |
| T1071.004 | DNS | Ứng viên ánh xạ DNS |

`lookup()` tách từ khóa, tính mức giao nhau với tên/mã/keywords và trả tối đa năm kết quả kèm link, version và mapping_status candidate. Đây là retrieval theo từ khóa trên corpus nhỏ, **không phải vector search/embedding RAG**. Có thể nghiên cứu mở rộng về sau nhưng phải ghi là hướng phát triển.

Các version technique/reviewed_at trong corpus là metadata cục bộ, không tự đồng bộ ATT&CK mới nhất. Cần kiểm tra lại nguồn khi viết trích dẫn học thuật.

## 15. Dữ liệu lưu trữ và cơ sở dữ liệu

| Bảng | Vai trò và các trường chính |
|---|---|
| `datasets` | id, filename, source, total_records, created_at, sha256, metadata_json |
| `events` | id/evidence UUID, dataset_id, record_index, timestamp, host, event_id, description, raw, normalized, IPs, process_guid |
| `investigations` | request, config_snapshot, result, status, progress, worker_id, lease_until, timestamps, error |
| `findings` | investigation_id và payload finding |
| `alerts` | investigation_id unique, severity, confidence, status, detected_at, created_at, acknowledgment, timing, history |
| `audit_entries` | investigation_id, action, details, created_at |
| `schema_migrations` | Version migration và thời gian áp dụng |

Dataset–Event, Investigation–Finding/Alert/Audit có khóa ngoại; tham chiếu evidence trong JSON không phải toàn bộ được mô hình hóa thành bảng quan hệ riêng. Investigation chứa danh sách dataset trong request JSON.

Migration additive `0002_multisource` bổ sung cột/index và chuẩn hóa record cũ, giữ UUID/raw. Có kiểm thử bảo toàn dữ liệu và tính idempotent. PostgreSQL dùng advisory lock cho migration. Không dùng framework migration lớn làm trọng tâm; logic migration nằm trong mã dự án.

## 16. API và hợp đồng đầu ra

| Nhóm | Endpoint chính |
|---|---|
| Health | `GET /health` |
| Nhập file | `POST /api/v1/logs/upload` với multipart file/source_type |
| Dataset | `GET /api/v1/datasets` |
| Sự kiện/evidence | `GET /api/v1/events`, `GET /api/v1/evidence/{id}` |
| Tạo job | `POST /api/v1/investigations` |
| Xem job | `GET /api/v1/investigations`, `GET /api/v1/investigations/{id}` |
| Hủy | `POST /api/v1/investigations/{id}/cancel` |
| Xuất | `GET /api/v1/investigations/{id}/report?format=json|markdown` |
| Review | `PATCH /api/v1/investigations/{id}/findings/{finding_id}` |
| Audit | `GET /api/v1/investigations/{id}/audit` |
| Alert | `GET /api/v1/alerts`, `PATCH /api/v1/alerts/{id}` |
| Metrics | `GET /api/v1/metrics` |
| Kiến thức | `GET /api/v1/knowledge` |
| Đồng bộ tương thích | `POST /api/v1/investigate` |

Request đại diện, với UUID phải thay bằng dataset thực sự đã upload:

```json
{
  "dataset_ids": ["00000000-0000-0000-0000-000000000001"],
  "host": "WIN-LAB-01",
  "ip": "192.0.2.10",
  "start_time": "2026-10-14T08:00:00Z",
  "end_time": "2026-10-14T09:00:00Z",
  "host_mappings": [{
    "host": "WIN-LAB-01", "ip": "192.0.2.10",
    "start_time": "2026-10-14T08:00:00Z", "end_time": "2026-10-14T09:00:00Z"
  }],
  "benign_destinations": [],
  "asset_criticality": "medium",
  "strategy": "multi_agent",
  "mode": "offline"
}
```

Result chứa scope, mode/strategy, evidence, findings, relationships, risk, assessments, response_plan, process_tree, coverage, warnings, timeline, tool_trace và timings. Trạng thái completed của investigation không mặc nhiên có nghĩa mọi assessment AI completed: phải đọc từng trạng thái.

## 17. Hàng đợi, đồng thời và giới hạn vận hành

Job được lưu trong DB, claim bằng cập nhật có điều kiện, có worker_id và lease. Worker thread pool mặc định tối đa hai job trên mỗi API process, quét/renew lease khoảng mỗi 0,5 giây. Lease hết hạn được đánh dấu lỗi bị gián đoạn. Checkpoint hỗ trợ hủy và deadline, ngăn worker bị hủy công bố kết quả.

Đây không phải triển khai message broker/Celery/RabbitMQ/Kafka hay cơ chế tự resume toàn bộ trạng thái LangGraph sau crash. Persistent job record và lease là cơ chế riêng của ứng dụng. Process restart/interrupted job có thể cần người dùng chạy lại.

| Cấu hình mặc định hiện tại | Giá trị |
|---|---:|
| MAX_UPLOAD_BYTES | 5.000.000 byte/file văn bản thông thường |
| MAX_WINDOWS_UPLOAD_BYTES | 100 MiB/file EVTX, JSON OTRF |
| MAX_RECORDS | 1000 |
| MAX_TOOL_CALLS | 16 |
| MAX_AGENT_ITERATIONS | 2 |
| LLM_TIMEOUT_SECONDS | 90 giây/yêu cầu |
| LLM_MAX_RETRIES | 1 |
| GEMINI_REASONING_EFFORT | low |
| MAX_LLM_CALLS | 9 |
| MAX_LLM_TOKENS | 30.000 |
| MAX_OUTPUT_TOKENS | 3000 |
| INVESTIGATION_TIMEOUT_SECONDS | 600 giây |
| MAX_CONCURRENT_JOBS | 2/process |
| MAX_PENDING_JOBS | 100 |
| LEASE_SECONDS | 60 |
| BEACON_MIN_CONNECTIONS | 6 |
| BEACON_MAX_CV | 0,15 |

Settings có thể bị ghi đè; cần lưu config của từng thí nghiệm. Một call và thời gian cho Response được chừa trong ngân sách. Mỗi retry tính là một call. SDK retry mặc định bị tắt để không cộng lượt retry ẩn; ứng dụng tự retry lỗi tạm thời có giới hạn và backoff ngắn.

Timeout/network/429/5xx có thể retry; key sai, thiếu model hoặc tham số 400 không retry mù. Kết quả rỗng, bị cắt, sai schema hoặc refs không hợp lệ được ghi lỗi. Có mã lỗi riêng như timeout, authentication, model_not_found, rate_limit, invalid_output, output_truncated, budget_exhausted.

**Token budget là giới hạn dừng theo usage quan sát trước call tiếp theo, không phải hard cap tiền phí:** Một call đang chạy có thể làm tổng vượt ngưỡng khi usage được trả về. Không có bộ tính hóa đơn hay bộ dự báo token chính xác trước mỗi request. Chỉ tính thinking token khi provider phản ánh chúng trong usage/total; phần không được provider báo không đo được đầy đủ.

## 18. Giao diện và trải nghiệm người dùng

Giao diện cập nhật ngày 24/11/2026 có bốn mục **Tổng quan**, **Nhập log**, **Phân tích** và **Theo dõi**.

- **Tổng quan** hiển thị biểu đồ nguồn, tần suất sự kiện, loại sự kiện, mức cảnh báo và trường gốc của 12 bản ghi gần nhất. Khoảng thời gian của log dựa trên mốc sự kiện mới nhất của nguồn đang chọn.
- **Nhập log** nhận diện nguồn, kiểm tệp, hiển thị số bản ghi, khoảng UTC và SHA-256. Khi bấm lưu, giao diện dùng lại tệp đã có cùng nội dung và nguồn.
- **Phân tích** nhận các tệp người dùng chọn. Phạm vi mặc định bao phủ thời gian của các tệp đã chọn. Người dùng có thể mở tùy chọn máy, IP, thời gian và chiến lược.
- Kết quả có ba tab. **Nhận định** hiển thị dấu hiệu duy trì truy cập, liên lạc C2, mức liên kết giữa hai nguồn và biện pháp đề xuất. **Bằng chứng** cho xem log gốc, diễn biến và chi tiết AI. **Báo cáo** cho tải kết quả.
- **Theo dõi** tập hợp lịch sử, cảnh báo, tệp đã nhập, thống kê và tra cứu ATT&CK.
- Có giải thích tiếng Việt cho các rule phổ biến, raw evidence và JSON kỹ thuật vẫn giữ để đối chiếu.
- Có analyst review severity, alert acknowledgment và audit; API còn hỗ trợ cập nhật trạng thái recommendation, nhưng UI hiện không yêu cầu chọn từng recommendation để đọc đề xuất.
- Lỗi timestamp trộn giây nguyên/phần lẻ đã được sửa bằng đọc ISO8601 và kiểm thử timezone/sắp xếp.

Không cần mô tả giao diện tối Dark Crimson như bản hiện hành; đó là thiết kế lịch sử đã được thay theo yêu cầu người dùng.

## 19. An toàn, độ tin cậy và ranh giới tin cậy

Các biện pháp đã triển khai:

- Bind API/frontend ở loopback trong Compose.
- Key ở backend, không nhập vào log hoặc đưa lên frontend.
- Tool chỉ đọc và ràng buộc scope, không cho model tùy ý thay dataset scope.
- Cắt gọn context và không đưa nguyên mọi raw record vào model.
- System prompt coi log là dữ liệu không đáng tin cậy và bỏ qua chỉ dẫn bên trong log.
- Kiểm tra schema và membership của evidence IDs.
- XML chống DTD/entities, upload giới hạn kích thước và nhập atomic.
- Audit cho review, điều kiện vận hành trong đề xuất containment/remediation.
- Tách môi trường product/verification và guard script chống vô tình seed vào product.

Giới hạn an toàn phải nêu:

- Prompt nhắc bỏ qua chỉ dẫn không chứng minh chống prompt injection tuyệt đối.
- Refs hợp lệ không chứng minh câu nhận định đúng ngữ nghĩa.
- Hash hỗ trợ đối chiếu file; chưa có hệ thống ký số/WORM/chain-of-custody pháp lý đầy đủ.
- Chưa có authentication/RBAC/tenant isolation hoàn chỉnh; chưa phù hợp mở public như dịch vụ production nhiều người dùng.
- Chưa có kiểm chứng tự động mức ảnh hưởng của hành động xử lý lên dịch vụ thật.

## 20. Thiết kế evaluation hiện có

### 20.1. Bốn kịch bản sinh bằng Python

| Kịch bản | Dữ liệu/điều chỉnh | Kỳ vọng |
|---|---|---|
| combined | 10 Sysmon events gồm process, Run Key và 8 Event 3; 8 conn, 1 DNS, 1 HTTP | run_key + periodic_connection, high, supported_correlation |
| ambiguous | Bỏ Event 3, vẫn giữ Run Key và flow | Hai rule, medium, chỉ hypothesis theo mapping/time |
| benign | Giữ process thông thường, bỏ Run Key; periodic flow có benign destination | periodic_connection, low, không có Persistence relationship |
| negative | Không Run Key, tăng jitter các flow | Không rule trong tập kiểm tra, severity unknown |

Host fixture `WIN-LAB-01`, IP nguồn `192.0.2.10`, đích `198.51.100.20`; tám flow cách 60 giây trong ca chuẩn. Mốc bắt đầu fixture là 14/10/2026 08:00 UTC. DNS/HTTP fixture chỉ là dữ liệu mô phỏng hỗ trợ, không phải trace PCAP chân thực của một phiên TLS đã giải mã; không suy diễn từ chúng thành kết quả phân tích payload thật.

### 20.2. Ba strategy và protocol

Evaluation runner upload cùng cấu trúc kịch bản qua public API TestClient vào SQLite tạm. Mỗi ca chạy heuristic/single_agent/multi_agent, mặc định ba lần. Tổng `4 × 3 × 3 = 36` lượt. Scope, ground truth, rule substrate và budget được giữ tương ứng giữa các strategy.

Trong mode Offline, cả ba strategy đều không gọi AI. Do đó kết quả ngang nhau là kiểm chứng tính nhất quán của nền logic, không phải thí nghiệm so sánh chất lượng LLM.

### 20.3. Metric và ý nghĩa

| Metric | Cách tính/đơn vị hiện tại | Giới hạn |
|---|---|---|
| Finding precision/recall/F1 | Tập rule_id phân biệt dự đoán so với tập rule_id kỳ vọng của scenario | Không phải tỷ lệ nhận diện malware/process/incident ở dữ liệu vận hành |
| Rule-set exact match | Tập rule dự đoán đúng hoàn toàn | Chỉ trên các ca được thiết kế |
| Evidence validity | Tỷ lệ ref resolve tới evidence trong scope | Không chấm nội dung ngữ nghĩa |
| Evidence completeness | Ref thu hồi trong tập source/record_index được gán là relevant | Phụ thuộc nhãn scenario do người thiết kế đặt |
| Severity agreement | Mức risk bằng mức nhãn ca | Đo đồng thuận rubric, không phải xác suất rủi ro chuẩn |
| Relationship agreement | Có/không loại relationship kỳ vọng | Chưa là benchmark mọi liên kết trong thế giới thật |
| Runtime | Thời gian job xử lý | Phụ thuộc máy, DB, provider và scope |
| LLM calls/tokens/status | Số attempt và usage được báo | Chưa suy ra chi phí tiền nếu không có giá/usage đầy đủ |
| Unsupported-claim rate | Hiện để null | Cần analyst gán nhãn các claim riêng |

Nếu không có dự đoán/mẫu số, một số metric là null; không tự đổi null thành 0 hoặc 1. Với ca âm, false positive cụ thể nên được tính rõ theo thiết kế mới nếu mở rộng, không lấy recall null làm “đạt 100%”.

## 21. Kết quả đã kiểm chứng và có thể đưa vào tiểu luận

### 21.1. Bộ test hiện tại

Ngày 23/11/2026 đã chạy lại:

```powershell
# Từ root repository, dùng môi trường đã cài dependencies verification
.\.venv\Scripts\python.exe -m pytest -c verification/pytest.ini -q
```

**Kết quả: 78 passed trong 19,31 giây.** Thời gian test là quan sát của lần chạy này, không phải latency phân tích log.

Phạm vi test: upload/API; XML đơn event và nhiều event; từ chối XML/fields sai; JSONL/TSV; scope/timezone/pagination; network correlation và benign context; worker/claim/cancel/lease; migration; timeline precision/timezone; AI refs/schema/fallback; retry/budget/time reservation; quota/model/auth diagnostics và không lộ body có secret; tách target verification.

Trong suite có mock provider và AppTest. Số test đạt không có nghĩa 78 vụ tấn công thật đã được phát hiện.

### 21.2. Evaluation Offline mới ngày 23/11/2026

Artifact: `verification/artifacts/evaluation-handoff-20261123.json`.

| Chỉ số toàn đợt | Kết quả |
|---|---:|
| Số lượt evaluation | 36 |
| Rule-set khớp | 36/36 |
| Severity khớp | 36/36 |
| Relationship khớp | 36/36 |
| Median runtime của 36 lượt | 73,0585 ms |
| LLM calls | 0 |

Chi tiết theo ca (mỗi ca có 9 lượt do 3 strategy × 3 lần):

| Ca | Finding/risk | Precision, recall, F1 của các rule | Evidence validity/completeness | Median runtime |
|---|---|---|---|---:|
| combined | run_key + periodic_connection; high | 1,0 / 1,0 / 1,0 | 1,0 / 1,0 | 76,480 ms |
| ambiguous | run_key + periodic_connection; medium | 1,0 / 1,0 / 1,0 | 1,0 / 1,0 | 73,681 ms |
| benign | periodic_connection; low | 1,0 / 1,0 / 1,0 | 1,0 / 1,0 | 68,163 ms |
| negative | không rule; unknown | null / null / null | null / null | 67,791 ms |

Chi tiết theo strategy trong mode Offline:

| Strategy | Lượt | Median runtime | LLM calls |
|---|---:|---:|---:|
| heuristic | 12 | 73,8655 ms | 0 |
| single_agent | 12 | 74,6480 ms | 0 |
| multi_agent | 12 | 71,1490 ms | 0 |

Sai khác thời gian vài ms trong mẫu nhỏ này không chứng minh strategy nào nhanh hơn hay tốt hơn. Không gộp với artifact cũ có median khác để tạo kết quả “tốt nhất” chọn lọc.

### 21.3. Gọi Gemini thật trên log mô phỏng

Các ca dưới đây là artifact thành công ngày 21/11/2026, được đọc lại khi tổng hợp; **không gọi lại provider ngày 23/11 chỉ để viết file này**.

| Thuộc tính | Ca Sysmon-only | Ca combined Sysmon/Zeek |
|---|---|---|
| Model ghi trong artifact | gemini-3.6-flash | gemini-3.6-flash |
| Strategy | multi_agent | multi_agent |
| Record trong scope | 10 | 20 |
| Findings | 1 | 2 |
| Risk | medium | high |
| Agent hoàn tất | Persistence, Response | Persistence, C2, Correlation, Response |
| LLM calls | 2 | 4 |
| Tổng runtime | 102.391,304 ms ≈ 102,39 s | 198.452,244 ms ≈ 198,45 s |
| Detection-to-alert | 52.132,588 ms | 35.953,508 ms |
| Usage prompt/completion trong artifact | 4094 / 1361 | 31.100 / 3528 |
| Nguồn response_plan | ai | ai |
| Artifact | ai-fix-sysmon-schema.json | ai-fix-combined.json |

Mỗi cột chỉ là một ca thành công, chưa phải phân phối thống kê hay đánh giá nội dung bởi nhiều chuyên gia. Ca combined đã có tổng usage vượt 30.000; điều này phù hợp với việc kiểm tra budget trước request kế tiếp, không phải hard cap chặn request đang chạy. Không dùng hai ca này để kết luận độ chính xác ngữ nghĩa hoặc hiệu quả chi phí.

Có các artifact provider lỗi cũ do timeout/JSON/404 ở thời điểm khác. Chúng là dữ liệu chẩn đoán, không được tính thành công. Chưa có bằng chứng live DeepSeek thành công tương đương trong hồ sơ này.

### 21.4. Kiểm tra tích hợp và UI đã có

- Artifact PostgreSQL stack: upload, background execution, UTC, 20 evidence resolve, report, metrics, acknowledgment và audit.
- Artifact lịch sử `ui-response-plan.json` kiểm tra giao diện trước ngày 24/11/2026: sáu màn hình và bốn tab, scope validation, navigation, filtering, đề xuất tổng hợp không selector, review, audit và downloads đạt AppTest.
- Có ghi nhận quan sát nền sáng trong Edge khi sửa giao diện; chưa có đánh giá usability với người dùng hoặc kiểm tra hình ảnh tự động toàn diện mọi thiết bị.
- Dữ liệu từng phép thử dùng stack/DB tương ứng; không coi số record demo trong một stack là dữ liệu thực chiến.

## 22. Ý nghĩa đúng của thời gian đo

`detected_at` được ghi ở bước verification/risk, sau các specialist. `alert_created_at` được ghi khi xây dựng alert trong server. Hiệu giữa hai mốc là `detection_to_alert_ms`.

Khoảng này:

- Không gồm toàn bộ thời gian từ sự kiện gốc tới detector.
- Không gồm toàn bộ thời gian specialist AI trước verification.
- Có thể gồm thời gian Response advisor và báo cáo sau verification, trước tạo alert.
- Không gồm commit DB hoàn tất, polling frontend và hiển thị trình duyệt.

Vì vậy không gọi nó là “thời gian phát hiện tấn công end-to-end” hay “thời gian cảnh báo xuất hiện trên trình duyệt”. Khi nói hiệu năng cần tách event-time, ingest-time, processing runtime, detection-to-alert creation và presentation latency.

Dashboard tính p50/p95 theo nearest-rank trên tối đa 1000 investigation completed gần nhất và ghi sample policy. Không lấy median test suite thay cho median runtime; không trộn Offline ms với provider hàng chục/hàng trăm giây thành một nhóm không chú thích.

## 23. Kịch bản máy thật: đã chuẩn bị và phần cần làm

### 23.1. Topology đề xuất đã có hướng dẫn

| Máy | Vai trò | Địa chỉ ví dụ |
|---|---|---|
| W | Windows endpoint, Sysmon, chạy hành vi lab | 192.168.56.10/24 |
| L | Linux HTTP server, tcpdump, Zeek offline | 192.168.56.20/24 |
| A | Chạy sản phẩm để upload/điều tra; có thể dùng máy riêng | Localhost trên máy A |

Linux là đích của HTTP nên capture trực tiếp lưu lượng tới mình, không giả định một máy thứ ba trên switch tự thấy mọi unicast. Đồng bộ đồng hồ trước ca, không dùng NAT làm thay đổi tuple mà không ghi nhận.

### 23.2. Các file công cụ

- `lab/sysmon-lab.xml`: Bật các nhóm process, network, file, registry, DNS cho endpoint lab; schema config 4.82 là mẫu, không khẳng định Sysmon binary đã cài ở mọi máy.
- `Invoke-LabScenario.ps1`: Combined/PersistenceOnly/PeriodicOnly/Jitter, IP private, default 12 kết nối cách 15 giây, có manifest UTC/PID/status; từ chối ghi đè ca cũ.
- `Export-LabLogs.ps1`: Đọc cửa sổ ca, giữ EVTX, xuất các ID 1/3/11/12/13/14/22, chia XML dưới khoảng 4 MB, metadata và SHA-256.
- `scripts.validate_lab_capture`: Dùng parser sản phẩm đọc XML/Zeek, kiểm tra kích thước, host, số record và cửa sổ; không upload/gọi AI.

### 23.3. Hành vi kiểm soát

Ca Combined ghi đúng một value HKCU Run `SecurityLabMarker`, chỉ để ghi marker lúc đăng nhập lại. Cùng process PowerShell mở các HTTP connection riêng tới server lab, lấy file heartbeat. Không có malware, shell điều khiển từ xa hay payload thực thi từ phản hồi.

Dùng cùng process để phù hợp điều kiện ProcessGuid của correlation. Nếu reg.exe ghi registry còn curl.exe mở network, GUID khác nhau và có thể chỉ tạo hypothesis. Thử đăng nhập để kiểm chứng autorun target execution là một lượt riêng, không tự chứng minh bởi ca ghi cấu hình + HTTP ban đầu.

### 23.4. Quy trình thu–lưu–phân tích

1. Chuẩn bị mạng, quyền, công cụ và time sync.
2. Bật/kiểm tra Sysmon, đặc biệt Event 3.
3. Khởi động HTTP server file thử trên Linux.
4. Bắt PCAP đúng interface và filter lab trước khi chạy scenario.
5. Chạy một mã ca duy nhất trên Windows, ghi manifest và lỗi request.
6. Dừng capture đúng cách; ghi packet drop.
7. Sinh Zeek JSON từ PCAP bằng image/version được ghi nhận.
8. Export Sysmon EVTX/XML trong đúng cửa sổ UTC.
9. Hash và giữ bản gốc; copy vào `verification/logs/captures/<case>/`.
10. Validate, tự upload XML/conn/http/dns đúng source.
11. Phân tích Offline trước, đối chiếu raw evidence và expected outcomes.
12. Chạy provider trên cùng dữ liệu được phép gửi; lưu report/UUID và note.
13. Dọn đúng Run value và service/rule lab đã tạo, không xóa toàn bộ log hoặc volume.

### 23.5. Ma trận ca đề xuất

| Ca | Nội dung | Điều nên quan sát |
|---|---|---|
| P | PersistenceOnly | Có thay đổi autorun, không tự kết luận C2 |
| N | PeriodicOnly | Có chu kỳ, không tự kết luận Persistence |
| PN | Combined | Hai dấu hiệu; khả năng nối mạnh khi đủ GUID/tuple/time |
| J | Jitter | Có HTTP thật nhưng có thể không đạt periodic threshold |
| B | Periodic hợp lệ với benign context | Có thể hạ ưu tiên, không thay raw log |
| M | Bỏ một nguồn khỏi investigation | Nêu thiếu evidence, không bịa nguồn còn lại |
| T | Scope/time/mapping sai có chủ đích | Phân biệt lỗi cấu hình với lỗi detector |

**Trạng thái:** Đã có công cụ/hướng dẫn. Trong `captures/` được kiểm tra khi lập hồ sơ chưa thấy bộ PCAP/EVTX cùng report thực nghiệm hoàn chỉnh. Không viết rằng lab máy thật đã thành công chỉ từ việc script tồn tại; cần người dùng thực hiện và cung cấp bằng chứng đo. Dùng cụm “log thật của hành vi mô phỏng có kiểm soát” khi lab được chạy, không gọi đó là “log của tấn công thực tế”.

## 24. Chạy hệ thống và tách sản phẩm với kiểm thử

| Môi trường | Project | API/UI | Dữ liệu |
|---|---|---|---|
| Product | multi-agent-security-product | 8000 / 8501 | Người dùng tự upload |
| Verification | multi-agent-security-verification | 18000 / 18501 | Demo và test khi được chủ động chạy |
| Unit/evaluation | SQLite tạm | TestClient nội bộ | Synthetic, không ghi vào product |
| Legacy | multi-agent-security đã dừng khi tách | Không phục vụ mặc định | Volume cũ và archive giữ lại |

Chạy sản phẩm từ thư mục gốc:

```powershell
Set-Location product
# Chỉ tạo .env từ mẫu nếu chưa có; không ghi đè key hiện có
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

Tạo database mới không tự nạp log. Build lại không xóa dữ liệu đã upload: volume còn dữ liệu thì giao diện vẫn có log. Đây là persistence của database, không phải build sinh dữ liệu.

Nếu chủ động chạy demo/test stack, từ thư mục gốc mở terminal khác:

```powershell
Set-Location verification
docker compose --env-file ../product/.env up --build -d
..\.venv\Scripts\python.exe -m scripts.seed_demo
..\.venv\Scripts\python.exe -m scripts.check_stack --result artifacts/demo-result.json
..\.venv\Scripts\python.exe -m scripts.check_ui
```

Các script seed/stack/UI này mặc định cổng 18000 và từ chối API không trả `environment: verification`. Không chạy chúng vào product chỉ để thử UI trống. Test/evaluation Offline dùng DB tạm; việc viết tài liệu này không tạo investigation trong product.

Lệnh đánh giá tái lập mà không gọi provider:

```powershell
# Trong verification/
..\.venv\Scripts\python.exe -m scripts.evaluate --runs 3 --output artifacts/evaluation-new.json
```

Lệnh kiểm tra provider thật, có phát sinh lượt dùng API nhưng vẫn DB tạm:

```powershell
..\.venv\Scripts\python.exe -m scripts.check_ai_provider --mode gemini --scope sysmon
..\.venv\Scripts\python.exe -m scripts.check_ai_provider --mode gemini --scope combined
```

Không đưa `.env`, dump hoặc log nhạy cảm lên GPT. Tránh `docker compose down -v` nếu chưa chủ động muốn xóa volume và có backup phù hợp.

## 25. Các vấn đề đã gặp và cách xử lý

| Vấn đề | Nguyên nhân thực tế/quan sát | Cách xử lý và ý nghĩa |
|---|---|---|
| API restart sau đổi cấu hình | Mật khẩu DB không khớp volume cũ | Đồng bộ credentials, giữ dữ liệu; thay biến init DB không tự đổi password đã có |
| Build thấy log sẵn | Volume giữ demo từ các lần kiểm tra | Archive và tách product/verification; không seed lúc startup |
| Giao diện tối, nhiều điều khiển | Thiết kế cũ quá dày | Nền sáng, ba bước chính, bốn tab, chi tiết mở rộng |
| Pandas lỗi timestamp | Trộn ISO giây nguyên/phần lẻ/timezone | Dùng ISO8601 + UTC và sort theo thời gian parse; có regression test |
| Gemini timeout | Deadline request 20 s quá thấp với phản hồi thực tế | Context đầu vào có sẵn, giảm call thừa, 90 s/request và 600 s/job, retry giới hạn |
| AI trả prose kèm JSON | Prompt không bảo đảm wire format | Gemini JSON Schema; validate schema/refs, JSON mode cho DeepSeek |
| Limitation sai kiểu/JSON rỗng/cắt | Output không đáp ứng hợp đồng | Diagnostics, không chấp nhận im lặng; fallback ghi rõ |
| Người dùng phải chọn từng biện pháp | Playbook UI cũ hiển thị từng mục | Response advisor và một bản kế hoạch đầy đủ |

Các tình huống này có thể đưa vào phần thảo luận độ tin cậy/kỹ thuật triển khai. Không dùng sửa lỗi kỹ thuật như bằng chứng nghiên cứu rằng detector thông minh hơn hệ thống khác.

## 26. Giới hạn và nguy cơ đe dọa tính hợp lệ nghiên cứu

1. **Construct validity:** Rule-set match không đo trực tiếp chất lượng điều tra hay khả năng phân biệt malware ngoài đời.
2. **Ground truth tự xây:** Người viết detector cũng tạo kịch bản; nguy cơ kiểm thử thuận theo luật, cần bộ ca độc lập.
3. **External validity:** Dataset nhỏ, synthetic, host/IP/time đơn giản; chưa bao phủ NAT, DHCP, mất log và nhiễu thực tế.
4. **Baseline chưa thuần:** Single-agent còn Response chung; detector/risk giống nhau ở mọi strategy.
5. **Số mẫu provider nhỏ:** Hai ca thành công không đủ CI, kiểm định thống kê hay kết luận vượt trội.
6. **Ngữ nghĩa chưa chấm độc lập:** Evidence IDs tồn tại không đủ xác nhận every claim và recommendation đúng.
7. **Temporal semantics:** Sysmon XML dùng TimeCreated và Zeek dùng flow start; độ trễ ghi event/clock có thể phá cửa sổ 2 giây.
8. **Causality:** Cùng process hoặc thời gian gần không chứng minh mục đích độc hại và toàn chuỗi autorun execution.
9. **Tính chu kỳ:** Traffic benign cũng periodic; jitter/lưu lượng ít có thể gây false negative.
10. **Sampling/truncation:** Earliest-per-source và context 25 phần tử có thể bỏ mất evidence quan trọng.
11. **Provider instability:** Network, quota, model/version, reasoning và tốc độ thay đổi; kết quả không hoàn toàn xác định.
12. **Chi phí:** Chỉ có usage quan sát, chưa có hóa đơn/định mức tiền phí hay đảm bảo hard cap.
13. **Thử nghiệm bị trộn môi trường:** Cần giữ product và verification riêng như thiết kế hiện tại.
14. **Human review bias:** Chưa có nhiều analyst gán nhãn và đo mức đồng thuận.
15. **Prototype local:** Chưa có đánh giá bảo mật nhiều người dùng, throughput lớn hoặc availability production.

## 27. Phương pháp nghiên cứu và kế hoạch thực nghiệm nên bổ sung

Phần này là **đề xuất**, không được trình bày như đã làm xong.

### 27.1. Phương pháp

- Tổng quan tài liệu về host/network telemetry, điều tra theo chuỗi hành vi, ATT&CK và AI hỗ trợ analyst.
- Phân tích yêu cầu, thiết kế kiến trúc và xây dựng nguyên mẫu.
- Thực nghiệm có kiểm soát, giữ scope/input/budget cố định.
- Đánh giá định lượng rule/evidence/runtime và đánh giá định tính/ngữ nghĩa của analyst.
- Phân tích lỗi, false positive, false negative và giới hạn triển khai.

### 27.2. Các thí nghiệm ưu tiên

1. Hoàn thành thu lab máy thật với đủ Sysmon/PCAP/Zeek và biên bản ground truth.
2. Thêm traffic benign updater/monitoring và thao tác quản trị hợp lệ.
3. Thay đổi interval, jitter, số connection và thời gian lệch để khảo sát độ nhạy ngưỡng.
4. Ablation bỏ Sysmon/Zeek/Event 3/mapping để đo đóng góp từng nguồn.
5. So sánh một specialist điều tra với nhiều specialist, giữ Response chung hoặc loại riêng chi phí bước này.
6. Chấm từng claim AI: supported/unsupported/contradicted/insufficient evidence; không chỉ chấm refs.
7. Chấm recommendation về đúng ngữ cảnh, mức ưu tiên, khả thi, điều kiện và rủi ro vận hành.
8. Lặp provider nhiều lần, ghi model/version/prompt/config, latency, usage, tỷ lệ hoàn tất/fallback.
9. Thử context lớn, truncation, thiếu record và giới hạn call để đo degradation.
10. Đánh giá giao diện bằng tác vụ analyst: thời gian tìm evidence, số thao tác, lỗi hiểu kết luận và phản hồi người dùng.

Không đặt số mẫu hoặc cam kết mức cải thiện tùy ý; cần căn cứ nguồn lực/độ biến thiên. Có thể đề xuất tối thiểu các lượt lặp cho thăm dò, nhưng phân biệt với tính toán power/kích thước mẫu chính thức.

### 27.3. Mẫu bảng ghi thực nghiệm

| Case ID | Nguồn dữ liệu | Ground truth | Strategy/mode/model | Scope/budget | Rule/evidence/link | Claim quality | Runtime/usage | Lỗi/giới hạn |
|---|---|---|---|---|---|---|---|---|
| Điền khi đo | Synthetic hoặc lab capture | Mô tả độc lập | Giữ config | UTC/dataset | Kết quả thực đo | Analyst chấm | Thực đo | Không bỏ ca lỗi |

## 28. Đóng góp có thể nêu và đóng góp chưa được chứng minh

**Có cơ sở mô tả ở mức kỹ thuật/nguyên mẫu:**

- Một pipeline tích hợp log endpoint/network, có provenance và phạm vi truy vấn rõ.
- Cách tách liên kết process–flow được hỗ trợ khỏi giả thuyết thời gian.
- Workflow chuyên trách kết hợp detector xác định với nhận định AI có kiểm tra refs.
- Bản response plan có cấu trúc, đầy đủ một lần và minh bạch fallback.
- Cơ chế test, môi trường dữ liệu và hướng dẫn lab tái lập.

**Chưa được khẳng định là đóng góp khoa học đã chứng minh:** Thuật toán phát hiện mới vượt SOTA, mô hình học mới, ưu thế Multi-agent, phát hiện C2 real-time ở quy mô doanh nghiệp, loại bỏ hallucination, chống prompt injection tuyệt đối hoặc tự động ứng cứu an toàn toàn diện.

Nên viết: “đề xuất và triển khai một nguyên mẫu; đánh giá bước đầu trong các kịch bản xác định; phân tích điều kiện và giới hạn”.

## 29. Khung đề cương gợi ý để GPT phát triển

Đây là khung đề xuất, có thể đổi số chương theo quy định môn học. Không dùng nó để giả định tiểu luận bắt buộc có một số trang cụ thể.

### Mở đầu

- Lý do chọn đề tài, bối cảnh và bài toán.
- Mục tiêu, câu hỏi nghiên cứu, đối tượng và phạm vi.
- Phương pháp, sản phẩm dự kiến/đã có, đóng góp và bố cục.

### Chương 1. Cơ sở lý thuyết và các nghiên cứu liên quan

1. Persistence, Command and Control và quan hệ trong điều tra hành vi.
2. Sysmon: sự kiện, ProcessGuid và giới hạn quan sát.
3. Zeek: conn/dns/http và semantics thời gian/connection.
4. Tương quan endpoint–network, 5-tuple, host–IP mapping, độ lệch thời gian.
5. LLM, agent, multi-agent, structured output, tool calling, evidence grounding.
6. ATT&CK và vai trò ánh xạ ứng viên.
7. Nhóm công trình liên quan và khoảng trống được xác minh bằng tài liệu.

### Chương 2. Phân tích yêu cầu và thiết kế hệ thống

1. Use case và yêu cầu chức năng/phi chức năng.
2. Phạm vi nguyên mẫu và threat/trust model.
3. Kiến trúc thành phần, deployment và phân tách dữ liệu.
4. Mô hình dữ liệu, schema chuẩn hóa và provenance.
5. Workflow/state, trách nhiệm agent và baseline strategy.
6. Thiết kế detector, correlation, risk và response plan.
7. Thiết kế API, UI, queue, budget và fallback.

### Chương 3. Xây dựng nguyên mẫu

1. Công nghệ và môi trường, entrypoints và cấu trúc mã.
2. Parser/atomic upload/validation.
3. Scoped tools, process lineage, periodicity, ATT&CK retrieval.
4. Triển khai node/graph và provider runtime.
5. Lưu trữ, migration, jobs/cancellation/audit.
6. Giao diện sáng và luồng thao tác analyst.
7. Các vấn đề triển khai, sửa lỗi và kiểm chứng.

### Chương 4. Kịch bản và phương pháp đánh giá

1. Dữ liệu synthetic và hạn chế; kế hoạch lab thực.
2. Ground truth và protocol chạy lặp.
3. Baseline/ablation, biến kiểm soát và biến độc lập.
4. Metric rule/evidence/semantic/runtime/cost, cách xử lý null và ca lỗi.
5. Kết quả 78 test, 36 lượt Offline và hai ca Gemini thật.
6. Các phép đo bổ sung chưa có; nếu chưa thực hiện thì ghi rõ là kế hoạch.

### Chương 5. Thảo luận và hướng phát triển

1. Diễn giải đúng bằng chứng đạt và chưa đạt.
2. Phân tích false positive/negative, hallucination và provider failure.
3. Khác biệt giữa tương quan, causality và kết luận tấn công.
4. Threats to validity, bảo mật dữ liệu và rủi ro vận hành.
5. Hướng mở rộng dataset, grounding, baseline và usability.

### Kết luận, tài liệu tham khảo và phụ lục

- Kết luận theo mục tiêu/câu hỏi có bằng chứng, không phóng đại.
- Tài liệu tham khảo thật với metadata được xác minh.
- Phụ lục API/schema/config mẫu không chứa key, kịch bản, bảng kết quả và hình UI.

## 30. Danh mục hình/bảng nên có trong tiểu luận

**Hình:** kiến trúc tổng thể; graph/state agent; sequence upload→job→report; ERD; chuỗi evidence Run Key→Event 3→Zeek conn; topology lab; các tab kết quả; ví dụ correlation mạnh/yếu; biểu đồ latency tách Offline/provider.

**Bảng:** yêu cầu và tiêu chí chấp nhận; ánh xạ trường Sysmon/Zeek; rule/ATT&CK; vai trò agent; ngân sách/cấu hình; bốn ca synthetic; ma trận lab; metric/giới hạn; kết quả thực đo; ablation dự kiến; threats to validity.

Các hình mô phỏng không được chú thích là ảnh chụp kết quả thật. Khi có ảnh UI cần giữ phạm vi dữ liệu rõ và che thông tin nhạy cảm.

## 31. Bản đồ mã nguồn để truy ngược khẳng định

| Chủ đề cần chứng minh | File/tài liệu trong repository |
|---|---|
| API, upload, metrics, review | product/app/main.py |
| Parser Sysmon | product/app/ingestion/sysmon_parser.py; sysmon_xml_parser.py |
| Parser Zeek | product/app/ingestion/zeek_parser.py |
| Chuẩn hóa endpoint | product/app/ingestion/normalize.py |
| Scoped query, cap, thống kê | product/app/tools/shared.py |
| Detector | product/app/tools/detection.py |
| Correlation | product/app/tools/correlation.py |
| ATT&CK | product/app/tools/attack.py |
| Phân vai | product/app/agents/supervisor_agent.py; persistence_agent.py; c2_agent.py; correlation_agent.py |
| Context/tool loop | product/app/agents/specialists.py |
| Retry, output và diagnostics | product/app/agents/provider_runtime.py |
| AI response | product/app/agents/response_agent.py |
| Graph và state | product/app/services/workflow.py; product/app/schemas/investigation_state.py |
| Risk và local fallback | product/app/services/risk.py; recommendations.py |
| Job/lease/finalization/alert | product/app/services/investigations.py |
| Reports | product/app/services/reports.py |
| Tables/migration | product/app/db/models.py; migrations.py; database.py |
| Schema đầu vào/đầu ra | product/app/schemas/investigation.py; domain.py |
| Cấu hình | product/app/config.py; product/.env.example |
| UI/theme | product/frontend/app.py; style.css; .streamlit/config.toml |
| Chạy sản phẩm/test | product/compose.yaml; verification/compose.yaml |
| Kịch bản và metrics | verification/scripts/scenarios.py; evaluate.py |
| Gọi provider thật cô lập | verification/scripts/check_ai_provider.py |
| Demo/kiểm tra | verification/scripts/seed_demo.py; check_stack.py; check_ui.py |
| Bảo vệ target | verification/scripts/target.py |
| Lab và validator | verification/lab/; verification/scripts/validate_lab_capture.py |
| Test suite | verification/tests/ |
| Hướng dẫn tổng quát | README.md |
| Kiến trúc/đánh giá/trạng thái | docs/ARCHITECTURE.md; EVALUATION.md; IMPLEMENTATION_STATUS.md |
| Tự kiểm thử và thu máy thật | docs/MANUAL_PRODUCT_TEST.md; REAL_MACHINE_LAB.md |

Các artifact nêu trong phần kết quả không bắt buộc tải lên cùng file này: số liệu cần thiết đã được chép vào bảng. Muốn thẩm định sâu hơn phải đọc artifact gốc, không suy luận thêm trường chưa có trong tài liệu.

## 32. Thuật ngữ ngắn

| Thuật ngữ | Nghĩa dùng trong dự án |
|---|---|
| Dataset | Một lần upload file với source và metadata |
| Event/evidence | Sự kiện đã lưu, có UUID và provenance |
| Finding | Dấu hiệu detector ghi nhận, có refs và giới hạn |
| Assessment | Nhận định của specialist LLM, là giả thuyết cần review |
| Relationship | Liên kết evidence mạnh/yếu theo điều kiện mã |
| Severity | Mức ưu tiên điều tra theo rubric |
| Confidence | Mức tin cậy phân loại, chưa hiệu chuẩn xác suất |
| Scope | Dataset, host/IP và thời gian được phép truy vấn |
| Grounding | Ràng buộc output với evidence/kiến thức được cung cấp |
| Fallback | Kết quả local khi AI không có/không hợp lệ/không hoàn tất |
| Provenance | Nguồn gốc, vị trí, hash và liên hệ bản ghi |
| CV | Độ lệch chuẩn chia trung bình khoảng thời gian giữa kết nối |
| 5-tuple | Hai IP, hai cổng và protocol |
| Response plan | Bản đề xuất xử lý tổng hợp, không tự thực thi |

## 33. Nguồn tham khảo và cách dùng cho đề cương

Nguồn nội bộ chính là mã và các tài liệu được lập chỉ mục ở mục 31. Bốn trang chính thức dưới đây đã được mở đối chiếu khi tổng hợp ngày 23/11/2026; chúng hỗ trợ khái niệm/công nghệ, không chứng minh kết quả thực nghiệm của dự án:

1. [Microsoft Sysinternals — Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon): vai trò telemetry Windows, process/network/registry và cấu hình.
2. [Zeek — conn.log](https://docs.zeek.org/en/current/reference/logs/conn.html): trường kết nối và ý nghĩa log mạng.
3. [MITRE ATT&CK — T1547.001](https://attack.mitre.org/techniques/T1547/001/): ngữ cảnh Registry Run Keys/Startup Folder.
4. [LangGraph overview](https://docs.langchain.com/oss/python/langgraph/overview): graph orchestration cho state, node và edge; khả năng thư viện không đồng nghĩa mọi khả năng đã dùng trong dự án.

Các link chính thức tiếp theo là chỉ mục tài liệu đã có trong hệ sinh thái dự án để nghiên cứu thêm; cần kiểm tra nội dung/version/ngày truy cập khi lập bibliography cuối cùng:

- MITRE T1053.005: https://attack.mitre.org/techniques/T1053/005/
- MITRE T1543.003: https://attack.mitre.org/techniques/T1543/003/
- MITRE T1071.001: https://attack.mitre.org/techniques/T1071/001/
- MITRE T1071.004: https://attack.mitre.org/techniques/T1071/004/
- Zeek Quick Start: https://docs.zeek.org/en/current/quickstart.html
- Gemini OpenAI compatibility: https://ai.google.dev/gemini-api/docs/openai
- DeepSeek JSON mode: https://api-docs.deepseek.com/guides/json_mode/

**Chưa có systematic literature review hoặc danh mục paper khoa học đầy đủ trong hồ sơ.** GPT cần tìm/đề xuất nhóm tài liệu liên quan nhưng không được bịa tác giả, DOI, năm xuất bản hoặc kết quả. Nếu chưa tra được tài liệu, ghi “cần bổ sung nguồn” thay vì tạo citation giả.

## 34. Thông tin người dùng cần bổ sung trước khi chốt đề cương

- Trường/khoa, môn học và quy định hình thức tiểu luận.
- Người thực hiện, giảng viên hướng dẫn và thời hạn nộp.
- Số trang/số chương dự kiến và chuẩn trích dẫn.
- Là đề cương trước nghiên cứu hay báo cáo tổng kết nguyên mẫu đã làm.
- Mức bắt buộc về thí nghiệm máy thật và dữ liệu độc lập.
- Máy lab, quyền truy cập, tài nguyên và giới hạn API/chi phí thực tế.
- Có được dùng Gemini/DeepSeek để xử lý log của môi trường thực tế hay chỉ log lab.

Không tự điền các thông tin này bằng suy đoán.

## 35. Prompt có thể gửi cùng file này cho GPT

> Hãy đọc toàn bộ hồ sơ dự án đính kèm và viết đề cương chi tiết tiểu luận bằng tiếng Việt cho đề tài được mô tả. Căn cứ vào triển khai và kết quả thật trong hồ sơ; không coi đề xuất tương lai là phần đã hoàn thành.
>
> Trước tiên, tóm tắt đúng bài toán và chỉ ra những khẳng định chưa đủ bằng chứng. Sau đó đề xuất tên đề tài phù hợp, mục tiêu tổng quát/cụ thể, câu hỏi nghiên cứu, đối tượng, phạm vi, phương pháp và đóng góp ở mức nguyên mẫu.
>
> Xây dựng đề cương đến cấp chương/mục/tiểu mục. Với mỗi mục, ghi rõ: nội dung cần viết, căn cứ mã hoặc bảng số liệu trong hồ sơ, hình/bảng nên có, thí nghiệm cần bổ sung và tiêu chí hoàn thành. Phân biệt phần đã có với phần cần làm thêm.
>
> Khi lập chương đánh giá, dùng phần cập nhật ngày 24/11/2026 cho bản hiện hành. Đặt 78 test và 36 lượt Offline ngày 23/11/2026 cùng hai ca Gemini ngày 21/11/2026 vào đúng mốc lịch sử. Không viết Multi-agent vượt Single-agent từ Offline; chú ý baseline single_agent có Response advisor chung. Không gọi metric kiểm tra rule set là độ chính xác phát hiện tấn công thực tế. Nêu đúng semantics độ trễ và giới hạn token budget.
>
> Đề xuất kế hoạch lab máy thật, ablation và đánh giá ngữ nghĩa AI có ground truth/analyst review, nhưng không giả định đã có PCAP/EVTX thực nghiệm thành công. Không bịa tài liệu tham khảo, không tạo số liệu, không yêu cầu hoặc chèn API key.
>
> Nếu thiếu thông tin về quy định môn học, hãy liệt kê ngắn các câu hỏi cần tôi bổ sung; vẫn có thể đưa khung đề cương dự thảo với giả định được ghi rõ. Kết thúc bằng danh sách công việc ưu tiên để từ trạng thái hiện tại hoàn thiện tiểu luận.

---

**Cách sử dụng:** Tải lên duy nhất file này, gửi prompt ở mục 35 hoặc yêu cầu tương đương. Không cần gửi `.env`, toàn bộ database hoặc log cá nhân cho GPT chỉ để viết đề cương.
