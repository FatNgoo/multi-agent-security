# Reproducible evaluation

Run from `verification/` with Python 3.12. Install dependencies from the repository root using `uv pip install -r verification/requirements.txt`, then `Set-Location verification`. Backend settings load from `product/.env`; test and evaluation databases remain isolated.

```powershell
..\.venv\Scripts\python.exe -m pytest -q
..\.venv\Scripts\python.exe -m scripts.evaluate --runs 3 --output artifacts/evaluation-offline.json
```

The evaluation runner uses a fresh temporary SQLite database and uploads synthetic labeled records through FastAPI. The four original scenarios cover a supported cross-source association, an ambiguous join without Event 3, a periodic connection with analyst-supplied benign context, and irregular negative-control traffic. Thirteen additional cases cover Windows startup, scheduled tasks, service changes, DNS, cleanup, inventory and cross-source controls. The fixtures and expected evidence are in [the case library](../verification/logs/cases/README.md). Three strategies share the same tools, rule substrate, model configuration and per-investigation budgets. The runner saves raw per-run metrics and provider assessment statuses.

The unit for finding precision/recall is a distinct deterministic `rule_id` within a labeled scenario. Expected evidence includes the persistence event, applicable endpoint network events and applicable Zeek connection records. Evidence completeness measures references actually cited in findings/relationships against that labeled set. Evidence validity checks whether cited IDs resolve in the scoped result. Severity agreement compares the result to the scenario's expected triage level.

Offline runs test pipeline correctness and reproducibility. Their common deterministic substrate produces the same detector decisions across strategies. A comparative claim about LLM investigation quality requires provider runs and analyst-labeled narrative claims. `unsupported_claim_rate` remains null until those annotations exist. Missing metrics and empty denominators remain null.

For provider experiments using the synthetic cases, configure the provider key in the backend `product/.env`, then run the following command. The command makes billed requests to the configured API.

```powershell
..\.venv\Scripts\python.exe -m scripts.evaluate --case combined --mode gemini --runs 1 --output artifacts/evaluation-gemini.json
```

Inspect every provider status alongside latency and token usage. Provider failure, deadline or missing assessments affect interpretation of the comparison. Pricing and semantic claim accuracy require separately recorded inputs. Preserve the model version, corpus version, rubric version, dataset ground truth and configuration with experimental artifacts.

The application records detection-to-server-alert-creation latency. This interval starts after evidence verification and excludes the earlier investigation duration. It also excludes transaction commit, UI polling and browser display. Report total investigation duration separately. Population summaries sample the latest 1000 completed investigations and include the sample count.

## Đợt đối chiếu ngày 24/11/2026

Cùng bộ 17 ca mô phỏng và cùng phạm vi, trước khi sửa có 13/17 ca khớp tập luật và mức ưu tiên. Bốn sai lệch đều ở nhóm đối chứng. Việc xóa tệp Startup, xóa khóa TaskCache, xóa giá trị Run và truy vấn dịch vụ có tên `config` từng bị diễn giải như thao tác thiết lập. Sau khi xét loại sự kiện và vị trí đối số, 17/17 ca khớp. Các thao tác xóa registry vẫn xuất hiện như thay đổi ở mức thông tin.

| Phép đo | Trước | Sau |
|---|---:|---:|
| Ca riêng biệt khớp tập luật | 13/17 | 17/17 |
| Ca riêng biệt khớp mức ưu tiên | 13/17 | 17/17 |
| Ca riêng biệt khớp tập loại liên kết | 17/17 | 17/17 |
| Ca có bước cô lập hoặc khắc phục trong playbook | 11/17 | 2/17 |

Hai ca còn bước cô lập là `combined` và `service-periodic`, đều có liên kết tiến trình–flow và mức ưu tiên cao. Điều kiện áp dụng yêu cầu xác minh và phê duyệt vận hành. Mức trung bình được hướng dẫn xác minh, lưu bằng chứng và theo dõi. Mỗi luật có hướng dẫn kiểm tra riêng, ví dụ so ImagePath với cấu hình đã duyệt hoặc đối chiếu DNS với lịch hoạt động của dịch vụ.

Lần đo trước gồm 51 lượt (mỗi chiến lược chạy một lần cho mỗi ca). Lần đo sau gồm 153 lượt (ba lần lặp). Cả 153 lượt Offline sau đều khớp tập luật, mức ưu tiên và tập loại liên kết. Các mã bằng chứng của từng bước trong kế hoạch đều nằm trong phạm vi. Đây là phép đo hồi quy trên 17 bộ dữ liệu có nhãn do dự án xây dựng. Chất lượng lập luận trên sự cố thực tế cần được chuyên viên đánh giá trên dữ liệu độc lập.

**DeepSeek trên dữ liệu mô phỏng.** Với ca `combined`, lần đầu ba agent điều tra hoàn tất nhưng agent đề xuất nhận một câu ở trường limitations thay cho danh sách. Sau khi bảo toàn câu đó dưới dạng danh sách một phần tử và giữ kiểm tra mã bằng chứng, lần chạy tiếp theo cả bốn agent hoàn tất qua 4 lượt gọi trong 27,8 giây. Kế hoạch có bốn bước, gồm đối chiếu Run Key và chữ ký tệp, lưu log và mã băm, xác minh chu kỳ kết nối với lịch cập nhật, rồi giám sát hoặc cô lập có điều kiện. Kết quả này xác nhận luồng tích hợp trên một ca. Chưa có điểm đánh giá ngữ nghĩa từ chuyên viên độc lập.

Bộ pytest có 93 kiểm thử đạt. Kết quả chi tiết của đợt này nằm trong `verification/artifacts/dashboard-baseline.json`, `dashboard-evaluation.json` và hai tệp `dashboard-deepseek*.json` trên máy chạy.
