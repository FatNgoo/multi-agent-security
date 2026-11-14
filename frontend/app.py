"""Local analyst workspace using the Dark Crimson design system."""
import html
import json
import os
from datetime import datetime, timedelta, timezone
import pandas as pd
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")
SOURCES = ["sysmon", "zeek_conn", "zeek_dns", "zeek_http"]
SEVERITIES = ["unknown", "informational", "low", "medium", "high", "critical"]
st.set_page_config(page_title="Persistence & C2 • Investigation", page_icon="◈", layout="wide")
st.markdown('''<style>
:root {--bg:#100F14;--surface:#19151D;--raised:#251B25;--accent:#F05A67;--text:#F5F1F3;--muted:#BDAFB9;}
html,body,[class*="st-"] {font-family:SpotifyMixUI,"Helvetica Neue",Helvetica,Arial,sans-serif;}
.stApp,[data-testid="stAppViewContainer"] {background:var(--bg);color:var(--text);}
[data-testid="stHeader"] {background:rgba(16,15,20,.93);}
[data-testid="stSidebar"] {background:var(--surface);border-right:1px solid #30222D;}
.block-container {padding-top:2rem;padding-bottom:5rem;max-width:1600px;}
h1,h2,h3 {font-family:SpotifyMixUITitle,"Helvetica Neue",Arial,sans-serif!important;font-weight:700!important;}
h1 {font-size:24px!important;} h2 {font-size:22px!important;} h3 {font-size:18px!important;}
p,.stMarkdown,li {color:var(--text);font-size:16px;}
.stCaption p {color:var(--muted);font-size:14px;}
.stButton button,.stDownloadButton button,.stFormSubmitButton button {border-radius:9999px!important;background:#251B25;color:#F5F1F3;border:1px solid #55414C;letter-spacing:1.4px;font-size:14px;text-transform:uppercase;font-weight:700;min-height:40px;}
.stButton button[kind="primary"],.stFormSubmitButton button[kind="primary"] {background:#F05A67;color:#100F14;border:0;}
button:focus-visible,a:focus-visible,input:focus-visible {outline:2px solid #F4B860!important;outline-offset:3px;}
[data-testid="stMetric"] {background:#19151D;border-radius:8px;padding:16px;box-shadow:0 8px 8px rgba(0,0,0,.3);}
[data-testid="stMetricLabel"] p {color:#BDAFB9;font-size:14px;}
[data-testid="stMetricValue"] {font-size:26px;}
[data-testid="stExpander"] {background:#19151D;border:0;border-radius:8px;}
[data-baseweb="input"],[data-baseweb="select"]>div {background:#251B25!important;border-radius:20px!important;box-shadow:0 1px 0 #100F14,0 0 0 1px #927983 inset;}
.identity {font-size:22px;font-weight:700;color:#F05A67;letter-spacing:1px;margin:0 0 4px;}
.eyebrow {color:#BDAFB9;font-size:12px;letter-spacing:1.4px;margin-bottom:24px;}
.finding {background:#19151D;border-radius:8px;padding:20px;margin:12px 0;box-shadow:0 8px 8px rgba(0,0,0,.3);}
.tag {display:inline-block;border-radius:4px;padding:3px 8px;background:#30222D;font-size:12px;margin-right:8px;}
.high,.critical {color:#FF6678}.medium {color:#F4B860}.low {color:#78B8E8}.informational {color:#6CC9AF}.unknown {color:#BDAFB9}
.statusbar {position:fixed;bottom:0;left:0;right:0;background:#19151D;box-shadow:0 -4px 24px rgba(0,0,0,.5);padding:10px 24px;color:#BDAFB9;font-size:12px;z-index:999;}
@media(max-width:768px) {.block-container{padding-left:16px;padding-right:16px;}[data-testid="stHorizontalBlock"]{flex-wrap:wrap;}[data-testid="stColumn"]{min-width:220px;flex:1 1 100%;}.statusbar{padding:8px 12px;font-size:11px;}}
</style>''', unsafe_allow_html=True)


def api(method, path, **kwargs):
    try:
        response = requests.request(method, API_BASE_URL + path, timeout=kwargs.pop("timeout", 20), **kwargs)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as exc:
        detail = str(exc)
        if isinstance(exc, requests.HTTPError):
            try:
                detail = exc.response.json().get("detail", detail)
            except ValueError:
                pass
        st.error(f"API • {detail}")
        return None


def open_job(identifier):
    st.session_state.active_job = identifier
    st.session_state.job_status = None


def ms(value):
    return f"{value:,.1f} ms" if value is not None else "—"


@st.fragment(run_every="2s")
def job_panel():
    identifier = st.session_state.get("active_job")
    if not identifier:
        return
    job = api("GET", f"/api/v1/investigations/{identifier}")
    if not job:
        return
    previous = st.session_state.get("job_status")
    st.session_state.job_status = job["status"]
    st.caption(f"{identifier} · {job['status']} · {job['progress']}")
    if job["status"] in {"queued", "running"}:
        st.info(f"Đang điều tra • {job['progress']}")
        if st.button("Hủy điều tra", key="cancel_active"):
            api("POST", f"/api/v1/investigations/{identifier}/cancel")
            st.rerun()
    elif job["result"]:
        st.session_state.last_result = job["result"]
        if previous != "completed":
            st.rerun()
    else:
        st.warning(job.get("error") or f"Investigation {job['status']}")


def results_view(result):
    if not result:
        st.info("Chọn một cuộc điều tra đã hoàn thành để xem kết quả.")
        return
    st.subheader(result["summary"])
    metrics = st.columns(4)
    metrics[0].metric("Mức nguy hiểm", result["risk"]["severity"].upper())
    metrics[1].metric("Findings", len(result["findings"]))
    metrics[2].metric("Phát hiện → tạo cảnh báo", ms(result["timings"].get("detection_to_alert_ms")))
    metrics[3].metric("Thời gian điều tra", ms(result["timings"].get("total_ms")))
    for warning in result.get("warnings", []):
        st.warning(warning)
    findings_tab, timeline_tab, relations_tab, evidence_tab, trace_tab, report_tab = st.tabs(
        ["Findings & biện pháp", "Timeline", "Liên kết", "Evidence", "Agent & tools", "Báo cáo"])
    with findings_tab:
        levels = st.multiselect("Lọc mức nguy hiểm", SEVERITIES)
        for item in result["findings"]:
            if levels and item["severity"] not in levels:
                continue
            st.markdown(f'<div class="finding"><span class="tag {html.escape(item["severity"])}">{html.escape(item["severity"].upper())}</span>'
                        f'<span class="tag">Confidence {html.escape(item["confidence"])}</span>'
                        f'<h3>{html.escape(item["title"])}</h3><p>{html.escape(item["severity_reason"])}</p></div>', unsafe_allow_html=True)
            st.caption(f"{item['agent']} · {item['classification']} · {item['rule_id']}")
            for limitation in item["limitations"]:
                st.caption(limitation)
            for reference in item.get("attack", []):
                st.markdown(f"ATT&CK candidate [{reference['technique_id']} · {reference['name']}]({reference['source']})")
            with st.expander("Evidence liên quan"):
                selected = [e for e in result["evidence"] if e["evidence_id"] in item["evidence_ids"]]
                for event in selected:
                    st.caption(f"{event['timestamp']} · {event['evidence_id']}")
                    st.json(event)
            with st.expander("Biện pháp đề xuất và tiến độ xử lý"):
                for action in item["recommendations"]:
                    st.write(f"**{action['priority']} · {action['phase'].upper()}** — {action['action']}")
                    st.caption(f"Điều kiện áp dụng • {action['condition']}")
                    st.caption(f"Ảnh hưởng vận hành • {action['operational_impact']}")
                    st.caption(f"Kiểm tra kết quả • {action['verification']}")
                    with st.form(f"recommendation_{action['id']}"):
                        status = st.selectbox("Trạng thái xử lý", ["pending", "in_progress", "completed", "skipped"],
                                              index=["pending", "in_progress", "completed", "skipped"].index(action["status"]))
                        note = st.text_input("Ghi chú", key=f"note_{action['id']}")
                        if st.form_submit_button("Lưu tiến độ") and note.strip():
                            if api("PATCH", f"/api/v1/investigations/{result['investigation_id']}/findings/{item['id']}",
                                   json={"recommendation_id": action["id"], "recommendation_status": status, "note": note}):
                                st.rerun()
            with st.expander("Analyst review mức nguy hiểm"):
                with st.form(f"review_{item['id']}"):
                    severity = st.selectbox("Severity", SEVERITIES, index=SEVERITIES.index(item["severity"]))
                    note = st.text_input("Lý do điều chỉnh")
                    if st.form_submit_button("Lưu đánh giá") and note.strip():
                        if api("PATCH", f"/api/v1/investigations/{result['investigation_id']}/findings/{item['id']}",
                               json={"severity": severity, "note": note}):
                            st.rerun()
    with timeline_tab:
        st.dataframe(result["timeline"], hide_index=True, width='stretch')
        if result["timeline"]:
            frame = pd.DataFrame(result["timeline"])
            frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
            counts = frame.groupby([pd.Grouper(key="timestamp", freq="1min"), "source"]).size().unstack(fill_value=0)
            st.bar_chart(counts)
    with relations_tab:
        if result["relationships"]:
            for relationship in result["relationships"]:
                with st.expander(f"{relationship['type']} · {relationship['confidence']}"):
                    st.json(relationship)
        else:
            st.info("Chưa có liên kết đủ điều kiện trong phạm vi dữ liệu đã chọn.")
    with evidence_tab:
        if result.get("process_tree"):
            with st.expander("Process lineage"):
                st.dataframe([{key: node.get(key) for key in ("host", "image", "process_guid", "parent_process_guid", "parent_evidence_ids", "evidence_id")}
                              for node in result["process_tree"]], hide_index=True, width="stretch")
        search = st.text_input("Tìm trong evidence", placeholder="Evidence ID, process, IP, registry…")
        selected_sources = st.multiselect("Nguồn dữ liệu", SOURCES, default=SOURCES)
        filtered = [e for e in result["evidence"] if e["source"] in selected_sources
                    and search.lower() in json.dumps(e, ensure_ascii=False).lower()]
        st.caption(f"{len(filtered)} evidence trong {result['coverage']['matching_records']} bản ghi phù hợp phạm vi")
        st.dataframe([{key: e.get(key) for key in ("timestamp", "source", "host", "event_id", "description", "evidence_id")}
                      for e in filtered], hide_index=True, width='stretch')
        if filtered:
            evidence_id = st.selectbox("Mở raw record", [e["evidence_id"] for e in filtered])
            st.json(next(e for e in filtered if e["evidence_id"] == evidence_id))
        statistics = [f["statistics"] for f in result["findings"] if "statistics" in f]
        if statistics:
            st.subheader("Beacon statistics")
            st.dataframe([{k: v for k, v in s.items() if k != "evidence_ids"} for s in statistics], hide_index=True)
    with trace_tab:
        st.dataframe(result["timings"]["tool_trace"], hide_index=True, width='stretch')
        st.json({"tokens": result["timings"]["tokens"], "llm_calls": result["timings"]["llm_calls"],
                 "coverage": result["coverage"], "verification": result["verification"], "plan": result["plan"]})
        for assessment in result["assessments"]:
            st.json(assessment)
    with report_tab:
        st.download_button("Tải JSON", json.dumps(result, ensure_ascii=False, indent=2),
                           file_name=f"investigation-{result['investigation_id']}.json", mime="application/json")
        if st.button("Chuẩn bị báo cáo Markdown"):
            try:
                response = requests.get(API_BASE_URL + f"/api/v1/investigations/{result['investigation_id']}/report",
                                        params={"format": "markdown"}, timeout=20)
                response.raise_for_status()
                st.download_button("Tải Markdown", response.text, file_name="investigation-report.md", mime="text/markdown")
            except requests.RequestException as exc:
                st.error(str(exc))
        if st.checkbox("Xem lịch sử analyst review"):
            st.json(api("GET", f"/api/v1/investigations/{result['investigation_id']}/audit") or [])


health = api("GET", "/health", timeout=5)
with st.sidebar:
    st.markdown('<div class="identity">◈ INVESTIGATION</div><div class="eyebrow">PERSISTENCE & COMMAND AND CONTROL</div>', unsafe_allow_html=True)
    page = st.radio("Điều hướng", ["Tổng quan", "Datasets", "Điều tra", "Cảnh báo", "Lịch sử & báo cáo", "Kiến thức & cấu hình"], label_visibility="collapsed")
    st.divider()
    st.caption(f"Backend • {health['status'] if health else 'unavailable'}")
    if health:
        st.caption(f"Database • {health['database']}\n\nProvider • {health['mode']}")
    if st.session_state.get("active_job"):
        st.caption(f"Investigation • {st.session_state.active_job[:8]}")
st.title(page)
st.markdown(f'<div class="statusbar">◈ PERSISTENCE & C2 &nbsp; · &nbsp; {html.escape(health["database"] if health else "Backend unavailable")} &nbsp; · &nbsp; UTC timestamps &nbsp; · &nbsp; Analyst workspace</div>', unsafe_allow_html=True)

if page == "Tổng quan":
    metrics = api("GET", "/api/v1/metrics")
    if metrics:
        columns = st.columns(4)
        columns[0].metric("Datasets", metrics["datasets"])
        columns[1].metric("Bản ghi", metrics["events"])
        columns[2].metric("Cảnh báo mới", metrics["alerts"].get("new", 0))
        columns[3].metric("Đang điều tra", metrics["investigations"].get("running", 0))
        left, right = st.columns(2)
        with left:
            st.subheader("Mức nguy hiểm của cảnh báo")
            if metrics["severity"]:
                st.bar_chart(pd.Series(metrics["severity"], name="alerts"))
            else:
                st.info("Upload dữ liệu và chạy điều tra để tạo findings và cảnh báo.")
        with right:
            st.subheader("Hiệu năng xử lý")
            st.metric("Phát hiện → tạo cảnh báo · p50", ms(metrics["detection_to_alert"]["p50_ms"]))
            st.metric("Phát hiện → tạo cảnh báo · p95", ms(metrics["detection_to_alert"]["p95_ms"]))
            st.caption(f"{metrics['detection_to_alert']['samples']} mẫu cảnh báo · kết thúc đo khi server tạo alert")
            st.metric("Thời gian điều tra · p95", ms(metrics["runtime"]["p95_ms"]))
    latest = api("GET", "/api/v1/investigations?limit=10") or []
    st.subheader("Điều tra gần đây")
    st.dataframe([{k: v for k, v in j.items() if k != "scope"} for j in latest], hide_index=True, width='stretch')

elif page == "Datasets":
    with st.form("upload", clear_on_submit=True):
        source = st.selectbox("Nguồn dữ liệu", SOURCES)
        uploaded = st.file_uploader("Sysmon XML/JSONL hoặc Zeek JSON/TSV", type=["jsonl", "json", "xml", "log", "tsv"])
        if st.form_submit_button("Upload & kiểm tra", type="primary"):
            if uploaded:
                result = api("POST", "/api/v1/logs/upload", data={"source_type": source}, files={"file": (uploaded.name, uploaded.getvalue())})
                if result:
                    st.success(f"Đã nhập {result['imported_records']} bản ghi")
                    st.json(result)
            else:
                st.warning("Chọn file để upload.")
    offset = st.number_input("Vị trí bắt đầu danh sách", min_value=0, step=100, value=0)
    datasets = api("GET", f"/api/v1/datasets?limit=100&offset={offset}") or []
    st.dataframe([{k: d.get(k) for k in ("filename", "source", "total_records", "created_at", "dataset_id")}
                  for d in datasets], hide_index=True, width='stretch')
    for dataset in datasets:
        with st.expander(f"{dataset['filename']} · metadata"):
            st.json(dataset)

elif page == "Điều tra":
    datasets = api("GET", "/api/v1/datasets?limit=1000") or []
    if datasets:
        names = {d["dataset_id"]: f"{d['filename']} · {d['source']} · {d['dataset_id'][:8]}" for d in datasets}
        with st.form("investigation"):
            selected = st.multiselect("Datasets", list(names), format_func=names.get)
            host_col, ip_col = st.columns(2)
            host = host_col.text_input("Host", placeholder="WIN-LAB-01")
            ip = ip_col.text_input("IP", placeholder="192.0.2.10")
            now = datetime.now(timezone.utc)
            default_start = min((d.get("metadata", {}).get("start_time") or now.isoformat() for d in datasets))
            default_end = max((d.get("metadata", {}).get("end_time") or now.isoformat() for d in datasets))
            start = st.text_input("Bắt đầu · ISO 8601 có timezone", default_start)
            end = st.text_input("Kết thúc · ISO 8601 có timezone", default_end)
            mode = st.selectbox("Chế độ", ["offline", "gemini", "deepseek"])
            strategy = st.selectbox("Chiến lược", ["multi_agent", "single_agent", "heuristic"])
            criticality = st.selectbox("Mức quan trọng tài sản", ["medium", "low", "high"])
            benign = st.text_input("IP đích có ngữ cảnh hợp lệ · phân cách dấu phẩy")
            mappings = st.text_area("Host–IP mappings · JSON với host, ip, start_time, end_time", value="[]", height=100)
            submitted = st.form_submit_button("Bắt đầu điều tra", type="primary")
        if submitted:
            try:
                payload = {"dataset_ids": selected, "host": host.strip() or None, "ip": ip.strip() or None,
                           "start_time": start, "end_time": end, "mode": mode, "strategy": strategy,
                           "asset_criticality": criticality, "host_mappings": json.loads(mappings),
                           "benign_destinations": [s.strip() for s in benign.split(",") if s.strip()]}
                job = api("POST", "/api/v1/investigations", json=payload)
                if job:
                    open_job(job["investigation_id"])
                    st.session_state.last_result = None
            except ValueError:
                st.error("Host–IP mappings cần là JSON hợp lệ.")
    else:
        st.info("Upload datasets ở màn hình Datasets để bắt đầu.")
    job_panel()
    results_view(st.session_state.get("last_result"))

elif page == "Cảnh báo":
    status_filter = st.selectbox("Trạng thái", ["all", "new", "acknowledged", "investigating", "closed"])
    alerts = api("GET", "/api/v1/alerts", params={} if status_filter == "all" else {"status": status_filter}) or []
    st.dataframe([{k: v for k, v in a.items() if k != "history"} for a in alerts], hide_index=True, width='stretch')
    if alerts:
        alert_id = st.selectbox("Cảnh báo", [a["alert_id"] for a in alerts])
        item = next(a for a in alerts if a["alert_id"] == alert_id)
        with st.form("alert_review"):
            status = st.selectbox("Chuyển trạng thái", ["new", "acknowledged", "investigating", "closed"])
            note = st.text_input("Ghi chú xử lý")
            if st.form_submit_button("Lưu trạng thái") and note.strip():
                if api("PATCH", f"/api/v1/alerts/{alert_id}", json={"status": status, "note": note}):
                    st.rerun()
        st.json(item["history"])
        if st.button("Mở kết quả điều tra"):
            open_job(item["investigation_id"])
        job_panel()
        results_view(st.session_state.get("last_result"))

elif page == "Lịch sử & báo cáo":
    offset = st.number_input("Vị trí bắt đầu", min_value=0, step=50, value=0)
    jobs = api("GET", f"/api/v1/investigations?limit=50&offset={offset}") or []
    st.dataframe([{k: v for k, v in j.items() if k != "scope"} for j in jobs], hide_index=True, width='stretch')
    if jobs:
        identifier = st.selectbox("Investigation", [j["investigation_id"] for j in jobs])
        if st.button("Mở investigation", type="primary"):
            open_job(identifier)
        job_panel()
        results_view(st.session_state.get("last_result"))

else:
    st.subheader("MITRE ATT&CK retrieval")
    query = st.text_input("Tìm kỹ thuật", "persistence c2")
    knowledge = api("GET", "/api/v1/knowledge", params={"query": query})
    if knowledge:
        st.caption(f"Curated corpus • {knowledge['version']}")
        for record in knowledge["results"]:
            st.markdown(f"[{record['technique_id']} · {record['name']}]({record['source']})")
            st.write(record["summary"])
    st.subheader("Kết nối và vận hành")
    st.json(health or {})
    st.caption("Provider credentials và budget được cấu hình trên backend qua .env. Các mốc thời gian hiển thị theo UTC.")
