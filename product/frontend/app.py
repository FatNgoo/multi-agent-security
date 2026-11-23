"""Light, task-focused workspace for importing logs and reviewing investigations."""
import html
import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")
SOURCES = ["sysmon", "zeek_conn", "zeek_dns", "zeek_http"]
SOURCE_NAMES = dict(zip(SOURCES, ["Sysmon · Endpoint", "Zeek · Kết nối", "Zeek · DNS", "Zeek · HTTP"]))
SEVERITIES = ["critical", "high", "medium", "low", "informational", "unknown"]
LEVELS = dict(zip(SEVERITIES, ["Nghiêm trọng", "Cao", "Trung bình", "Thấp", "Thông tin", "Chưa xác định"]))
COLORS = dict(zip(SEVERITIES, ["#991B1B", "#DC2626", "#B77900", "#2563EB", "#15803D", "#64748B"]))
STATUS = {"new": "Mới", "acknowledged": "Đã tiếp nhận", "investigating": "Đang xử lý", "closed": "Đã đóng",
          "queued": "Đang chờ", "running": "Đang điều tra", "completed": "Hoàn thành", "failed": "Thất bại",
          "cancelled": "Đã hủy", "cancel_requested": "Đang hủy", "pending": "Chưa thực hiện", "in_progress": "Đang thực hiện", "skipped": "Bỏ qua"}
STATUS.update({"unavailable": "Chưa hoàn tất", "llm_budget_exhausted": "Hết ngân sách AI",
               "iteration_limit": "Chưa đủ lượt xử lý", "insufficient_evidence": "Chưa đủ bằng chứng"})
CONFIDENCE = {"high": "Cao", "medium": "Trung bình", "low": "Thấp"}
PHASES = {"verify": "Xác minh", "preserve": "Bảo toàn bằng chứng", "contain": "Cô lập", "remediate": "Khắc phục", "recover": "Khôi phục", "monitor": "Giám sát"}
PAGES = ["Tổng quan", "Datasets", "Điều tra", "Cảnh báo", "Lịch sử & báo cáo", "Kiến thức & cấu hình"]
PAGE_LABELS = dict(zip(PAGES, ["Tổng quan", "Dữ liệu log", "Phân tích", "Cảnh báo", "Lịch sử", "Tra cứu & hệ thống"]))
FINDING_TITLES = {
    "run_key": "Có cấu hình tự chạy khi đăng nhập", "startup": "Có thay đổi trong thư mục khởi động",
    "scheduled_task": "Có dấu hiệu tạo tác vụ định kỳ", "service": "Có dấu hiệu cấu hình dịch vụ",
    "registry_change": "Có thay đổi registry cần kiểm tra", "periodic_connection": "Có kết nối mạng lặp lại đều đặn",
    "long_dns_label": "Có truy vấn DNS dài bất thường",
}
FINDING_NOTES = {
    "run_key": "Log ghi nhận thay đổi cấu hình tự chạy khi đăng nhập. Cần xác minh người tạo và mục đích sử dụng.",
    "startup": "Log ghi nhận thay đổi tại thư mục khởi động. Kiểm tra tệp và phần mềm đã tạo thay đổi.",
    "scheduled_task": "Có dấu hiệu cấu hình tác vụ. Đối chiếu lịch chạy và lệnh thực thi.",
    "service": "Có dấu hiệu cấu hình dịch vụ. Kiểm tra đường dẫn chương trình và người thực hiện.",
    "registry_change": "Registry có thay đổi. Cần thêm ngữ cảnh để xác định thay đổi có hợp lệ hay không.",
    "periodic_connection": "Các kết nối lặp lại theo chu kỳ. Đây cũng có thể là hoạt động cập nhật hoặc giám sát hợp lệ.",
    "long_dns_label": "Một truy vấn DNS có nhãn dài. Hình dạng tên miền chưa đủ để kết luận có dữ liệu bị gửi ra ngoài.",
}
DESCRIPTIONS = {
    "Tổng quan": "Nhập log, phân tích và xem những dấu hiệu cần kiểm tra.",
    "Datasets": "Nhập log, kiểm tra phạm vi dữ liệu và chuẩn bị cho cuộc điều tra.",
    "Điều tra": "Chọn tệp log để bắt đầu. Có thể thu hẹp máy và thời gian khi cần.",
    "Cảnh báo": "Ưu tiên theo mức nguy hiểm, ghi nhận đánh giá và theo dõi xử lý.",
    "Lịch sử & báo cáo": "Mở lại cuộc điều tra, đối chiếu bằng chứng và xuất báo cáo.",
    "Kiến thức & cấu hình": "Tra cứu kỹ thuật ATT&CK và kiểm tra kết nối của hệ thống.",
}

st.set_page_config(page_title="Phân tích log | Persistence & C2", page_icon="◈", layout="wide")
st.markdown(f"<style>{Path(__file__).with_name('style.css').read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def esc(value):
    return html.escape(str(value if value is not None else "—"))


def api(method, path, **kwargs):
    try:
        response = requests.request(method, API_BASE_URL + path, timeout=kwargs.pop("timeout", 20), **kwargs)
        response.raise_for_status()
        return response.text if kwargs.get("params", {}).get("format") == "markdown" else response.json()
    except (requests.RequestException, ValueError) as exc:
        detail = str(exc)
        if isinstance(exc, requests.HTTPError):
            try:
                detail = exc.response.json().get("detail", detail)
            except ValueError:
                pass
        st.error(f"Không thể hoàn tất yêu cầu. {detail}")
        return None


def parsed(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)


def stamp(value, short=False):
    if not value:
        return "—"
    try:
        return parsed(value).strftime("%d/%m · %H:%M" if short else "%d/%m/%Y · %H:%M:%S UTC")
    except (ValueError, TypeError):
        return str(value)


def ms(value):
    if value is None:
        return "—"
    return f"{value / 1000:,.2f} s" if value >= 1000 else f"{value:,.1f} ms"


def badge(value, labels=LEVELS):
    css = value if value in SEVERITIES else "neutral"
    return f'<span class="badge {css}">{esc(labels.get(value, value))}</span>'


def section(title, subtitle=None):
    st.markdown(f'<div class="section-title">{esc(title)}</div>' +
                (f'<div class="section-note">{esc(subtitle)}</div>' if subtitle else ""), unsafe_allow_html=True)


def empty(title, description, icon="◎"):
    st.markdown(f'<div class="empty-state"><div class="empty-symbol">{esc(icon)}</div><strong>{esc(title)}</strong><p>{esc(description)}</p></div>', unsafe_allow_html=True)


def kpis(items):
    for col, (label, value, note, tone) in zip(st.columns(len(items)), items):
        with col:
            st.markdown(f'<div class="kpi"><div class="kpi-label">{esc(label)}</div><div class="kpi-value {esc(tone)}">{esc(value)}</div><div class="kpi-note">{esc(note)}</div></div>', unsafe_allow_html=True)


def navigate(page):
    st.session_state.nav = page


def new_investigation():
    open_job(None)
    navigate("Điều tra")


def open_job(identifier, navigate_to=None):
    st.session_state.active_job = identifier
    st.session_state.job_status = None
    st.session_state.last_result = None
    st.session_state.terminal_job = None
    st.session_state.result_rendered = None
    if navigate_to:
        navigate(navigate_to)


def refresh_result(identifier):
    st.session_state.pop(f"markdown_{identifier}", None)
    job = api("GET", f"/api/v1/investigations/{identifier}")
    if job:
        st.session_state.last_result = job.get("result")
        st.session_state.terminal_job = job


def chart_style(chart):
    return chart.configure(background="transparent").configure_view(strokeWidth=0).configure_axis(
        labelColor="#52647C", titleColor="#172B4D", gridColor="#E3EAF3", domain=False,
        labelFont="Arial", titleFont="Arial", labelFontSize=11, titleFontSize=12,
    ).configure_legend(labelColor="#344967", titleColor="#344967", orient="bottom", title=None)


def pagination(key, has_more):
    page_number = st.session_state.get(key, 0)
    left, middle, right = st.columns([1, 4, 1])
    if left.button("← Trước", key=f"{key}_prev", disabled=page_number == 0, width="stretch"):
        st.session_state[key] = page_number - 1
        st.rerun()
    middle.caption(f"Trang {page_number + 1} · Bộ lọc áp dụng cho trang hiện tại")
    if right.button("Sau →", key=f"{key}_next", disabled=not has_more, width="stretch"):
        st.session_state[key] = page_number + 1
        st.rerun()


@st.fragment(run_every="2s")
def job_panel():
    identifier = st.session_state.get("active_job")
    if not identifier:
        return
    cached = st.session_state.get("terminal_job")
    job = cached if cached and cached["investigation_id"] == identifier else api("GET", f"/api/v1/investigations/{identifier}")
    if not job:
        return
    previous = st.session_state.get("job_status")
    state = job["status"]
    st.session_state.job_status = state
    if state in {"queued", "running", "cancel_requested"}:
        with st.container(border=True):
            st.markdown(f"**◌ {STATUS.get(state, state)}** · {job.get('progress', '')}")
            st.caption(f"Mã điều tra {identifier[:8]} · Tạo lúc {stamp(job.get('created_at'))} · Tự cập nhật mỗi 2 giây")
            if st.button("Hủy điều tra", key="cancel_active", disabled=state == "cancel_requested"):
                api("POST", f"/api/v1/investigations/{identifier}/cancel")
                st.rerun()
    else:
        st.session_state.terminal_job = job
        if job.get("result"):
            st.session_state.last_result = job["result"]
            if previous != state or not st.session_state.get("result_rendered") == identifier:
                st.session_state.result_rendered = identifier
                st.rerun()
        elif state == "cancelled":
            st.info("Cuộc điều tra đã được hủy.")
        else:
            st.error(job.get("error") or f"Cuộc điều tra: {STATUS.get(state, state)}")


def event_table(events, key, height=310):
    if not events:
        empty("Chưa có bằng chứng phù hợp", "Thử thay đổi từ khóa hoặc nguồn dữ liệu.", "▤")
        return
    rows = [{"Thời gian (UTC)": stamp(e.get("timestamp")), "Nguồn": SOURCE_NAMES.get(e.get("source"), e.get("source")),
             "Host": e.get("host") or "—", "Sự kiện": str(e.get("event_id") or "—"),
             "Mô tả": e.get("description", ""), "Evidence ID": e.get("evidence_id", "")} for e in events]
    st.dataframe(rows, hide_index=True, width="stretch", height=height,
                 column_config={"Mô tả": st.column_config.TextColumn(width="large"), "Evidence ID": st.column_config.TextColumn(width="small")}, key=key)


def findings_view(result):
    findings = result.get("findings", [])
    if not findings:
        empty("Chưa có dấu vết đạt điều kiện", "Kết quả này chỉ phản ánh phạm vi dữ liệu đã chọn; chưa đủ để kết luận hệ thống an toàn.")
        return
    left, right = st.columns([1, 2.1], gap="large")
    with left:
        section("Dấu vết phát hiện", "Chọn một dấu vết để xem lý do và bằng chứng.")
        selected = st.radio("Chọn dấu vết", range(len(findings)),
                            format_func=lambda i: f"{LEVELS.get(findings[i]['severity'])} · {FINDING_TITLES.get(findings[i]['rule_id'], findings[i]['title'])}",
                            key=f"finding_{result['investigation_id']}", label_visibility="collapsed")
        st.caption("Mức nguy hiểm phản ánh tác động; độ tin cậy phản ánh sức mạnh bằng chứng.")
    item = findings[selected]
    with right:
        title = FINDING_TITLES.get(item["rule_id"], item["title"])
        note = FINDING_NOTES.get(item["rule_id"], item["severity_reason"])
        st.markdown(f'<div class="finding-card">{badge(item["severity"])}<span class="meta-inline">Độ tin cậy: {esc(CONFIDENCE.get(item["confidence"], item["confidence"]))}</span><h3>{esc(title)}</h3><p>{esc(note)}</p></div>', unsafe_allow_html=True)
        with st.expander("Lý do đánh giá & thông tin kỹ thuật"):
            st.write(item["severity_reason"])
            st.caption(f"{item['agent']} · {item['rule_id']} · {item['classification']}")
        related = [e for e in result.get("evidence", []) if e["evidence_id"] in item.get("evidence_ids", [])]
        section(f"Bằng chứng hỗ trợ · {len(related)}")
        event_table(related, "finding_evidence", 245)
        if item.get("limitations"):
            with st.expander(f"Giới hạn kết luận · {len(item['limitations'])}"):
                for line in item["limitations"]:
                    st.write(f"• {line}")
        for reference in item.get("attack", []):
            st.markdown(f"Kỹ thuật tham chiếu: [{reference['technique_id']} · {reference['name']}]({reference['source']}) · ánh xạ ứng viên")
        with st.expander("Đánh giá lại mức nguy hiểm"):
            with st.form(f"review_{item['id']}"):
                severity = st.selectbox("Mức nguy hiểm sau đánh giá", SEVERITIES, index=SEVERITIES.index(item["severity"]), format_func=LEVELS.get)
                note = st.text_area("Lý do điều chỉnh", placeholder="Ghi rõ ngữ cảnh và bằng chứng hỗ trợ…", max_chars=2000)
                if st.form_submit_button("Lưu đánh giá", type="primary"):
                    if not note.strip():
                        st.warning("Nhập lý do để lưu đánh giá và nhật ký thay đổi.")
                    elif api("PATCH", f"/api/v1/investigations/{result['investigation_id']}/findings/{item['id']}", json={"severity": severity, "note": note.strip()}):
                        refresh_result(result["investigation_id"])
                        st.session_state.notice = "Đã lưu đánh giá mức nguy hiểm."
                        st.rerun()


def recommendations_view(result):
    section("Biện pháp đề xuất", "Một bản hướng xử lý tổng hợp cho toàn bộ cuộc điều tra.")
    plan = result.get("response_plan")
    if not plan:
        # Old investigations remain readable; never call a provider while rendering.
        groups = {}
        for finding in result.get("findings", []):
            for action in finding.get("recommendations", []):
                groups.setdefault(action["phase"], []).append(action)
        steps = []
        for phase, actions in groups.items():
            unique = lambda field: " ".join(dict.fromkeys(a.get(field, "") for a in actions if a.get(field)))
            steps.append({"title": PHASES.get(phase, phase), "action": unique("action"),
                          "condition": unique("condition"), "verification": unique("verification"),
                          "evidence_ids": list(dict.fromkeys(ref for a in actions for ref in a.get("evidence_ids", [])))})
        plan = {"source": "local_playbook", "status": "legacy", "steps": steps,
                "summary": "Kết quả cũ chưa có bản tổng hợp AI. Dưới đây là các biện pháp đã lưu, được gộp để đọc một lần."}
    if plan.get("source") == "ai":
        st.caption(f"AI đề xuất · {str(plan.get('provider', '')).title()} · Bản tổng hợp khi hoàn tất lượt phân tích")
    elif plan.get("status") == "offline":
        st.caption("Playbook tổng hợp · Chế độ Offline không gọi AI")
    elif plan.get("status") != "legacy":
        detail = plan.get("error_message") or plan.get("error") or "Chưa có nhận định AI đầy đủ."
        st.warning(f"{detail} Đang hiển thị playbook thay thế.")
    st.write(plan.get("summary", ""))
    for index, step in enumerate(plan.get("steps", []), 1):
        with st.container(border=True):
            st.markdown(f"**{index}. {step['title']}**")
            st.write(step["action"])
            st.markdown("**Điều kiện áp dụng:** " + step.get("condition", ""))
            st.markdown("**Kiểm tra kết quả:** " + step.get("verification", ""))
            st.caption(f"{len(step.get('evidence_ids', []))} bằng chứng liên quan")
    for line in plan.get("limitations", []):
        st.caption(line)
    st.caption("Đây là đề xuất xử lý. Hệ thống không tự thực thi các thay đổi trên máy hoặc mạng.")


def timeline_view(result):
    timeline = result.get("timeline", [])
    section("Diễn biến theo thời gian", "Các mốc được hiển thị theo UTC. Di chuột lên biểu đồ để xem số sự kiện.")
    if not timeline:
        empty("Chưa có sự kiện trong timeline", "Chọn thêm nguồn log hoặc mở rộng khoảng thời gian.")
        return
    frame = pd.DataFrame(timeline)
    # Sysmon and Zeek may mix whole seconds and fractional seconds in one result.
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], format="ISO8601", utc=True)
    span = (frame.timestamp.max() - frame.timestamp.min()).total_seconds()
    frequency = "1min" if span < 7200 else "1h" if span < 172800 else "1D"
    counts = frame.groupby([pd.Grouper(key="timestamp", freq=frequency), "source"]).size().reset_index(name="Sự kiện")
    counts["UTC"] = counts["timestamp"].dt.strftime("%d/%m/%Y %H:%M")
    chart = alt.Chart(counts).mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
        x=alt.X("timestamp:T", title="Thời gian (UTC)", scale=alt.Scale(type="utc")), y=alt.Y("Sự kiện:Q", title="Số sự kiện", axis=alt.Axis(tickMinStep=1)),
        color=alt.Color("source:N", title="Nguồn", scale=alt.Scale(domain=SOURCES, range=["#2563EB", "#147D64", "#B77900", "#7C3AED"])),
        tooltip=["UTC:N", "source:N", "Sự kiện:Q"],
    ).properties(height=225)
    st.altair_chart(chart_style(chart), width="stretch", theme=None)
    st.caption(f"Độ chia: {dict(zip(['1min', '1h', '1D'], ['1 phút', '1 giờ', '1 ngày']))[frequency]} · {len(timeline)} sự kiện trong kết quả trả về")
    event_table(sorted(timeline, key=lambda e: parsed(e["timestamp"])), "timeline_events", 340)


def relationships_view(result):
    relations = result.get("relationships", [])
    section("Chuỗi liên kết bằng chứng", "Liên kết có khóa đối chiếu được phân biệt với giả thuyết cần xác minh.")
    if not relations:
        empty("Chưa có liên kết đủ điều kiện", "Cần bằng chứng endpoint và mạng trong cùng phạm vi để đối chiếu.", "⇄")
        return
    index = st.selectbox("Liên kết", range(len(relations)), format_func=lambda i: f"{i + 1:02d} · {'Đối chiếu được hỗ trợ' if relations[i]['type'] == 'supported_correlation' else 'Giả thuyết'} · Độ tin cậy {CONFIDENCE.get(relations[i]['confidence'], relations[i]['confidence'])}")
    item = relations[index]
    st.info(item.get("reason", ""))
    st.caption("Khóa đối chiếu: " + json.dumps(item.get("join_keys", {}), ensure_ascii=False))
    evidence = {e["evidence_id"]: e for e in result.get("evidence", [])}
    for identifier in item.get("evidence_ids", [])[:12]:
        event = evidence.get(identifier)
        if event:
            st.markdown(f'<div class="chain-event"><div class="chain-marker">●</div><div><div class="chain-meta">{esc(stamp(event["timestamp"]))} · {esc(SOURCE_NAMES.get(event["source"], event["source"]))}</div><strong>{esc(event.get("description"))}</strong><div class="chain-meta">{esc(event.get("host"))} · {esc(identifier)}</div></div></div>', unsafe_allow_html=True)
        else:
            st.caption(f"Evidence {identifier} · không nằm trong tập bản ghi trả về")
    if len(item.get("evidence_ids", [])) > 12:
        st.caption("Hiển thị 12 mốc đầu; toàn bộ bằng chứng nằm trong báo cáo JSON.")
    for line in item.get("limitations", []):
        st.caption(f"Giới hạn: {line}")


def evidence_view(result):
    left, right = st.columns([2, 1])
    search = left.text_input("Tìm bằng chứng", placeholder="Tên tiến trình, IP, registry, evidence ID…", key="evidence_search")
    sources = right.multiselect("Nguồn log", SOURCES, default=SOURCES, format_func=SOURCE_NAMES.get, key="evidence_sources")
    events = [e for e in result.get("evidence", []) if e["source"] in sources and search.casefold() in json.dumps(e, ensure_ascii=False).casefold()]
    coverage = result.get("coverage", {})
    st.caption(f"Hiển thị {len(events)} / {len(result.get('evidence', []))} bằng chứng trả về · {coverage.get('matching_records', 0):,} bản ghi khớp phạm vi")
    event_table(events, "all_evidence", 340)
    if events:
        event = st.selectbox("Kiểm tra một bản ghi", events, format_func=lambda e: f"{stamp(e['timestamp'], True)} · {e['source']} · {e.get('description', '')[:100]}", key=f"raw_{result['investigation_id']}")
        with st.expander("Bản ghi chuẩn hóa & log gốc", expanded=False):
            one, two = st.columns(2)
            with one:
                section("Đã chuẩn hóa")
                st.json(event.get("normalized", {}), expanded=1)
                st.caption(f"Dataset {event.get('dataset_id')} · Dòng {event.get('record_index')} · {event['evidence_id']}")
            with two:
                section("Log gốc")
                st.json(event.get("raw", {}), expanded=1)
    if result.get("process_tree"):
        with st.expander(f"Quan hệ tiến trình · {len(result['process_tree'])} bản ghi"):
            st.dataframe([{k: n.get(k) for k in ("host", "image", "process_guid", "parent_process_guid", "parent_evidence_ids", "evidence_id")} for n in result["process_tree"]], hide_index=True, width="stretch")
    statistics = [f["statistics"] for f in result.get("findings", []) if f.get("statistics")]
    if statistics:
        with st.expander("Thống kê kết nối định kỳ · beaconing"):
            st.dataframe([{k: v for k, v in item.items() if k != "evidence_ids"} for item in statistics], hide_index=True, width="stretch")


def activity_view(result):
    timings = result.get("timings", {})
    tokens = timings.get("tokens", {})
    kpis([("Thời gian điều tra", ms(timings.get("total_ms")), "Tổng thời gian xử lý", ""),
          ("Lượt gọi mô hình", timings.get("llm_calls", 0), f"Chế độ {result.get('mode')}", ""),
          ("Tokens", f"{sum(v for v in tokens.values() if isinstance(v, (int, float))):,}", "Prompt + completion", "")])
    section("Các agent chuyên trách")
    for item in result.get("assessments", []):
        state = item.get("status", "unknown")
        with st.expander(f"{item.get('agent', 'Agent')} · {'Luật offline' if state == 'offline' else STATUS.get(state, state)}"):
            assessment = item.get("assessment") or {}
            st.write(assessment.get("text") or item.get("error_message") or item.get("error") or "Không có nhận định bổ sung từ mô hình.")
            st.caption("Nhận định của mô hình là giả thuyết; cần đối chiếu với bằng chứng.")
            for limitation in assessment.get("limitations", []):
                st.caption(limitation)
    traces = timings.get("tool_trace", [])
    if traces:
        section("Thời gian thực thi công cụ")
        chart = alt.Chart(pd.DataFrame(traces)).mark_bar(color="#78B8E8", cornerRadiusEnd=3).encode(
            x=alt.X("runtime_ms:Q", title="Thời gian (ms)"), y=alt.Y("tool:N", title=None, sort="-x"),
            tooltip=["agent:N", "tool:N", alt.Tooltip("runtime_ms:Q", format=".2f"), "result_count:Q"],
        ).properties(height=min(320, max(120, len(traces) * 25)))
        st.altair_chart(chart_style(chart), width="stretch", theme=None)
        with st.expander("Chi tiết các lượt gọi công cụ"):
            st.dataframe(traces, hide_index=True, width="stretch")
    with st.expander("Phạm vi, độ bao phủ và kiểm chứng"):
        st.json({"coverage": result.get("coverage"), "verification": result.get("verification"), "plan": result.get("plan"), "tokens": tokens})


def reports_view(result):
    identifier = result["investigation_id"]
    section("Xuất kết quả điều tra", "Báo cáo giữ nguyên bằng chứng, giới hạn kết luận và các đánh giá đã lưu.")
    left, right = st.columns(2)
    with left, st.container(border=True):
        section("Báo cáo Markdown", "Dễ đọc, phù hợp đưa vào hồ sơ hoặc tài liệu đồ án.")
        key = f"markdown_{identifier}"
        if key not in st.session_state:
            text = api("GET", f"/api/v1/investigations/{identifier}/report", params={"format": "markdown"})
            if text is not None:
                st.session_state[key] = text
        if key in st.session_state:
            st.download_button("↓ Tải Markdown", st.session_state[key], f"investigation-{identifier[:8]}.md", mime="text/markdown", width="stretch")
    with right, st.container(border=True):
        section("Dữ liệu JSON", "Toàn bộ kết quả có cấu trúc để kiểm tra và tái sử dụng.")
        st.download_button("↓ Tải JSON", json.dumps(result, ensure_ascii=False, indent=2), f"investigation-{identifier[:8]}.json", mime="application/json", width="stretch")
    with st.expander("Nhật ký đánh giá và xử lý"):
        if st.checkbox("Tải nhật ký thay đổi", key=f"audit_{identifier}"):
            entries = api("GET", f"/api/v1/investigations/{identifier}/audit") or []
            if entries:
                st.dataframe(entries, hide_index=True, width="stretch")
            else:
                st.caption("Chưa có đánh giá hoặc cập nhật biện pháp.")


def results_view(result):
    if not result:
        return
    st.divider()
    scope = result.get("scope", {})
    severity = result.get("risk", {}).get("severity", "unknown")
    st.markdown(f'<div class="result-heading"><div><div class="overline">KẾT QUẢ ĐIỀU TRA · {esc(result["investigation_id"][:8])}</div><h2>{esc(scope.get("host") or scope.get("ip") or "Phân tích phạm vi đã chọn")}</h2><div class="section-note">{esc(stamp(scope.get("start_time")))} → {esc(stamp(scope.get("end_time")))}</div></div>{badge(severity)}</div>', unsafe_allow_html=True)
    st.caption(f"{len(result.get('dataset_ids', []))} tệp log · {STATUS.get(result.get('status'), result.get('status'))}")
    kpis([("Mức nguy hiểm", LEVELS.get(severity, severity), "Đánh giá tổng hợp trong phạm vi", severity),
          ("Dấu vết", len(result.get("findings", [])), f"{len(result.get('relationships', []))} liên kết bằng chứng", ""),
          ("Bằng chứng", len(result.get("evidence", [])), f"{result.get('coverage', {}).get('matching_records', 0):,} bản ghi khớp phạm vi", "")])
    with st.expander("Tóm tắt kết luận & giới hạn", expanded=bool(result.get("warnings"))):
        st.write(result.get("summary", ""))
        st.caption(result.get("risk", {}).get("reason", ""))
        for warning in result.get("warnings", []):
            st.warning(warning)
    # Warnings remain visible even when the summary is collapsed.
    if result.get("coverage", {}).get("truncated"):
        st.warning("Chỉ một phần log được phân tích. Mở thông tin kỹ thuật để kiểm tra độ bao phủ.")
    tabs = st.tabs(["Kết quả", "Diễn biến", "Bằng chứng", "Báo cáo"])
    with tabs[0]:
        findings_view(result)
        st.divider()
        recommendations_view(result)
    with tabs[1]:
        timeline_view(result)
        with st.expander("Xem liên kết giữa các nguồn log"):
            relationships_view(result)
    with tabs[2]:
        evidence_view(result)
        with st.expander("Thông tin kỹ thuật & hoạt động AI"):
            activity_view(result)
    with tabs[3]:
        reports_view(result)


def job_rows(jobs):
    return [{"Tạo lúc (UTC)": stamp(j.get("created_at"), True), "Đối tượng": j.get("scope", {}).get("host") or j.get("scope", {}).get("ip") or "Toàn phạm vi",
             "Trạng thái": STATUS.get(j["status"], j["status"]), "Mức nguy hiểm": LEVELS.get(j.get("severity"), "—"),
             "Mã điều tra": j["investigation_id"][:8]} for j in jobs]


def job_label(job):
    scope = job.get("scope", {})
    return f"{stamp(job.get('created_at'), True)} · {scope.get('host') or scope.get('ip') or 'Toàn phạm vi'} · {STATUS.get(job['status'], job['status'])} · {job['investigation_id'][:8]}"


def dashboard():
    metrics = api("GET", "/api/v1/metrics")
    if not metrics:
        return
    alerts = api("GET", "/api/v1/alerts", params={"limit": 500}) or []
    jobs = api("GET", "/api/v1/investigations", params={"limit": 200}) or []
    active = sum(metrics["investigations"].get(state, 0) for state in ("running", "queued"))
    kpis([("Tệp log đã nhập", f"{metrics['datasets']:,}", f"{metrics['events']:,} bản ghi", ""),
          ("Cảnh báo mới", metrics["alerts"].get("new", 0), "Cần xem và xác minh", "high" if metrics["alerts"].get("new") else ""),
          ("Đang phân tích", active, "Gồm cả các lượt đang chờ", "")])
    section("Bắt đầu với 3 bước")
    for col, number, title, note, label, action in zip(
        st.columns(3), [1, 2, 3], ["Nhập log", "Phân tích", "Xem kết quả"],
        ["Thêm tệp Sysmon hoặc Zeek.", "Chọn dữ liệu cần kiểm tra.", "Mở lại kết quả và tải báo cáo."],
        ["Thêm tệp log", "Phân tích mới", "Mở lịch sử"], ["Datasets", "Điều tra", "Lịch sử & báo cáo"],
    ):
        with col, st.container(border=True):
            st.markdown(f'<div class="workflow-step"><span class="step-number">{number}</span>{title}</div>', unsafe_allow_html=True)
            st.caption(note)
            if action == "Điều tra":
                st.button(label, on_click=new_investigation, type="primary", key="dashboard_new", width="stretch")
            else:
                st.button(label, on_click=navigate, args=(action,), width="stretch")
    left, right = st.columns([1.6, 1], gap="medium")
    with left, st.container(border=True):
        section("Cảnh báo cần xem")
        pending = sorted([a for a in alerts if a["status"] != "closed"],
                         key=lambda a: SEVERITIES.index(a["severity"]) if a["severity"] in SEVERITIES else 99)[:4]
        if not pending:
            empty("Chưa có cảnh báo cần xử lý", "Cảnh báo từ các lượt phân tích sẽ xuất hiện ở đây.", "✓")
        for alert in pending:
            one, two = st.columns([3, 1.3], vertical_alignment="center")
            one.markdown(f'<div class="alert-row">{badge(alert["severity"])}<strong>Điều tra {esc(alert["investigation_id"][:8])}</strong><div class="chain-meta">{esc(STATUS.get(alert["status"]))} · {esc(stamp(alert.get("alert_created_at"), True))}</div></div>', unsafe_allow_html=True)
            two.button("Xem", key=f"dash_{alert['alert_id']}", on_click=open_job, args=(alert["investigation_id"], "Lịch sử & báo cáo"), width="stretch")
        st.caption("Tối đa 4 cảnh báo ưu tiên, từ 500 cảnh báo gần nhất.")
    with right, st.container(border=True):
        section("Mức độ cảnh báo")
        levels = metrics.get("severity", {})
        total = sum(levels.values())
        if total:
            for level in SEVERITIES:
                count = levels.get(level, 0)
                if count:
                    st.markdown(f'<div class="severity-row"><div><span>{esc(LEVELS[level])}</span><strong>{count}</strong></div><div class="severity-track"><div style="width:{count / total * 100:.2f}%;background:{COLORS[level]}"></div></div></div>', unsafe_allow_html=True)
            st.caption("Tất cả cảnh báo, gồm cả đã đóng.")
        else:
            st.caption("Chưa có dữ liệu để thống kê.")
    section("Phân tích gần đây")
    if jobs:
        st.dataframe(job_rows(jobs[:5]), hide_index=True, width="stretch")
        st.button("Xem toàn bộ lịch sử →", on_click=navigate, args=("Lịch sử & báo cáo",))
    else:
        empty("Chưa có kết quả", "Thêm tệp log và bắt đầu lượt phân tích đầu tiên.")
    with st.expander("Hiệu năng hệ thống"):
        a, b = st.columns(2)
        a.metric("Tạo cảnh báo · p95", ms(metrics["detection_to_alert"].get("p95_ms")))
        b.metric("Thời gian phân tích · p95", ms(metrics["runtime"].get("p95_ms")))
        st.caption(f"Độ trễ đo đến khi server tạo cảnh báo · {metrics['detection_to_alert']['samples']} mẫu. Không gồm thời gian hiển thị trên trình duyệt.")


def datasets_page():
    with st.expander("Thêm tệp log", expanded=True):
        with st.form("upload", clear_on_submit=True):
            left, right = st.columns([1, 2])
            with left:
                source = st.selectbox("Loại log", SOURCES, format_func=SOURCE_NAMES.get)
                st.caption("Sysmon: XML / JSONL\n\nZeek: JSONL / TSV (conn, dns, http)\n\nMỗi tệp tương ứng một nguồn log.")
            with right:
                uploaded = st.file_uploader("Kéo thả tệp log vào đây", type=["jsonl", "json", "xml", "log", "tsv"])
                submitted = st.form_submit_button("Nhập & kiểm tra dữ liệu", type="primary")
        if submitted:
            if not uploaded:
                st.warning("Chọn một tệp log trước khi nhập.")
            else:
                with st.spinner("Đang nhập và kiểm tra log…"):
                    result = api("POST", "/api/v1/logs/upload", data={"source_type": source}, files={"file": (uploaded.name, uploaded.getvalue())})
                if result:
                    st.success(f"Đã nhập {result['imported_records']:,} bản ghi từ {uploaded.name}.")
                    with st.expander("Chi tiết kiểm tra tệp"):
                        st.json(result)
    section("Kho dữ liệu", "Kiểm tra nguồn log và khoảng thời gian trước khi điều tra.")
    items = api("GET", "/api/v1/datasets", params={"limit": 101, "offset": st.session_state.get("datasets_page", 0) * 100}) or []
    left, right = st.columns([2, 1])
    query = left.text_input("Tìm dataset", placeholder="Tên tệp, host, IP…")
    source_filter = right.selectbox("Lọc theo nguồn", ["all"] + SOURCES, format_func=lambda s: "Tất cả nguồn" if s == "all" else SOURCE_NAMES[s])
    datasets = [d for d in items[:100] if (source_filter == "all" or d["source"] == source_filter) and query.casefold() in json.dumps(d, ensure_ascii=False).casefold()]
    if datasets:
        st.dataframe([{"Tên tệp": d["filename"], "Nguồn": SOURCE_NAMES.get(d["source"], d["source"]), "Bản ghi": d["total_records"], "Bắt đầu (UTC)": stamp(d.get("metadata", {}).get("start_time"), True), "Kết thúc (UTC)": stamp(d.get("metadata", {}).get("end_time"), True), "Nhập lúc (UTC)": stamp(d.get("created_at"), True)} for d in datasets], hide_index=True, width="stretch")
        d = st.selectbox("Xem thông tin tệp", datasets, format_func=lambda d: f"{d['filename']} · {d['dataset_id'][:8]}")
        with st.expander("Phạm vi & nguồn gốc dữ liệu"):
            meta = d.get("metadata", {})
            a, b = st.columns(2)
            a.write(f"**Hosts:** {', '.join(meta.get('hosts', [])) or '—'}")
            b.write(f"**IPs:** {', '.join(meta.get('ips', [])) or '—'}")
            st.caption(f"Dataset ID: {d['dataset_id']} · SHA-256: {d.get('sha256', '—')}")
            st.json(meta, expanded=1)
    else:
        empty("Chưa có dataset phù hợp", "Nhập log mới hoặc thay đổi bộ lọc.", "▤")
    pagination("datasets_page", len(items) > 100)


def scope_defaults(datasets):
    now = datetime.now(timezone.utc)
    starts = [parsed(d["metadata"]["start_time"]) for d in datasets if d.get("metadata", {}).get("start_time")]
    ends = [parsed(d["metadata"]["end_time"]) for d in datasets if d.get("metadata", {}).get("end_time")]
    start = min(starts, default=now - timedelta(hours=1)).replace(second=0, microsecond=0)
    end = max(ends, default=now)
    end = end.replace(second=0, microsecond=0) + (timedelta(minutes=1) if end.second or end.microsecond else timedelta())
    return start, end


def investigation_page():
    datasets = api("GET", "/api/v1/datasets?limit=1000") or []
    if not datasets:
        empty("Cần dữ liệu để bắt đầu", "Nhập log Sysmon hoặc Zeek vào kho dữ liệu, sau đó chọn phạm vi phân tích.")
        st.button("Đến kho dữ liệu →", on_click=navigate, args=("Datasets",), type="primary")
    else:
        with st.expander("Thiết lập cuộc điều tra", expanded=not bool(st.session_state.get("active_job"))):
            main, aside = st.columns([2.2, 1], gap="large")
            with main:
                section("1. Chọn tệp log")
                lookup = {d["dataset_id"]: d for d in datasets}
                selected = st.multiselect("Tệp log cần phân tích", list(lookup), format_func=lambda i: f"{lookup[i]['filename']} · {SOURCE_NAMES.get(lookup[i]['source'])}", max_selections=20, key="scope_datasets", placeholder="Chọn một hoặc nhiều tệp log…")
                chosen = [lookup[i] for i in selected]
                signature = tuple(sorted(selected))
                if st.session_state.get("scope_signature") != signature or "start_date" not in st.session_state:
                    start, end = scope_defaults(chosen or datasets)
                    for key, value in {"start_date": start.date(), "start_clock": start.time().replace(tzinfo=None), "end_date": end.date(), "end_clock": end.time().replace(tzinfo=None)}.items():
                        st.session_state[key] = value
                    st.session_state.scope_signature = signature
                with st.form("investigation"):
                    with st.expander("Chọn máy & thời gian cụ thể (tùy chọn)"):
                        a, b = st.columns(2)
                        host = a.text_input("Host", placeholder="WIN-LAB-01", key="scope_host", max_chars=128)
                        ip = b.text_input("IP của host", placeholder="192.0.2.10", key="scope_ip")
                        mapping = st.checkbox("Xác nhận host và IP này thuộc cùng thiết bị trong thời gian đã chọn", value=False, key="scope_mapping", help="Ánh xạ đã xác minh giúp đối chiếu Sysmon với log mạng Zeek. Chỉ chọn khi bạn biết quan hệ host–IP này.")
                        a, b, c, d = st.columns(4)
                        start_date = a.date_input("Ngày bắt đầu · UTC", key="start_date")
                        start_time = b.time_input("Giờ bắt đầu · UTC", key="start_clock", step=60)
                        end_date = c.date_input("Ngày kết thúc · UTC", key="end_date")
                        end_time = d.time_input("Giờ kết thúc · UTC", key="end_clock", step=60)
                    section("2. Cách phân tích")
                    mode = st.selectbox("Chế độ", ["offline", "gemini", "deepseek"], format_func=lambda m: {"offline": "Offline · Luật & thống kê", "gemini": "Gemini · AI hỗ trợ", "deepseek": "DeepSeek · AI hỗ trợ"}[m], key="scope_mode")
                    with st.expander("Tùy chọn nâng cao"):
                        strategy = st.selectbox("Chiến lược", ["multi_agent", "single_agent", "heuristic"], format_func=lambda m: {"multi_agent": "Multi-agent · Chuyên trách phối hợp", "single_agent": "Single-agent · Một agent", "heuristic": "Heuristic · Chỉ luật & thống kê"}[m], key="scope_strategy")
                        criticality = st.selectbox("Mức quan trọng của tài sản", ["medium", "low", "high"], format_func=CONFIDENCE.get, key="scope_criticality")
                        benign = st.text_input("IP đích đã biết hợp lệ", placeholder="Phân cách bằng dấu phẩy, ví dụ 192.0.2.20, 192.0.2.21", key="scope_benign")
                        mappings = st.text_area("Ánh xạ host–IP bổ sung · JSON", value="[]", key="scope_extra_mappings", help="Danh sách đối tượng có host, ip, start_time, end_time (ISO 8601 có timezone). Dùng khi có nhiều thiết bị hoặc IP thay đổi theo thời gian.")
                    submitted = st.form_submit_button("Bắt đầu điều tra", type="primary", width="stretch")
            with aside:
                with st.container(border=True):
                    section("Dữ liệu sẽ phân tích")
                    st.metric("Tệp log", len(selected))
                    st.metric("Bản ghi trong các tệp", f"{sum(d['total_records'] for d in chosen):,}")
                    st.caption("Mặc định lấy toàn bộ thời gian của các tệp đã chọn. Mở phần chọn máy và thời gian nếu cần thu hẹp.")
                    st.divider()
                    sources = list(dict.fromkeys(d["source"] for d in chosen))
                    for source in sources:
                        st.write(f"✓ {SOURCE_NAMES.get(source, source)}")
                    if not sources:
                        st.caption("Chưa chọn nguồn log.")
                st.caption("Offline chạy bằng luật và thống kê. Chế độ AI sử dụng nhà cung cấp đã cấu hình và có thể phát sinh chi phí API.")

            if submitted:
                try:
                    start = datetime.combine(start_date, start_time, tzinfo=timezone.utc)
                    end = datetime.combine(end_date, end_time, tzinfo=timezone.utc)
                    if not selected:
                        raise ValueError("Chọn ít nhất một dataset để điều tra.")
                    if start > end:
                        raise ValueError("Thời gian bắt đầu phải trước hoặc bằng thời gian kết thúc.")
                    if ip.strip():
                        ipaddress.ip_address(ip.strip())
                    extra = json.loads(mappings)
                    if not isinstance(extra, list):
                        raise ValueError("Ánh xạ bổ sung cần là một danh sách JSON.")
                    if mapping:
                        if not host.strip() or not ip.strip():
                            raise ValueError("Cần cả host và IP để xác nhận ánh xạ thiết bị.")
                        extra.append({"host": host.strip(), "ip": ip.strip(), "start_time": start.isoformat(), "end_time": end.isoformat()})
                    benign_ips = [str(ipaddress.ip_address(s.strip())) for s in benign.split(",") if s.strip()]
                    payload = {"dataset_ids": selected, "host": host.strip() or None, "ip": ip.strip() or None, "start_time": start.isoformat(), "end_time": end.isoformat(), "mode": mode, "strategy": strategy, "asset_criticality": criticality, "host_mappings": extra, "benign_destinations": benign_ips}
                    job = api("POST", "/api/v1/investigations", json=payload)
                    if job:
                        open_job(job["investigation_id"])
                        st.rerun()
                except ValueError as exc:
                    st.error(f"Kiểm tra lại phạm vi: {exc}")
    job_panel()
    results_view(st.session_state.get("last_result"))


def alerts_page():
    a, b = st.columns([1, 2])
    state = a.selectbox("Trạng thái cảnh báo", ["all", "new", "acknowledged", "investigating", "closed"], format_func=lambda s: "Tất cả trạng thái" if s == "all" else STATUS[s])
    if st.session_state.get("previous_alert_filter") != state:
        st.session_state.alerts_page = 0
        st.session_state.previous_alert_filter = state
    levels = b.multiselect("Mức nguy hiểm", SEVERITIES, format_func=LEVELS.get, placeholder="Tất cả mức nguy hiểm")
    params = {"limit": 101, "offset": st.session_state.get("alerts_page", 0) * 100}
    if state != "all":
        params["status"] = state
    items = api("GET", "/api/v1/alerts", params=params) or []
    alerts = [a for a in items[:100] if not levels or a["severity"] in levels]
    if alerts:
        st.dataframe([{"Mức nguy hiểm": LEVELS.get(a["severity"]), "Trạng thái": STATUS.get(a["status"]), "Độ tin cậy": CONFIDENCE.get(a["confidence"], a["confidence"]), "Tạo lúc (UTC)": stamp(a.get("alert_created_at"), True), "Phát hiện → cảnh báo": ms(a.get("detection_to_alert_ms")), "Mã điều tra": a["investigation_id"][:8]} for a in alerts], hide_index=True, width="stretch")
        item = st.selectbox("Xử lý cảnh báo", alerts, format_func=lambda a: f"{LEVELS[a['severity']]} · {stamp(a.get('alert_created_at'), True)} · Điều tra {a['investigation_id'][:8]}")
        left, right = st.columns([1.5, 1], gap="large")
        with left, st.container(border=True):
            st.markdown(f"**Điều tra {item['investigation_id'][:8]}** · {STATUS[item['status']]}")
            with st.form(f"alert_review_{item['alert_id']}_{item['status']}"):
                statuses = ["new", "acknowledged", "investigating", "closed"]
                state = st.selectbox("Chuyển trạng thái", statuses, index=statuses.index(item["status"]), format_func=STATUS.get)
                note = st.text_area("Ghi chú xử lý cảnh báo", placeholder="Lý do chuyển trạng thái và kết quả đã xác minh…", max_chars=2000)
                if st.form_submit_button("Lưu trạng thái", type="primary"):
                    if not note.strip():
                        st.warning("Nhập ghi chú để lưu trạng thái cảnh báo.")
                    elif api("PATCH", f"/api/v1/alerts/{item['alert_id']}", json={"status": state, "note": note.strip()}):
                        st.session_state.notice = "Đã cập nhật trạng thái cảnh báo."
                        st.rerun()
        with right:
            section("Đối chiếu trước khi xử lý")
            st.caption(f"Phát hiện: {stamp(item.get('detected_at'))}\n\nTạo cảnh báo: {stamp(item.get('alert_created_at'))}")
            st.button("Mở kết quả điều tra →", type="primary", on_click=open_job, args=(item["investigation_id"], "Lịch sử & báo cáo"), width="stretch")
            with st.expander("Lịch sử trạng thái"):
                if item.get("history"):
                    st.dataframe(item["history"], hide_index=True, width="stretch")
                else:
                    st.caption("Chưa có thay đổi trạng thái.")
    else:
        empty("Không có cảnh báo phù hợp", "Thử thay đổi bộ lọc hoặc chạy điều tra trên dữ liệu đã nhập.", "△")
    pagination("alerts_page", len(items) > 100)


def history_page():
    items = api("GET", "/api/v1/investigations", params={"limit": 51, "offset": st.session_state.get("history_page", 0) * 50}) or []
    a, b = st.columns([2, 1])
    query = a.text_input("Tìm cuộc điều tra", placeholder="Host, IP hoặc mã điều tra…")
    state = b.selectbox("Trạng thái điều tra", ["all", "completed", "running", "queued", "failed", "cancelled"], format_func=lambda s: "Tất cả trạng thái" if s == "all" else STATUS[s])
    jobs = [j for j in items[:50] if (state == "all" or j["status"] == state) and query.casefold() in json.dumps(j, ensure_ascii=False).casefold()]
    if jobs:
        st.dataframe(job_rows(jobs), hide_index=True, width="stretch")
        left, right = st.columns([3, 1], vertical_alignment="bottom")
        job = left.selectbox("Chọn cuộc điều tra", jobs, format_func=job_label)
        right.button("Mở kết quả →", type="primary", on_click=open_job, args=(job["investigation_id"],), width="stretch")
    else:
        empty("Không tìm thấy cuộc điều tra", "Thử thay đổi bộ lọc hoặc tạo một cuộc điều tra mới.", "◷")
    pagination("history_page", len(items) > 50)
    job_panel()
    results_view(st.session_state.get("last_result"))


def knowledge_page(health):
    left, right = st.columns([2, 1], gap="large")
    with left:
        section("Thư viện MITRE ATT&CK", "Các kỹ thuật trong corpus đã tuyển chọn phục vụ Persistence và C2.")
        query = st.text_input("Tìm kỹ thuật ATT&CK", value="persistence c2", placeholder="Tên kỹ thuật, ID hoặc hành vi…")
        knowledge = api("GET", "/api/v1/knowledge", params={"query": query})
        if knowledge:
            st.caption(f"{len(knowledge['results'])} kết quả · Corpus {knowledge['version']} · Ánh xạ kỹ thuật là ứng viên cần kiểm chứng")
            for record in knowledge["results"]:
                with st.container(border=True):
                    st.markdown(f"**{record['technique_id']} · {record['name']}**")
                    st.write(record["summary"])
                    st.link_button("Tham chiếu MITRE ↗", record["source"])
            if not knowledge["results"]:
                empty("Chưa có kỹ thuật phù hợp", "Thử tìm bằng mã kỹ thuật hoặc tên hành vi.", "◇")
    with right, st.container(border=True):
        section("Trạng thái hệ thống")
        if health:
            for label, value in [("API", "Sẵn sàng" if health.get("status") == "healthy" else health.get("status")), ("Cơ sở dữ liệu", health.get("database")), ("Provider mặc định", health.get("mode")), ("Worker điều tra", "Đang bật" if health.get("worker_enabled") else "Đang tắt")]:
                st.markdown(f"**{label}**")
                st.caption(str(value))
        else:
            st.error("Không kết nối được API.")
        st.divider()
        st.caption("Tất cả thời gian hiển thị theo UTC. Khóa API và giới hạn sử dụng được quản lý trên backend.")
        with st.expander("Thông tin kỹ thuật"):
            st.json(health or {})


health = api("GET", "/health", timeout=5)
with st.sidebar:
    st.markdown('<div class="brand"><div class="brand-mark">◈</div><div><strong>Phân tích log</strong><span>Sysmon & Zeek</span></div></div>', unsafe_allow_html=True)
    page = st.radio("Điều hướng", PAGES, format_func=PAGE_LABELS.get, label_visibility="collapsed", key="nav")
    st.divider()
    ready = bool(health and health.get("status") == "healthy")
    st.markdown(f'<div class="connection"><span class="connection-dot {"online" if ready else "offline"}"></span>{"API đang hoạt động" if ready else "API chưa sẵn sàng"}</div>', unsafe_allow_html=True)
    if st.session_state.get("active_job"):
        st.caption(f"Điều tra đang mở · {st.session_state.active_job[:8]}")
    st.caption("Thời gian hiển thị theo UTC")

header, actions = st.columns([3, 1.5], vertical_alignment="center")
with header:
    st.title(PAGE_LABELS[page])
    st.caption(DESCRIPTIONS[page])
with actions:
    st.button("Phân tích mới", type="primary", width="stretch", on_click=new_investigation, key="header_new")
if st.session_state.get("notice"):
    st.toast(st.session_state.pop("notice"), icon=":material/check_circle:")

if page == "Tổng quan":
    dashboard()
elif page == "Datasets":
    datasets_page()
elif page == "Điều tra":
    investigation_page()
elif page == "Cảnh báo":
    alerts_page()
elif page == "Lịch sử & báo cáo":
    history_page()
else:
    knowledge_page(health)
