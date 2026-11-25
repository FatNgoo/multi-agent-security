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

import import_ui
import overview_ui

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")
SOURCES = list(overview_ui.SOURCE_NAMES)
SOURCE_NAMES = overview_ui.SOURCE_NAMES
SEVERITIES = ["critical", "high", "medium", "low", "informational", "unknown"]
LEVELS = dict(zip(SEVERITIES, ["Nghiêm trọng", "Cao", "Trung bình", "Thấp", "Thông tin", "Chưa xác định"]))
STATUS = {"new": "Mới", "acknowledged": "Đã tiếp nhận", "investigating": "Đang xử lý", "closed": "Đã đóng",
          "queued": "Đang chờ", "running": "Đang điều tra", "completed": "Hoàn thành", "failed": "Thất bại",
          "cancelled": "Đã hủy", "cancel_requested": "Đang hủy", "pending": "Chưa thực hiện", "in_progress": "Đang thực hiện", "skipped": "Bỏ qua"}
STATUS.update({"unavailable": "Chưa hoàn tất", "llm_budget_exhausted": "Hết ngân sách AI",
               "iteration_limit": "Chưa đủ lượt xử lý", "insufficient_evidence": "Chưa đủ bằng chứng"})
CONFIDENCE = {"high": "Cao", "medium": "Trung bình", "low": "Thấp"}
PHASES = {"verify": "Xác minh", "preserve": "Bảo toàn bằng chứng", "contain": "Cô lập", "remediate": "Khắc phục", "recover": "Khôi phục", "monitor": "Giám sát"}
PAGES = ["Tổng quan", "Nhập log", "Phân tích", "Theo dõi"]
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
WARNINGS = {
    "Insufficient evidence: no records match the requested scope.": "Không có bản ghi khớp với phạm vi đã chọn.",
    "Evidence coverage is partial: record limit reached. Narrow the time window or datasets.": "Đã chạm giới hạn bản ghi. Hãy thu hẹp thời gian hoặc chọn ít tệp hơn.",
    "Relationship presentation reached its 500-link cap; narrow the investigation scope.": "Đã chạm giới hạn 500 liên kết. Hãy thu hẹp phạm vi.",
    "Host scope has no explicit IP mapping. Zeek events cannot be attributed to this host.": "Thiếu ánh xạ máy và IP để đối chiếu log Zeek.",
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
    navigate("Phân tích")


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
    if not page_number and not has_more:
        return
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
            st.caption(f"Bắt đầu lúc {stamp(job.get('created_at'))}")
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
        st.caption("Chưa thấy dấu vết đạt ngưỡng trong các bản ghi đã phân tích.")
        return
    with st.expander("Xem dấu vết và bằng chứng"):
        selected = 0
        if len(findings) > 1:
            selected = st.selectbox("Dấu vết", range(len(findings)),
                                    format_func=lambda i: FINDING_TITLES.get(findings[i]["rule_id"], findings[i]["title"]),
                                    key=f"finding_{result['investigation_id']}")
        item = findings[selected]
        title = FINDING_TITLES.get(item["rule_id"], item["title"])
        note = FINDING_NOTES.get(item["rule_id"], item["severity_reason"])
        st.markdown(f'<div class="finding-card">{badge(item["severity"])}<span class="meta-inline">Độ tin cậy {esc(CONFIDENCE.get(item["confidence"], item["confidence"]))}</span><h3>{esc(title)}</h3><p>{esc(note)}</p></div>', unsafe_allow_html=True)
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
    section("Biện pháp đề xuất")
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
        st.caption(f"AI đề xuất · {str(plan.get('provider', '')).title()}")
    elif plan.get("status") == "offline":
        st.caption("Hướng dẫn cục bộ · Chế độ Offline")
    elif plan.get("status") != "legacy":
        detail = plan.get("error_message") or plan.get("error") or "Chưa có nhận định AI đầy đủ."
        st.warning(f"{detail} Đang hiển thị playbook thay thế.")
    st.write(plan.get("summary", ""))
    steps = plan.get("steps", [])
    for index, step in enumerate(steps, 1):
        st.markdown(f'<div class="plan-step"><span>{index}</span><div><strong>{esc(step["title"])}</strong><p>{esc(step["action"])}</p><small>{esc(step.get("condition", ""))}</small></div></div>', unsafe_allow_html=True)
    evidence = {e["evidence_id"]: e for e in result.get("evidence", [])}
    if steps or plan.get("limitations"):
        with st.expander("Kiểm tra kết quả và đối chiếu bằng chứng"):
            for step in steps:
                st.markdown(f"**{step['title']}**")
                st.write(step.get("verification", ""))
                for ref in dict.fromkeys(step.get("evidence_ids", [])):
                    event = evidence.get(ref, {})
                    st.caption(f"{SOURCE_NAMES.get(event.get('source'), 'Bằng chứng')} · {stamp(event.get('timestamp'), True)} · {ref}")
            for line in plan.get("limitations", []):
                st.caption(line)


def timeline_view(result, show_table=True):
    timeline = result.get("timeline", [])
    section("Diễn biến theo nguồn log")
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
    present = [source for source in SOURCES if source in set(counts["source"])]
    counts["Nguồn"] = counts["source"].map(SOURCE_NAMES)
    chart = alt.Chart(counts).mark_bar(size=14 if len(counts) <= 40 else 5, cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
        x=alt.X("timestamp:T", title="Thời gian (UTC)", scale=alt.Scale(type="utc"),
                axis=alt.Axis(tickCount=5, format="%H:%M" if span < 86400 else "%d/%m", labelOverlap=True)), y=alt.Y("Sự kiện:Q", title="Số sự kiện", axis=alt.Axis(tickMinStep=1)),
        color=alt.Color("Nguồn:N", title=None, scale=alt.Scale(domain=[SOURCE_NAMES[key] for key in present], range=[SOURCE_COLORS[key] for key in present])),
        tooltip=["UTC:N", "Nguồn:N", "Sự kiện:Q"],
    ).properties(height=225)
    st.altair_chart(chart_style(chart), width="stretch", theme=None)
    st.caption(f"Độ chia: {dict(zip(['1min', '1h', '1D'], ['1 phút', '1 giờ', '1 ngày']))[frequency]} · {len(timeline)} sự kiện trong kết quả trả về")
    if show_table:
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
    scope = result.get("scope", {})
    severity = result.get("risk", {}).get("severity", "unknown")
    findings = result.get("findings", [])
    evidence = result.get("evidence", [])
    sources = {e["source"] for e in evidence}
    host = scope.get("host") or scope.get("ip") or f"{len(result.get('dataset_ids') or [result.get('dataset_id')])} tệp log"
    st.markdown(f'<div class="result-heading"><h2>{esc(host)}</h2><span>Mức ưu tiên {badge(severity)}</span></div>', unsafe_allow_html=True)
    st.caption(f"{len(evidence)} bản ghi · {stamp(scope.get('start_time'), True)} → {stamp(scope.get('end_time'), True)} UTC")
    for warning in result.get("warnings", []):
        if warning != "OFFLINE: deterministic investigation; no LLM was called.":
            st.warning(WARNINGS.get(warning, warning))
    tabs = st.tabs(["Nhận định", "Bằng chứng", "Báo cáo"])
    with tabs[0]:
        observations = []
        for agent, title, has_source in [
            ("persistence", "Duy trì truy cập", "sysmon" in sources),
            ("c2", "Dấu hiệu C2", any(s.startswith("zeek_") for s in sources)),
        ]:
            titles = dict.fromkeys(FINDING_TITLES.get(f["rule_id"], f["title"]) for f in findings if f.get("agent") == agent)
            count = sum(f.get("agent") == agent for f in findings)
            observations.append((title, f"{count} dấu vết" if has_source else "Thiếu log", " · ".join(titles) or ("Chưa thấy dấu hiệu" if has_source else "Trong phạm vi đã chọn")))
        links = result.get("relationships", [])
        matched = sum(link["type"] == "supported_correlation" for link in links)
        hypotheses = sum(link["type"] == "hypothesis" for link in links)
        link_text = " · ".join(filter(None, [f"{matched} liên kết có bằng chứng" if matched else "", f"{hypotheses} giả thuyết" if hypotheses else ""]))
        observations.append(("Đối chiếu hai nguồn", f"{len(links)} liên kết", link_text or "Chưa tìm thấy liên kết"))
        with st.container(key="observations"):
            for col, (title, value, detail) in zip(st.columns(3), observations):
                col.markdown(f'<div class="observation"><strong>{esc(title)}</strong><b>{esc(value)}</b><p>{esc(detail)}</p></div>', unsafe_allow_html=True)
        if result.get("timeline"):
            with st.container(border=True):
                timeline_view(result, show_table=False)
        findings_view(result)
        recommendations_view(result)
    with tabs[1]:
        evidence_view(result)
        with st.expander("Diễn biến theo thời gian"):
            event_table(sorted(result.get("timeline", []), key=lambda e: parsed(e["timestamp"])), "timeline_events", 340)
        with st.expander("Liên kết Sysmon và Zeek"):
            relationships_view(result)
        with st.expander("Thông tin kỹ thuật & hoạt động AI"):
            st.write(result.get("summary", ""))
            st.caption(result.get("risk", {}).get("reason", ""))
            activity_view(result)
    with tabs[2]:
        reports_view(result)


def job_rows(jobs):
    return [{"Tạo lúc (UTC)": stamp(j.get("created_at"), True), "Đối tượng": j.get("scope", {}).get("host") or j.get("scope", {}).get("ip") or "Toàn phạm vi",
             "Trạng thái": STATUS.get(j["status"], j["status"]), "Mức nguy hiểm": LEVELS.get(j.get("severity"), "—"),
             "Mã điều tra": j["investigation_id"][:8]} for j in jobs]


def job_label(job):
    scope = job.get("scope", {})
    return f"{stamp(job.get('created_at'), True)} · {scope.get('host') or scope.get('ip') or 'Toàn phạm vi'} · {STATUS.get(job['status'], job['status'])} · {job['investigation_id'][:8]}"


def metrics_view():
    metrics = api("GET", "/api/v1/metrics")
    if metrics:
        kpis([("Tệp log", metrics["datasets"], f"{metrics['events']:,} bản ghi", ""),
              ("Cảnh báo mới", metrics["alerts"].get("new", 0), "Chờ tiếp nhận", ""),
              ("Đang phân tích", sum(metrics["investigations"].get(s, 0) for s in ("running", "queued")), "Gồm lượt đang chờ", "")])
        a, b = st.columns(2)
        a.metric("Tạo cảnh báo · p95", ms(metrics["detection_to_alert"].get("p95_ms")))
        b.metric("Thời gian phân tích · p95", ms(metrics["runtime"].get("p95_ms")))


def analyze_import(ids):
    new_investigation()
    st.session_state.pending_selection = ids


def datasets_page():
    section("Tệp đã nhập")
    items = api("GET", "/api/v1/datasets", params={"limit": 101, "offset": st.session_state.get("datasets_page", 0) * 100}) or []
    left, right = st.columns([2, 1])
    query = left.text_input("Tìm dataset", placeholder="Tên tệp, host, IP…")
    source_filter = right.selectbox("Lọc theo nguồn", ["all"] + SOURCES, format_func=lambda s: "Tất cả nguồn" if s == "all" else SOURCE_NAMES[s])
    datasets = [d for d in items[:100] if (source_filter == "all" or d["source"] == source_filter or
                source_filter in d.get("metadata", {}).get("source_counts", {})) and
                query.casefold() in json.dumps(d, ensure_ascii=False).casefold()]
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


SOURCE_COLORS = overview_ui.SOURCE_COLORS


def source_profile(datasets, title):
    counts = dict.fromkeys(SOURCES, 0)
    for d in datasets:
        for source, n in (d.get("metadata", {}).get("source_counts") or {d["source"]: d["total_records"]}).items():
            counts[source] += n
    total = sum(counts.values())
    with st.container(border=True, key="source_profile"):
        section(title)
        st.metric("Bản ghi", f"{total:,}")
        if total:
            segments = "".join(f'<i style="width:{count / total * 100:.3f}%;background:{SOURCE_COLORS[source]}"></i>'
                               for source, count in counts.items() if count)
            st.markdown(f'<div class="source-bar" aria-hidden="true">{segments}</div>', unsafe_allow_html=True)
        for source in SOURCES:
            st.markdown(f'<div class="source-row"><span><i style="background:{SOURCE_COLORS[source]}"></i>{esc(SOURCE_NAMES[source])}</span><strong>{counts[source]:,}</strong></div>', unsafe_allow_html=True)


def investigation_page():
    if st.session_state.get("active_job"):
        job_panel()
        results_view(st.session_state.get("last_result"))
        return
    datasets = api("GET", "/api/v1/datasets?limit=1000")
    if datasets is None:
        return
    chosen_ids = st.session_state.get("pending_selection") or st.session_state.get("scope_datasets", [])
    missing = set(chosen_ids).difference(d["dataset_id"] for d in datasets)
    if missing:
        older = api("GET", "/api/v1/datasets", params={"ids": sorted(missing)})
        if older is None:
            return
        datasets.extend(older)
    form, profile = st.columns([1.85, 1], gap="large")
    with form, st.container(border=True):
        if not datasets:
            section("Nhập log đầu tiên")
            st.button("Chọn tệp từ máy", on_click=navigate, args=("Nhập log",), type="primary")
        else:
            section("Phạm vi phân tích")
            scope_form(datasets)
    selected = set(st.session_state.get("scope_datasets", []))
    with profile:
        if selected:
            source_profile([d for d in datasets if d["dataset_id"] in selected], "Nguồn đã chọn")
        else:
            source_profile(datasets, "Nguồn có thể chọn")


def scope_form(datasets):
    lookup = {d["dataset_id"]: d for d in datasets}
    pending = st.session_state.pop("pending_selection", None)
    if pending:
        st.session_state.scope_datasets = [i for i in pending if i in lookup]
        if len(st.session_state.scope_datasets) < len(pending):
            st.warning("Một số tệp đã chọn không còn trong kho log.")
    selected = st.multiselect("Tệp log cần phân tích", list(lookup),
                              format_func=lambda i: f"{lookup[i]['filename']} · {SOURCE_NAMES.get(lookup[i]['source'])} · {i[:8]}",
                              max_selections=20, key="scope_datasets", placeholder="Chọn log Sysmon hoặc Zeek")
    chosen = [lookup[i] for i in selected]
    signature = tuple(sorted(selected))
    if st.session_state.get("scope_signature") != signature or "start_date" not in st.session_state:
        start, end = scope_defaults(chosen or datasets)
        for key, value in {"start_date": start.date(), "start_clock": start.time().replace(tzinfo=None), "end_date": end.date(), "end_clock": end.time().replace(tzinfo=None)}.items():
            st.session_state[key] = value
        st.session_state.scope_signature = signature
    with st.form("investigation", border=False):
        mode = st.radio("Chế độ phân tích", ["offline", "gemini", "deepseek"],
                        format_func=lambda m: {"offline": "Offline", "gemini": "Gemini", "deepseek": "DeepSeek"}[m],
                        key="scope_mode", horizontal=True, help="Offline dùng luật và thống kê. Gemini và DeepSeek gửi dữ liệu liên quan đến nhà cung cấp AI đã chọn.")
        with st.expander("Phạm vi và tùy chọn"):
            a, b = st.columns(2)
            host = a.text_input("Host", placeholder="WIN-LAB-01", key="scope_host", max_chars=128)
            ip = b.text_input("IP của host", placeholder="192.0.2.10", key="scope_ip")
            mapping = st.checkbox("Xác nhận host và IP này thuộc cùng thiết bị trong thời gian đã chọn", value=False, key="scope_mapping", help="Ánh xạ đã xác minh giúp đối chiếu Sysmon với log mạng Zeek. Chỉ chọn khi bạn biết quan hệ host–IP này.")
            a, b, c, d = st.columns(4)
            start_date = a.date_input("Ngày bắt đầu · UTC", key="start_date")
            start_time = b.time_input("Giờ bắt đầu · UTC", key="start_clock", step=60)
            end_date = c.date_input("Ngày kết thúc · UTC", key="end_date")
            end_time = d.time_input("Giờ kết thúc · UTC", key="end_clock", step=60)
            strategy = st.selectbox("Chiến lược", ["multi_agent", "single_agent", "heuristic"], format_func=lambda m: {"multi_agent": "Multi-agent · Chuyên trách phối hợp", "single_agent": "Single-agent · Một agent", "heuristic": "Heuristic · Chỉ luật & thống kê"}[m], key="scope_strategy")
            criticality = st.selectbox("Mức quan trọng của tài sản", ["medium", "low", "high"], format_func=CONFIDENCE.get, key="scope_criticality")
            benign = st.text_input("IP đích đã biết hợp lệ", placeholder="Phân cách bằng dấu phẩy, ví dụ 192.0.2.20, 192.0.2.21", key="scope_benign")
            mappings = st.text_area("Ánh xạ host–IP bổ sung · JSON", value="[]", key="scope_extra_mappings", help="Danh sách đối tượng có host, ip, start_time, end_time (ISO 8601 có timezone). Dùng khi có nhiều thiết bị hoặc IP thay đổi theo thời gian.")
        submitted = st.form_submit_button("Phân tích log", type="primary", disabled=not selected)
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
            st.button("Mở kết quả điều tra →", type="primary", on_click=open_job, args=(item["investigation_id"], "Phân tích"), width="stretch")
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
    if not items and not st.session_state.get("history_page"):
        st.info("Chưa có lượt phân tích nào.")
        return
    a, b = st.columns([2, 1])
    query = a.text_input("Tìm cuộc điều tra", placeholder="Host, IP hoặc mã điều tra…")
    state = b.selectbox("Trạng thái điều tra", ["all", "completed", "running", "queued", "failed", "cancelled"], format_func=lambda s: "Tất cả trạng thái" if s == "all" else STATUS[s])
    jobs = [j for j in items[:50] if (state == "all" or j["status"] == state) and query.casefold() in json.dumps(j, ensure_ascii=False).casefold()]
    if jobs:
        st.dataframe(job_rows(jobs), hide_index=True, width="stretch")
        left, right = st.columns([3, 1], vertical_alignment="bottom")
        job = left.selectbox("Chọn cuộc điều tra", jobs, format_func=job_label)
        right.button("Mở kết quả →", type="primary", on_click=open_job, args=(job["investigation_id"], "Phân tích"), width="stretch")
    else:
        empty("Không tìm thấy cuộc điều tra", "Thử thay đổi bộ lọc hoặc tạo một cuộc điều tra mới.", "◷")
    pagination("history_page", len(items) > 50)


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


with st.container(key="topbar"):
    brand, menu = st.columns([1, 2.8], vertical_alignment="center")
    brand.markdown('<div class="wordmark"><b>S<span>.</span></b><strong>Sysmon &amp; Zeek</strong></div>', unsafe_allow_html=True)
    page = menu.radio("Không gian làm việc", PAGES, key="nav", horizontal=True, label_visibility="collapsed")

if st.session_state.get("notice"):
    st.toast(st.session_state.pop("notice"), icon=":material/check_circle:")
if page == "Tổng quan":
    overview_ui.render(api, navigate, stamp)
elif page == "Nhập log":
    import_ui.render(api, analyze_import, stamp)
elif page == "Phân tích":
    if st.session_state.get("active_job"):
        title, action = st.columns([3, 1], vertical_alignment="center")
        title.title("Kết quả phân tích" if st.session_state.get("last_result") else "Tiến trình phân tích")
        action.button("Phân tích mới", on_click=new_investigation, key="header_new")
    else:
        st.title("Phân tích Persistence & C2")
    investigation_page()
else:
    view = st.selectbox("Nội dung", ["Lịch sử phân tích", "Cảnh báo", "Tệp đã nhập", "Thống kê", "Tra cứu ATT&CK"], key="monitor_view")
    st.title(view)
    if view == "Lịch sử phân tích":
        history_page()
    elif view == "Cảnh báo":
        alerts_page()
    elif view == "Tệp đã nhập":
        datasets_page()
    elif view == "Thống kê":
        metrics_view()
    else:
        knowledge_page(api("GET", "/health", timeout=5))
