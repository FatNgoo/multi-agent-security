"""Overview of imported telemetry and independently generated investigation alerts."""
from datetime import datetime, timezone
from html import escape
from math import floor

import altair as alt
import pandas as pd
import streamlit as st


SOURCE_NAMES = {"sysmon": "Sysmon · Endpoint", "zeek_conn": "Zeek · Kết nối",
                "zeek_dns": "Zeek · DNS", "zeek_http": "Zeek · HTTP", "windows_event": "Windows Event Log", "web_access": "Web access"}
SOURCE_COLORS = {"sysmon": "#1474b8", "zeek_conn": "#008c83", "zeek_dns": "#8055ae", "zeek_http": "#b57516",
                 "windows_event": "#546b83", "web_access": "#9c4978"}
EVENT_NAMES = {1: "Tạo tiến trình", 3: "Kết nối mạng", 11: "Tạo tệp", 12: "Tạo hoặc xóa khóa",
               13: "Ghi giá trị registry", 14: "Đổi tên registry", 22: "Truy vấn DNS"}
LEVELS = [("critical", "Nghiêm trọng", "#bd3945"), ("high", "Cao", "#b76104"),
          ("medium", "Trung bình", "#1876af"), ("low", "Thấp", "#167e76")]


def kind(source, event_id):
    if source == "sysmon":
        return f'ID {event_id} · {EVENT_NAMES.get(event_id, "Sysmon")}'
    if source == "windows_event":
        return f"Windows · ID {event_id}"
    return SOURCE_NAMES[source]


def source_ring(counts):
    total = sum(counts.values())
    start, wedges, legend = 0, [], []
    for source in SOURCE_NAMES:
        count = counts.get(source, 0)
        if total and not count:
            continue
        end = start + (100 * count / total if total else 0)
        color = SOURCE_COLORS[source]
        wedges.append(f"{color} {start:.4f}% {end:.4f}%")
        name = SOURCE_NAMES[source]
        legend.append(f'<li><i style="background:{color}"></i><span>{name}</span><b>{count:,}</b></li>')
        start = end
    fill = f'conic-gradient({", ".join(wedges)})' if total else "#e3ebef"
    st.markdown(f'<fieldset class="dash-summary"><legend>Nguồn sự kiện</legend><div class="source-summary">'
                f'<div class="ring" style="background:{fill}"><div><b>{total:,}</b><small>bản ghi</small></div></div>'
                f'<ul class="ring-key">{"".join(legend)}</ul></div></fieldset>', unsafe_allow_html=True)


def severity_panel(alerts):
    indicators = "".join(f'<div style="--tone:{color}"><b>{alerts.get(key, 0):,}</b><span>{label}</span></div>'
                         for key, label, color in LEVELS)
    extra = sum(alerts.values()) - sum(alerts.get(key, 0) for key, _, _ in LEVELS)
    note = "Tất cả các lượt phân tích" + (f" · {extra:,} cảnh báo thông tin hoặc chưa phân mức" if extra else "")
    st.markdown(f'<fieldset class="dash-summary"><legend>Cảnh báo theo mức độ</legend>'
                f'<div class="severity-strip">{indicators}</div><div class="panel-foot">{note}</div></fieldset>',
                unsafe_allow_html=True)


def timeline(data):
    if not data["bins"]:
        st.markdown('<div class="plot-empty">Nhập log để xem phân bố theo thời gian.</div>', unsafe_allow_html=True)
        return
    step = data["step"]
    counts = {(entry["ts"], entry["source"]): entry["count"] for entry in data["bins"]}
    first = floor(datetime.fromisoformat(data["start"]).timestamp() / step) * step
    last = floor(datetime.fromisoformat(data["end"]).timestamp() / step) * step
    rows = [{"UTC": datetime.fromtimestamp(ts, timezone.utc), "Nguồn": SOURCE_NAMES[src],
             "Bản ghi": counts.get((ts, src), 0)}
            for ts in range(first, last + 1, step) for src in data["sources"]]
    frame = pd.DataFrame(rows)
    frame["Đầu khoảng UTC"] = frame["UTC"].dt.strftime("%d/%m/%Y %H:%M:%S")
    colors = alt.Scale(domain=list(SOURCE_NAMES.values()), range=list(SOURCE_COLORS.values()))
    ticks = "%d/%m" if last - first >= 2 * 86400 else ("%H:%M:%S" if step < 60 else "%H:%M")
    chart = alt.Chart(frame).mark_bar(size=15, cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
        x=alt.X("UTC:T", title="Thời gian (UTC)", scale=alt.Scale(type="utc"),
                axis=alt.Axis(format=ticks, tickCount=6, labelOverlap=True)),
        y=alt.Y("Bản ghi:Q", title="Bản ghi", axis=alt.Axis(tickMinStep=1), stack="zero"),
        color=alt.Color("Nguồn:N", scale=colors, legend=None),
        tooltip=["Đầu khoảng UTC:N", "Nguồn:N", "Bản ghi:Q"]
    ).properties(height=207).configure(background="white").configure_view(stroke=None).configure_axis(
        domain=False, ticks=False, gridColor="#e0e9ec", labelColor="#44586a", titleColor="#44586a",
        labelFontSize=13, titleFontSize=13, labelPadding=6)
    st.altair_chart(chart, width="stretch", theme=None)


def ranking(types):
    if not types:
        st.markdown('<div class="plot-empty">Các loại sự kiện sẽ xuất hiện sau khi nhập log.</div>', unsafe_allow_html=True)
        return
    largest = max(row["count"] for row in types)
    bars = []
    for row in types:
        source, count = row["source"], row["count"]
        label = escape(kind(source, row["event_id"]))
        bars.append(f'<div class="rank-label"><span>{label}</span><b>{count:,}</b></div>'
                    f'<div class="rank-track"><i style="width:{100 * count / largest:.2f}%;background:{SOURCE_COLORS[source]}"></i></div>')
    st.markdown('<div class="rank-list">' + "".join(bars) + '</div>', unsafe_allow_html=True)


def render(api, navigate, stamp):
    a, b = st.columns([4, 1], vertical_alignment="center")
    a.title("Tổng quan an ninh")
    b.button("Nhập log", icon=":material/upload_file:", key="overview_import", type="primary",
             on_click=navigate, args=("Nhập log",), width="stretch")
    with st.container(key="overview_filters"):
        a, b, hint = st.columns([1.1, 1.1, 2.1], vertical_alignment="bottom")
        source = a.selectbox("Nguồn sự kiện", ["all", *SOURCE_NAMES], format_func=lambda s: SOURCE_NAMES.get(s, "Tất cả nguồn"))
        periods = {0: "Toàn bộ dữ liệu", 1: "1 giờ cuối", 24: "24 giờ cuối", 168: "7 ngày cuối"}
        hours = b.selectbox("Khoảng thời gian", list(periods), format_func=periods.get,
                            help="Tính ngược từ sự kiện mới nhất của nguồn đã chọn.")
        data = api("GET", "/api/v1/overview", params={"source": source, "hours": hours})
        if data is None:
            return
        if data["end"]:
            hint.caption(f'{stamp(data["start"], True)} → {stamp(data["end"])}')
        else:
            hint.caption("Chưa có sự kiện trong phạm vi này.")
    a, b = st.columns([1, 1.4])
    with a:
        source_ring(data["sources"])
    with b:
        severity_panel(data["alerts"])
    a, b = st.columns([1.4, 1])
    with a, st.container(border=True, key="overview_timeline"):
        st.subheader("Tần suất sự kiện")
        timeline(data)
    with b, st.container(border=True, key="overview_types"):
        st.subheader("Loại sự kiện phổ biến")
        ranking(data["types"][:5])
    with st.container(border=True, key="overview_events"):
        st.subheader("Sự kiện gần nhất")
        recent = data["recent"]
        if not recent:
            st.caption("Chưa có bản ghi để đối chiếu.")
            return
        st.dataframe([{"Thời gian UTC": r["timestamp"], "Nguồn": SOURCE_NAMES[r["source"]],
                       "Sự kiện": kind(r["source"], r["event_id"]), "Máy": r["host"] or "—",
                       "Tệp": r["filename"], "Vị trí": r["record_index"]} for r in recent],
                     hide_index=True, width="stretch", height=min(325, 38 * (1 + len(recent))))
        with st.expander("Đối chiếu bản ghi gốc"):
            row = st.selectbox("Chọn sự kiện", recent, format_func=lambda r: f'{r["filename"]} · #{r["record_index"]} · {r["timestamp"]}')
            if st.button("Xem trường gốc"):
                event = api("GET", f'/api/v1/evidence/{row["evidence_id"]}')
                if event:
                    st.json(event.get("raw", {}), expanded=2)
