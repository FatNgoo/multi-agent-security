"""Streamlit AppTest against a running local API seeded with synthetic data."""
from scripts.paths import ARTIFACTS
from scripts.target import VERIFICATION_API, require_verification_api
import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
import requests


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default=VERIFICATION_API)
    parser.add_argument("--result", default=str(ARTIFACTS / "demo-result.json"))
    parser.add_argument("--output", default=str(ARTIFACTS / "ui-check.json"))
    args = parser.parse_args()
    require_verification_api(args.api_url)
    os.environ["API_BASE_URL"] = args.api_url
    from streamlit.testing.v1 import AppTest
    result = json.loads(Path(args.result).read_text(encoding="utf-8"))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[2] / "product/frontend/app.py"), default_timeout=30).run()
    assert not app.exception, [e.message for e in app.exception]
    assert not app.error, [e.value for e in app.error]
    print("PASS Tổng quan")
    pages = ["Datasets", "Điều tra", "Cảnh báo", "Lịch sử & báo cáo", "Kiến thức & cấu hình"]
    for page in pages:
        app.session_state["active_job"] = result["investigation_id"]
        app.session_state["job_status"] = "completed"
        app.session_state["terminal_job"] = None
        app.sidebar.radio[0].set_value(page).run()
        assert not app.exception, [e.message for e in app.exception]
        assert not app.error, [e.value for e in app.error]
        print(f"PASS {page}")
    def button(label):
        return next(item for item in app.button if item.label == label)

    def field(elements, label):
        return next(item for item in elements if item.label == label)

    def clean():
        assert not app.exception, [e.message for e in app.exception]
        assert not app.error, [e.value for e in app.error]

    # Exercise real callbacks and validation rather than only rendering pages.
    app.button(key="header_new").click().run()
    assert app.sidebar.radio[0].value == "Điều tra"
    assert not app.session_state["active_job"] and not app.session_state["last_result"]
    button("Bắt đầu điều tra").click().run()
    assert any("Chọn ít nhất" in error.value for error in app.error)
    app.multiselect(key="scope_datasets").set_value(result["dataset_ids"]).run()
    start = datetime.fromisoformat(result["scope"]["start_time"])
    end = datetime.fromisoformat(result["scope"]["end_time"])
    app.text_input(key="scope_host").set_value("WIN-LAB-01")
    app.text_input(key="scope_ip").set_value("192.0.2.10")
    app.checkbox(key="scope_mapping").set_value(True)
    app.date_input(key="start_date").set_value(end.date() + timedelta(days=1))
    app.date_input(key="end_date").set_value(end.date())
    button("Bắt đầu điều tra").click().run()
    assert any("bắt đầu phải trước" in error.value for error in app.error)
    app.date_input(key="start_date").set_value(start.date())
    app.time_input(key="start_clock").set_value(start.time().replace(tzinfo=None))
    app.time_input(key="end_clock").set_value(end.time().replace(tzinfo=None))
    app.selectbox(key="scope_mode").set_value("offline")
    app.text_area(key="scope_extra_mappings").set_value("[]")
    button("Bắt đầu điều tra").click().run()
    deadline = time.monotonic() + 15
    while not app.session_state["last_result"] and time.monotonic() < deadline:
        time.sleep(0.1)
        app.run()
    clean()
    fresh = app.session_state["last_result"]
    identifier = fresh["investigation_id"]
    assert fresh["status"] == "completed" and fresh["risk"]["severity"] == "high"
    assert fresh["scope"]["host_mappings"][0]["ip"] == "192.0.2.10"
    assert len(app.tabs) == 4
    print("PASS new-investigation callback, scope validation, date/time form, host mapping and completion")

    app.radio(key=f"finding_{identifier}").set_value(1).run()
    clean()
    evidence_tables = lambda: [table for table in app.dataframe if "Evidence ID" in table.value.columns]
    before = len(evidence_tables())
    app.text_input(key="evidence_search").set_value("no-evidence-matches-this").run()
    clean()
    assert len(evidence_tables()) == before - 1
    app.text_input(key="evidence_search").set_value("")
    app.multiselect(key="evidence_sources").set_value(["zeek_conn"]).run()
    clean()
    table = evidence_tables()[-1]
    assert set(table.value["Nguồn"]) == {"Zeek · Kết nối"}
    assert len(table.value) == sum(e["source"] == "zeek_conn" for e in fresh["evidence"])
    print("PASS finding selection, evidence search, source filter and empty state")

    assert not any(item.label in {"Chọn biện pháp", "Tiến độ thực hiện"} for item in app.selectbox)
    plan = fresh["response_plan"]
    assert plan["source"] == "local_playbook" and plan["status"] == "offline"
    markdown = " ".join(item.value for item in app.markdown)
    for step in plan["steps"]:
        assert step["title"] in markdown
    print("PASS consolidated recommendations visible without a selector")
    field(app.selectbox, "Mức nguy hiểm sau đánh giá").set_value("medium")
    field(app.text_area, "Lý do điều chỉnh").set_value("Synthetic UI verification: analyst context review.")
    button("Lưu đánh giá").click().run()
    clean()
    fresh = app.session_state["last_result"]
    assert fresh["findings"][1]["severity"] == "medium"
    assert app.session_state[f"markdown_{identifier}"]
    assert len(app.get("download_button")) == 2
    app.checkbox(key=f"audit_{identifier}").check().run()
    clean()
    response = requests.get(f"{args.api_url}/api/v1/investigations/{identifier}/audit", timeout=10)
    response.raise_for_status()
    assert len(response.json()) >= 1
    print("PASS consolidated response plan, severity review, refreshed result, reports and audit")

    app.sidebar.radio[0].set_value("Cảnh báo").run()
    selector = field(app.selectbox, "Xử lý cảnh báo")
    selector.select_index(next(i for i, label in enumerate(selector.options) if identifier[:8] in label)).run()
    assert field(app.selectbox, "Xử lý cảnh báo").value["investigation_id"] == identifier
    field(app.selectbox, "Chuyển trạng thái").set_value("acknowledged")
    field(app.text_area, "Ghi chú xử lý cảnh báo").set_value("Synthetic UI verification: alert acknowledged.")
    button("Lưu trạng thái").click().run()
    clean()
    alerts = requests.get(f"{args.api_url}/api/v1/alerts", timeout=10).json()
    assert next(a for a in alerts if a["investigation_id"] == identifier)["status"] == "acknowledged"
    button("Mở kết quả điều tra →").click().run()
    clean()
    assert app.sidebar.radio[0].value == "Lịch sử & báo cáo"
    assert app.session_state["last_result"]["investigation_id"] == identifier
    print("PASS alert acknowledgment and navigation to investigation result")

    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"status": "passed", "investigation_id": identifier, "screens": 6, "result_tabs": 4,
                                 "checks": ["render", "navigation", "scope validation", "date/time", "host mapping", "offline execution", "finding selection", "evidence filtering", "consolidated response plan", "severity review", "alert review", "reports", "audit"],
                                 "visual_browser_check": "not covered by AppTest; verify separately in browser"}, indent=2), encoding="utf-8")
    print("PASS all six screens, four result tabs and analyst interactions")


if __name__ == "__main__":
    main()
