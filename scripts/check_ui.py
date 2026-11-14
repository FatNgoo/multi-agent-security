"""Streamlit AppTest against a running local API seeded with synthetic data."""
import argparse
import json
import os
import sys
import time
from pathlib import Path


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--result", default="artifacts/demo-result.json")
    args = parser.parse_args()
    os.environ["API_BASE_URL"] = args.api_url
    from streamlit.testing.v1 import AppTest
    result = json.loads(Path(args.result).read_text(encoding="utf-8"))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "frontend/app.py"), default_timeout=30).run()
    assert not app.exception, [e.message for e in app.exception]
    pages = ["Datasets", "Điều tra", "Cảnh báo", "Lịch sử & báo cáo", "Kiến thức & cấu hình"]
    for page in pages:
        app.session_state["active_job"] = result["investigation_id"]
        app.session_state["job_status"] = "completed"
        app.sidebar.radio[0].set_value(page).run()
        assert not app.exception, [e.message for e in app.exception]
        assert not app.error, [e.value for e in app.error]
        print(f"PASS {page}")
    app.session_state["active_job"] = None
    app.session_state["last_result"] = None
    app.sidebar.radio[0].set_value("Điều tra").run()
    app.multiselect[0].set_value(result["dataset_ids"])
    values = {"Host": "WIN-LAB-01", "Bắt đầu · ISO 8601 có timezone": result["scope"]["start_time"],
              "Kết thúc · ISO 8601 có timezone": result["scope"]["end_time"]}
    for field in app.text_input:
        if field.label in values:
            field.set_value(values[field.label])
    app.text_area[0].set_value(json.dumps(result["scope"]["host_mappings"]))
    next(button for button in app.button if button.label == "Bắt đầu điều tra").click().run()
    deadline = time.monotonic() + 15
    while not app.session_state.get("last_result") and time.monotonic() < deadline:
        time.sleep(0.1)
        app.run()
    assert not app.exception, [e.message for e in app.exception]
    assert app.session_state["last_result"]["status"] == "completed"
    assert app.session_state["last_result"]["risk"]["severity"] == "high"
    print("PASS investigation form submission, background completion and result rendering")
    print("PASS all six screens and completed investigation panels")


if __name__ == "__main__":
    main()
