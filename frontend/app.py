"""Streamlit frontend for the v0.4 investigation API.
No database or LLM credentials are required in the frontend.
"""
import json
import os
from datetime import datetime, timedelta, timezone

import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")
REQUEST_TIMEOUT = 120

st.set_page_config(page_title="Security Investigation", page_icon="🔎", layout="wide")
st.title("Security Investigation Platform")
st.caption("Sysmon JSONL/XML Upload · Dataset Management · Persistence Investigation · LangGraph")


def api_request(method: str, endpoint: str, **kwargs):
    try:
        response = requests.request(
            method, f"{API_BASE_URL}{endpoint}", timeout=kwargs.pop("timeout", REQUEST_TIMEOUT), **kwargs
        )
        response.raise_for_status()
        return response.json(), None
    except requests.HTTPError as exc:
        try:
            detail = exc.response.json().get("detail", exc.response.text)
        except (ValueError, AttributeError):
            detail = str(exc)
        return None, f"API returned HTTP {exc.response.status_code}: {detail}"
    except (requests.ConnectionError, requests.Timeout, ValueError) as exc:
        return None, f"Cannot reach backend: {exc}"


if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "last_dataset_id" not in st.session_state:
    st.session_state.last_dataset_id = None

health, health_error = api_request("GET", "/health", timeout=5)
col1, col2, col3 = st.columns(3)
col1.metric("Backend", "Connected" if health else "Unavailable")
col2.metric("Agent mode", health.get("mode", "—") if health else "—")
col3.metric("Data source", "PostgreSQL (API)")
if health_error:
    st.error(health_error)

upload_tab, investigate_tab, evidence_tab = st.tabs(["Upload & Datasets", "AI Investigation", "Evidence & Results"])

with upload_tab:
    st.subheader("Upload Sysmon logs")
    st.info("Supports Sysmon JSONL (normalized fixture schema) and Sysmon XML exported from Windows Event Viewer (one Event or Events root). EVTX and Zeek are not supported yet.")
    uploaded = st.file_uploader("Select Sysmon JSONL or XML", type=["jsonl", "json", "xml"], key="sysmon_upload")
    if st.button("Upload to PostgreSQL", disabled=uploaded is None or health_error is not None, type="primary"):
        with st.spinner("Uploading and validating records..."):
            result, error = api_request("POST", "/api/v1/logs/upload", files={"file": (uploaded.name, uploaded.getvalue(), "application/xml" if uploaded.name.lower().endswith(".xml") else "application/json")})
        if error:
            st.error(error)
        else:
            st.session_state.last_dataset_id = result["dataset_id"]
            st.success(f"Imported {result['imported_records']} record(s) into dataset {result['dataset_id']}")
            st.json(result)
    st.subheader("Uploaded datasets")
    datasets, error = api_request("GET", "/api/v1/datasets", timeout=15)
    if error:
        st.warning(error)
    elif not datasets:
        st.caption("No datasets yet. Upload a Sysmon JSONL file to begin.")
    else:
        st.dataframe(datasets, hide_index=True, use_container_width=True)

with investigate_tab:
    st.subheader("Run Persistence Investigation")
    datasets, ds_error = api_request("GET", "/api/v1/datasets", timeout=15)
    if ds_error:
        st.error(ds_error)
    elif not datasets:
        st.info("Upload a dataset in the first tab before running an investigation.")
    else:
        names = {d["dataset_id"]: f"{d['filename']} ({d['total_records']} records) — {d['dataset_id'][:8]}" for d in datasets}
        ids = list(names)
        selected = st.selectbox("Dataset", ids, index=ids.index(st.session_state.last_dataset_id) if st.session_state.last_dataset_id in ids else 0, format_func=lambda key: names[key])
        host = st.text_input("Target host", value="WIN-LAB-01").strip()
        now = datetime.now(timezone.utc)
        default_start = now - timedelta(days=30)
        start_col, end_col = st.columns(2)
        with start_col:
            start_date = st.date_input("Start date (UTC)", value=default_start.date())
            start_time = st.time_input("Start time (UTC)", value=datetime.min.time())
        with end_col:
            end_date = st.date_input("End date (UTC)", value=(now + timedelta(days=1)).date())
            end_time = st.time_input("End time (UTC)", value=datetime.min.time())
        start_dt = datetime.combine(start_date, start_time, tzinfo=timezone.utc)
        end_dt = datetime.combine(end_date, end_time, tzinfo=timezone.utc)
        if st.button("Run Investigation", type="primary", disabled=not host):
            if start_dt >= end_dt:
                st.error("Start time must be earlier than end time.")
            else:
                payload = {"dataset_id": selected, "host": host,
                           "start_time": start_dt.isoformat(), "end_time": end_dt.isoformat()}
                with st.spinner("LangGraph Agent is investigating..."):
                    result, error = api_request("POST", "/api/v1/investigate", json=payload)
                if error:
                    st.error(error)
                else:
                    st.session_state.last_result = result
                    st.success("Investigation completed. See Evidence & Results tab.")
                    st.write("**Summary**", result.get("summary", ""))
                    st.caption(f"Route: {result.get('route')} · Mode: {result.get('mode')} · Evidence: {len(result.get('evidence', []))}")

with evidence_tab:
    st.subheader("Investigation findings")
    result = st.session_state.last_result
    if result is None:
        st.info("Run an investigation in the second tab to view results.")
    else:
        if result.get("warning"):
            st.warning(result["warning"])
        st.write("**Summary**")
        st.write(result.get("summary", ""))
        evidences = result.get("evidence", [])
        if evidences:
            st.write("**Evidence records**")
            st.dataframe([{k: e.get(k) for k in ["evidence_id", "timestamp", "host", "event_id", "description"]} for e in evidences], hide_index=True, use_container_width=True)
            for e in evidences:
                with st.expander(f"Event {e.get('event_id')} — {e.get('evidence_id')}"):
                    st.json(e)
        else:
            st.info("No matching events found for the selected host and time range.")
        st.write("**Tool trace**")
        trace = result.get("tool_trace", [])
        if trace:
            for line in trace:
                st.code(str(line), language=None)
        else:
            st.caption("No tool calls recorded.")
        st.download_button(
            label="Download investigation JSON",
            data=json.dumps(result, indent=2, ensure_ascii=False),
            file_name="investigation-result.json",
            mime="application/json",
            key="download_investigation_json",
        )

st.caption("Prototype v0.4 · Synthetic fixtures are for workflow testing, not validated attack detections.")
