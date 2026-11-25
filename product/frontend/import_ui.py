"""Preview a batch with the API parser before explicitly storing the selected files."""
import hashlib

import streamlit as st

from overview_ui import SOURCE_NAMES


def render(api, analyze, stamp):
    st.title("Nhập log")
    with st.container(border=True):
        revision = st.session_state.get("import_revision", 0)
        files = st.file_uploader("Chọn log từ máy", accept_multiple_files=True,
                                 type=["xml", "jsonl", "json", "log", "tsv"], key=f"files_{revision}",
                                 help="Sysmon XML hoặc JSON Lines. Zeek conn, dns, http ở dạng ASCII có header hoặc JSON Lines.")
        st.caption("Sysmon XML, Zeek .log hoặc JSON Lines · Tối đa 20 tệp mỗi lượt")
        if len(files) > 20:
            st.warning("Chọn tối đa 20 tệp cho một lượt nhập.")
        elif files:
            preview_batch(files, api, stamp)
    receipt = st.session_state.get("import_receipt")
    if receipt:
        with st.container(border=True):
            st.subheader("Kết quả lượt lưu gần nhất")
            st.dataframe([{"Tệp": r["filename"], "Nguồn": SOURCE_NAMES[r["source"]],
                           "Trạng thái": "Dùng lại bản đã lưu" if r["status"] == "reused" else "Đã lưu",
                           "Bản ghi thêm": r["imported_records"]} for r in receipt], hide_index=True, width="stretch")
            ids = list(dict.fromkeys(r["dataset_id"] for r in receipt))
            st.button("Phân tích các tệp đã lưu", on_click=analyze, args=(ids,), type="primary")
    with st.expander("Lấy log trên máy thật và đối chiếu"):
        st.markdown("""
**Windows Sysmon.** Giữ bản EVTX của kênh `Microsoft-Windows-Sysmon/Operational`. Xuất các sự kiện trong cùng khoảng UTC thành XML bằng `Get-WinEvent` và `ToXml()`, rồi nhập XML. Đối chiếu tên máy, `Channel`, `EventRecordID` và thời điểm.

**Zeek.** Giữ PCAP và nhập `conn.log`, `dns.log` hoặc `http.log` đã đọc từ PCAP đó. Đối chiếu `uid`, hai đầu IP/cổng và thời điểm. Giữ các dòng header nếu tệp dùng định dạng ASCII.

**Trong ứng dụng.** Kiểm SHA-256 ở bước xem trước. Vào **Tổng quan → Sự kiện gần nhất → Đối chiếu bản ghi gốc** để xem từng trường. Lệnh xuất và cách kiểm lại nằm trong `docs/DOI_CHIEU_LOG.md` của dự án.
""")


def preview_batch(files, api, stamp):
    digests = [hashlib.sha256(f.getbuffer()).hexdigest() for f in files]
    sources = []
    with st.expander("Điều chỉnh nguồn khi chưa nhận diện được"):
        for idx, (file, digest) in enumerate(zip(files, digests)):
            source = st.selectbox(file.name, ["auto", *SOURCE_NAMES],
                                  format_func=lambda s: SOURCE_NAMES.get(s, "Tự nhận diện"),
                                  key=f"file_source_{idx}_{digest}")
            sources.append(source)
    old_cache = st.session_state.get("import_previews", {})
    cache, valid, seen, rows = {}, [], set(), []
    for file, digest, source in zip(files, digests, sources):
        key = (digest, file.name, source)
        preview = old_cache.get(key)
        if not preview:
            preview = api("POST", "/api/v1/logs/preview", data={"source_type": source},
                          files={"file": (file.name, file.getvalue())}, timeout=45)
        if not preview:
            st.caption(f"Tệp cần kiểm tra: {file.name}")
            continue
        cache[key] = preview
        identity = (digest, preview["source"])
        reuse = bool(preview["duplicate_of"]) or identity in seen
        seen.add(identity)
        valid.append((file, preview))
        rows.append({"Tệp": file.name, "Nguồn": SOURCE_NAMES[preview["source"]], "Bản ghi": preview["records"],
                     "Khi lưu": "Dùng lại" if reuse else "Thêm mới", "Bắt đầu UTC": preview["start_time"],
                     "Kết thúc UTC": preview["end_time"], "SHA-256": digest})
    st.session_state.import_previews = cache
    if not rows:
        return
    st.subheader("Xem trước")
    st.dataframe(rows, width="stretch", hide_index=True)
    if len(valid) != len(files):
        st.warning("Sửa nguồn hoặc bỏ tệp báo lỗi để lưu lượt này.")
        return
    if st.button(f"Lưu {len(valid)} tệp", type="primary", icon=":material/save_alt:"):
        saved = []
        for file, preview in valid:
            row = api("POST", "/api/v1/logs/upload", data={"source_type": preview["source"], "reuse_existing": "true"},
                      files={"file": (file.name, file.getvalue())}, timeout=60)
            if row:
                saved.append(row)
            else:
                st.warning(f"Chưa xác nhận lưu {file.name}. Có thể bấm lưu lại, tệp đã có sẽ được dùng lại.")
        if saved:
            st.session_state.import_receipt = saved
        st.session_state.import_previews = {}
        if len(saved) == len(valid):
            st.session_state.import_revision = st.session_state.get("import_revision", 0) + 1
            st.rerun()
