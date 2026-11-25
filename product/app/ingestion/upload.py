"""Classify uploads and validate their contents before committing a dataset."""
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from fastapi import HTTPException
from app.common import iso
from app.config import settings
from app.ingestion.normalize import normalize_sysmon
from app.ingestion.sysmon_parser import parse_jsonl
from app.ingestion.sysmon_xml_parser import parse_sysmon_xml
from app.ingestion.web_access import APACHE, web_rows
from app.ingestion.windows_logs import evtx_rows, is_windows_json, otrf_rows
from app.ingestion.zeek_parser import identify_zeek_source, parse_zeek

ZEEK = ("zeek_conn", "zeek_dns", "zeek_http")


def identify(stream, ext, requested):
    if ext == ".evtx":
        return "evtx"
    if ext == ".xml":
        return "sysmon"
    if ext not in (".json", ".jsonl", ".log", ".tsv", ".txt"):
        raise HTTPException(415, "Đuôi tệp chưa được hỗ trợ.")
    sample = stream.read(1024 * 1024).decode("utf-8-sig", errors="replace").lstrip()
    if sample.startswith(("#Software: Microsoft Internet Information Services", "#Fields:")):
        return "iis"
    first = sample.partition("\n")[0].rstrip("\r")
    if APACHE.fullmatch(first):
        return "apache"
    path = re.search(r"(?m)^#path\s+([^\s]+)", sample)
    if path:
        return "zeek_" + path[1]
    try:
        row = json.loads(first)
    except ValueError:
        row = {}
    if isinstance(row, dict):
        if is_windows_json(row):
            return "otrf"
        if {"timestamp", "host", "event_id"} <= row.keys():
            return "sysmon"
        if {"ts", "uid", "id.orig_h", "id.resp_h"} <= row.keys():
            source = identify_zeek_source(row)
            if source:
                return source
    if requested == "auto":
        raise HTTPException(422, "Chưa nhận diện được nguồn. Kiểm tra định dạng hoặc chọn nguồn phù hợp.")
    return requested


class LogImport:
    def __init__(self, file, requested):
        self.stream = file.file
        self.filename = file.filename or ""
        self.ext = Path(self.filename).suffix.lower()
        self.kind = identify(self.stream, self.ext, requested)
        self.requested = requested
        self.windows = self.kind in ("evtx", "otrf")
        if not self.windows:
            source = "web_access" if self.kind in ("apache", "iis") else self.kind
            if source not in ("sysmon", "web_access", *ZEEK) or requested not in ("auto", source):
                raise HTTPException(422, "Nội dung khác nguồn đã chọn hoặc chưa được hỗ trợ.")
            allowed = (".xml", ".json", ".jsonl") if source == "sysmon" else (".json", ".jsonl", ".log", ".tsv", ".txt")
            if self.ext not in allowed or (source == "web_access" and self.kind not in ("apache", "iis")):
                raise HTTPException(415, "Đuôi hoặc định dạng tệp chưa được hỗ trợ cho nguồn đã chọn.")
        limit = settings.max_windows_upload_bytes if self.windows else settings.max_upload_bytes
        self.stream.seek(0, 2)
        if self.stream.tell() > limit:
            raise HTTPException(413, f"Tệp vượt giới hạn {limit:,} byte cho định dạng này.")
        self.stream.seek(0)
        self.sha256 = hashlib.file_digest(self.stream, "sha256").hexdigest()

    def rows(self):
        self.stream.seek(0)
        self.stats = {"missing_timezone": 0, "clock_fields": Counter()}
        try:
            if self.kind == "evtx":
                yield from evtx_rows(self.stream)
            elif self.kind == "otrf":
                yield from otrf_rows(self.stream, self.stats)
            elif self.kind in ("apache", "iis"):
                yield from web_rows(self.stream, self.kind)
            elif self.kind == "sysmon":
                parser = parse_sysmon_xml if self.ext == ".xml" else parse_jsonl
                for idx, rec, raw in parser(self.stream.read()):
                    yield idx, rec.timestamp, rec.host, rec.event_id, rec.description, normalize_sysmon(raw), raw, "sysmon"
            else:
                for idx, n, raw in parse_zeek(self.stream.read(), self.kind):
                    desc = f"{self.kind}: {n['source_ip']}:{n['source_port']} -> {n['dest_ip']}:{n['dest_port']}"
                    yield idx, n["timestamp"], "", 0, desc, {k: v for k, v in n.items() if k != "timestamp"}, raw, self.kind
        except (ValueError, UnicodeError) as exc:
            raise HTTPException(422, str(exc)) from exc

    def summarize(self):
        counts, hosts, ips = Counter(), set(), set()
        start = end = None
        for _, ts, host, _, _, normalized, _, source in self.rows():
            counts[source] += 1
            start = min(start, ts) if start else ts
            end = max(end, ts) if end else ts
            if host:
                hosts.add(host)
            ips.update(normalized[k] for k in ("source_ip", "dest_ip") if normalized.get(k))
        if not counts:
            raise HTTPException(422, "Tệp không có sự kiện với thời gian UTC xác định.")
        source = next(iter(counts)) if len(counts) == 1 else "windows_event"
        if self.requested not in ("auto", source):
            raise HTTPException(422, f"Tệp thuộc nguồn {source}. Chọn Tự nhận diện để nhập đầy đủ.")
        metadata = {"format": self.kind, "source_counts": dict(counts), "start_time": iso(start), "end_time": iso(end),
                    "hosts": sorted(hosts), "ips": sorted(ips), "error_count": 0, **self.stats}
        return source, sum(counts.values()), metadata
