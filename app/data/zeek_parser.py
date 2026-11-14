"""Strict atomic ingestion of Zeek JSON Lines and ASCII logs with #fields/#types."""
import json
import math
import re
from datetime import datetime, timezone
from ipaddress import ip_address


def _unescape(value: str) -> str:
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda match: chr(int(match[1], 16)), value)


def _typed(value: str, kind: str, unset: str, empty: str, set_separator: str):
    if value == unset:
        return None
    if value == empty:
        return [] if kind.startswith(("set[", "vector[")) else ""
    if kind.startswith(("set[", "vector[")):
        return [_typed(item, kind[kind.index("[") + 1:-1], unset, empty, set_separator)
                for item in value.split(set_separator)]
    if kind in {"count", "int", "port"}:
        return int(value)
    if kind in {"time", "interval", "double"}:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("non-finite number")
        return result
    if kind == "bool":
        if value not in {"T", "F"}:
            raise ValueError("invalid bool")
        return value == "T"
    return _unescape(value)


def _normalize(raw: dict, source: str) -> dict:
    ts = raw.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, (float, int)) or not math.isfinite(ts):
        raise ValueError("ts must be a finite Unix timestamp")
    uid = raw.get("uid")
    if not isinstance(uid, str) or not uid or len(uid) > 128:
        raise ValueError("uid must be a nonempty string up to 128 characters")
    normalized = {"zeek_uid": uid, "timestamp": datetime.fromtimestamp(ts, timezone.utc),
                  "event_type": source.removeprefix("zeek_")}
    for src, dest in (("id.orig_h", "source_ip"), ("id.resp_h", "dest_ip")):
        normalized[dest] = str(ip_address(raw[src]))
    for src, dest in (("id.orig_p", "source_port"), ("id.resp_p", "dest_port")):
        port = raw.get(src)
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError(f"{src} must be a port between 0 and 65535")
        normalized[dest] = port
    proto = raw.get("proto")
    if source in {"zeek_conn", "zeek_dns"} and proto not in {"tcp", "udp", "icmp"}:
        raise ValueError("proto must be tcp, udp, or icmp")
    normalized["protocol"] = proto
    for name in ("duration", "orig_bytes", "resp_bytes"):
        value = raw.get(name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                  or not math.isfinite(value) or value < 0):
            raise ValueError(f"{name} must be a finite nonnegative number")
    for name in ("service", "duration", "orig_bytes", "resp_bytes", "conn_state", "query", "qtype_name",
                 "answers", "method", "host", "uri", "status_code", "user_agent"):
        normalized[name if name != "host" else "http_host"] = raw.get(name)
    return normalized


def parse_zeek(data: bytes, source: str) -> list[tuple[int, dict, dict]]:
    if source not in {"zeek_conn", "zeek_dns", "zeek_http"}:
        raise ValueError("Unsupported Zeek log type")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Zeek upload must be UTF-8") from exc
    rows = []
    separator, set_separator, unset, empty = "\t", ",", "-", "(empty)"
    fields, types = [], []
    json_mode = text.lstrip().startswith("{")
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            if not json_mode and line.startswith("#"):
                if line.startswith("#separator "):
                    separator = _unescape(line.split(" ", 1)[1])
                    if not separator or len(separator) != 1:
                        raise ValueError("invalid separator")
                    continue
                key, _, value = line.partition(separator)
                if key == "#fields":
                    fields = value.split(separator)
                elif key == "#types":
                    types = value.split(separator)
                elif key == "#unset_field":
                    unset = value
                elif key == "#empty_field":
                    empty = value
                elif key == "#set_separator":
                    set_separator = value
                elif key == "#path" and value != source.removeprefix("zeek_"):
                    raise ValueError("#path differs from selected source")
                continue
            if json_mode:
                raw = json.loads(line)
                json.dumps(raw, allow_nan=False)
                if not isinstance(raw, dict):
                    raise ValueError("each line must be an object")
            else:
                values = line.split(separator)
                if not fields or len(fields) != len(types) or len(fields) != len(set(fields)):
                    raise ValueError("valid #fields and #types headers required")
                if len(values) != len(fields):
                    raise ValueError("column count differs from #fields")
                raw = {key: _typed(value, kind, unset, empty, set_separator)
                       for key, kind, value in zip(fields, types, values)}
            normalized = _normalize(raw, source)
            # Preserve the exact data line alongside decoded structured fields.
            rows.append((line_no, normalized, {**raw, "_raw_line": line}))
        except (ValueError, TypeError, KeyError, OverflowError, OSError) as exc:
            raise ValueError(f"Invalid Zeek record on line {line_no}: {exc}") from exc
    if not rows:
        raise ValueError("File contains no Zeek records")
    return rows
