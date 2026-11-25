"""Read IIS W3C and Apache common/combined access logs as supporting evidence."""
import re
from datetime import datetime, timezone
from ipaddress import ip_address

APACHE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(.*?)" (\d{3}) (\d+|-)(?: .*)?$')


def web_rows(stream, style):
    fields = []
    for index, binary in enumerate(stream, 1):
        try:
            line = binary.decode("utf-8-sig")
            encoding = "utf-8"
        except UnicodeDecodeError:
            line = binary.decode("latin-1")
            encoding = "latin-1"
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if style == "iis" and line.startswith("#"):
            if line.startswith("#Fields:"):
                fields = line.partition(":")[2].split()
            continue
        try:
            if style == "iis":
                values = line.split()
                if not fields or len(fields) != len(values):
                    raise ValueError("header #Fields không khớp số cột")
                data = dict(zip(fields, values))
                ts = datetime.fromisoformat(data["date"] + "T" + data["time"]).replace(tzinfo=timezone.utc)
                client, method, status = data["c-ip"], data["cs-method"], data["sc-status"]
                server = data.get("s-ip")
            else:
                match = APACHE.fullmatch(line)
                if not match:
                    raise ValueError("định dạng access log không hợp lệ")
                client, date, request, status, size = match.groups()
                ts = datetime.strptime(date, "%d/%b/%Y:%H:%M:%S %z")
                method = request.partition(" ")[0]
                server = None
                data = {"request": request, "bytes": size, "status": status}
            norm = {"source_ip": str(ip_address(client)), "dest_ip": str(ip_address(server)) if server and server != "-" else None,
                    "method": method, "status": int(status)}
            raw = {"format": style, "encoding": encoding, "fields": data, "_raw_line": line}
            yield index, ts.astimezone(timezone.utc), "", 0, f"HTTP {method[:24]} · {status}".replace("\x00", "�"), norm, raw, "web_access"
        except (ValueError, KeyError) as exc:
            raise ValueError(f"Web access, dòng {index}: {exc}") from exc
