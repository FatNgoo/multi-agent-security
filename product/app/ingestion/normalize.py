"""Canonical fields shared by parsers, database queries, and investigators."""
from ipaddress import ip_address


def normalize_sysmon(raw: dict) -> dict:
    if not isinstance(raw.get("event_data", {}), dict):
        raise ValueError("event_data must be an object")
    fields = {**raw, **raw.get("event_data", {})}
    aliases = {
        "process_guid": ("ProcessGuid", "process_guid"),
        "parent_process_guid": ("ParentProcessGuid", "parent_process_guid"),
        "image": ("Image", "image"), "parent_image": ("ParentImage", "parent_image"),
        "command_line": ("CommandLine", "command_line"),
        "target_object": ("TargetObject", "target_object", "TargetFilename", "target_filename"), "details": ("Details", "details"),
        "source_ip": ("SourceIp", "source_ip"), "dest_ip": ("DestinationIp", "dest_ip"),
        "source_port": ("SourcePort", "source_port"), "dest_port": ("DestinationPort", "dest_port"),
        "protocol": ("Protocol", "protocol"),
    }
    normalized = {name: next((fields[key] for key in keys if fields.get(key) is not None), None)
                  for name, keys in aliases.items()}
    for name in ("process_guid", "parent_process_guid", "image", "parent_image", "command_line", "target_object", "details", "protocol"):
        value = normalized[name]
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
    for name in ("process_guid", "parent_process_guid"):
        if normalized[name] and len(normalized[name]) > 128:
            raise ValueError(f"{name} must not exceed 128 characters")
    for name in ("source_ip", "dest_ip"):
        if normalized[name] is not None:
            try:
                if not isinstance(normalized[name], str):
                    raise ValueError("IP must be a string")
                normalized[name] = str(ip_address(normalized[name]))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid {name}") from exc
    for name in ("source_port", "dest_port"):
        if normalized[name] is None:
            continue
        try:
            if isinstance(normalized[name], bool) or not isinstance(normalized[name], (str, int)):
                raise ValueError("Port must be an integer")
            port = int(normalized[name])
            if not 0 <= port <= 65535:
                raise ValueError("Port out of range")
            normalized[name] = port
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid {name}") from exc
    if normalized["protocol"]:
        normalized["protocol"] = str(normalized["protocol"]).lower()
    return normalized
