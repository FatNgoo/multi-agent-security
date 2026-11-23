"""Read real capture files without uploading, contacting a provider or changing originals."""
import argparse
from collections import Counter
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
from app.ingestion.sysmon_xml_parser import parse_sysmon_xml
from app.ingestion.zeek_parser import parse_zeek


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case_directory', type=Path)
    args = parser.parse_args()
    case = args.case_directory.resolve()
    manifest = json.loads((case / 'scenario.json').read_text(encoding='utf-8-sig'))
    begin = datetime.fromisoformat(manifest['start_utc'].replace('Z', '+00:00'))
    end = datetime.fromisoformat(manifest['end_utc'].replace('Z', '+00:00'))
    files = [(p, 'sysmon') for p in sorted((case / 'sysmon').glob('sysmon-*.xml'))]
    for name in ('conn', 'http', 'dns'):
        files += [(p, f'zeek_{name}') for p in sorted((case / 'zeek').glob(f'{name}*.log'))]
    if not files:
        parser.error('No sysmon/sysmon-*.xml or zeek/{conn,http,dns}*.log files found.')
    report = []
    hosts = set()
    ids = Counter()
    for path, source in files:
        data = path.read_bytes()
        if len(data) > 5_000_000:
            raise ValueError(f'{path.name}: exceeds the default 5 MB upload limit; split without editing events')
        rows = parse_sysmon_xml(data) if source == 'sysmon' else parse_zeek(data, source)
        times = []
        in_window = 0
        for _, record, _ in rows:
            if source == 'sysmon':
                hosts.add(record.host)
                ids[record.event_id] += 1
                timestamp = record.timestamp
            else:
                timestamp = record['timestamp']
            times.append(timestamp)
            in_window += begin <= timestamp <= end
        report.append({'file': str(path.relative_to(case)), 'source_type': source,
                       'bytes': len(data), 'records': len(rows), 'records_in_case_window': in_window,
                       'start_utc': min(times).isoformat(), 'end_utc': max(times).isoformat(),
                       'sha256': sha256(data).hexdigest()})
    print(json.dumps({'case_id': manifest['case_id'], 'sysmon_hosts': sorted(hosts),
                      'sysmon_event_ids': dict(ids), 'files': report,
                      'note': 'Parsing passed. Capture completeness, clock skew and behavior still require review.'},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
