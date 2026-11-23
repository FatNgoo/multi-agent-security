"""Render the actual timeline with mixed timestamp precision, without a running API."""
import json
from pathlib import Path

import pytest
import requests
from streamlit.testing.v1 import AppTest


@pytest.mark.parametrize("reverse", [False, True])
def test_timeline_renders_mixed_iso_precision_and_offsets(monkeypatch, reverse):
    def local_response(method, url, **kwargs):
        if url.endswith('/health'):
            body = {'status': 'healthy', 'database': 'sqlite', 'mode': 'offline', 'worker_enabled': False}
        elif url.endswith('/api/v1/knowledge'):
            body = {'version': 'test', 'results': []}
        else:
            raise AssertionError(f'Unexpected HTTP request: {method} {url}')
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(body).encode()
        return response

    monkeypatch.setattr(requests, 'request', local_response)
    # Reproduces the reported position-12 failure; the other order previously failed too.
    timeline = [{'timestamp': f'2026-10-14T08:03:{second:02d}+00:00',
                 'source': 'sysmon', 'description': f'event-{second}', 'evidence_id': str(second)}
                for second in range(12)]
    timeline.append({'timestamp': '2026-10-14T08:03:10.123456+00:00',
                     'source': 'zeek_conn', 'description': 'fractional', 'evidence_id': 'fractional'})
    timeline.append({'timestamp': '2026-10-14T15:03:09.500000+07:00',
                     'source': 'zeek_conn', 'description': 'offset', 'evidence_id': 'offset'})
    timeline.append({'timestamp': '2026-10-14T08:03:12Z',
                     'source': 'sysmon', 'description': 'utc-z', 'evidence_id': 'utc-z'})
    if reverse:
        timeline.reverse()
    original = json.dumps(timeline)
    frontend = Path(__file__).resolve().parents[2] / 'product/frontend/app.py'
    harness = f'''import runpy
import streamlit as st
st.session_state.nav = "Kiến thức & cấu hình"
workspace = runpy.run_path({str(frontend)!r})
workspace["timeline_view"]({{"timeline": st.session_state["test_timeline"]}})
'''
    view = AppTest.from_string(harness, default_timeout=20)
    view.session_state['test_timeline'] = timeline
    view.run()
    assert not view.exception, [e.message for e in view.exception]
    assert not view.error
    table = view.dataframe[0].value
    assert len(table) == len(timeline)
    descriptions = list(table['Mô tả'])
    assert descriptions.index('event-9') < descriptions.index('offset') < descriptions.index('event-10')
    assert descriptions.index('event-10') < descriptions.index('fractional') < descriptions.index('event-11')
    assert json.dumps(view.session_state['test_timeline']) == original
