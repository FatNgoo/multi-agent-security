"""One live provider check with synthetic data and an isolated temporary SQLite database."""
import argparse
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace

from scripts.paths import ARTIFACTS
from scripts.scenarios import scenario, jsonl


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['gemini', 'deepseek'], default='gemini')
    parser.add_argument('--scope', choices=['sysmon', 'combined'], default='sysmon')
    parser.add_argument('--output', type=Path, default=ARTIFACTS / 'ai-provider-check.json')
    parser.add_argument('--trace-output', type=Path, help='Save provider responses for this synthetic-only check')
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='isolated-ai-check-'))
    os.environ['DATABASE_URL'] = 'sqlite:///' + (directory / 'check.db').as_posix()
    os.environ['WORKER_ENABLED'] = 'false'
    from fastapi.testclient import TestClient
    from app.main import app
    from app.config import settings
    if args.trace_output:
        from openai import OpenAI
        from app.agents import specialists, response_agent
        traces = []
        class TracingClient:
            def __init__(self, **kwargs):
                self.client = OpenAI(**kwargs)
                self.chat = SimpleNamespace(completions=self)
            def __enter__(self):
                self.client.__enter__()
                return self
            def __exit__(self, *args):
                return self.client.__exit__(*args)
            def create(self, **kwargs):
                result = self.client.chat.completions.create(**kwargs)
                traces.append({'finish_reason': result.choices[0].finish_reason,
                               'content': result.choices[0].message.content,
                               'tool_choice': kwargs.get('tool_choice'),
                               'usage': result.usage.model_dump() if result.usage else None})
                args.trace_output.parent.mkdir(parents=True, exist_ok=True)
                args.trace_output.write_text(json.dumps(traces, ensure_ascii=False, indent=2), encoding='utf-8')
                return result
        specialists.OpenAI = TracingClient
        response_agent.OpenAI = TracingClient
    with TestClient(app) as client:
        ids = []
        for source, records in scenario('combined').items():
            if args.scope == 'sysmon' and source != 'sysmon':
                continue
            response = client.post('/api/v1/logs/upload', data={'source_type': source},
                                   files={'file': (source + '.jsonl', jsonl(records))})
            response.raise_for_status()
            ids.append(response.json()['dataset_id'])
        response = client.post('/api/v1/investigate', json={
            'dataset_ids': ids, 'host': 'WIN-LAB-01', 'mode': args.mode, 'strategy': 'multi_agent',
            'ip': '192.0.2.10', 'start_time': '2026-10-14T08:00:00Z', 'end_time': '2026-10-14T09:00:00Z',
            'host_mappings': [{'host': 'WIN-LAB-01', 'ip': '192.0.2.10',
                               'start_time': '2026-10-14T08:00:00Z', 'end_time': '2026-10-14T09:00:00Z'}]})
        response.raise_for_status()
        result = response.json()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = {'model': getattr(settings, f'{args.mode}_model'), 'database': str(directory / 'check.db'),
              'data_origin': 'synthetic, isolated from product API and database', 'result': result}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    statuses = [{k: item.get(k) for k in ('agent', 'status', 'error_code', 'error_message')} for item in result['assessments']]
    print(json.dumps({'model': report['model'], 'assessments': statuses,
                      'response_source': result['response_plan']['source'], 'llm_calls': result['timings']['llm_calls'],
                      'runtime_ms': result['timings']['total_ms'], 'output': str(args.output)}, ensure_ascii=True))
    if any(a['status'] != 'completed' for a in result['assessments']) or result['response_plan']['source'] != 'ai':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
