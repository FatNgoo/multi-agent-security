import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.agents import response_agent, specialists
from app.config import settings
from app.main import app
from app.services.recommendations import recommend
from app.tools.shared import Cancelled
from tests.helpers import upload_case


class ResponseTools:
    def __init__(self):
        self.request = SimpleNamespace(model_dump=lambda **kwargs: {'host': 'LAB', 'dataset_ids': ['lab-data']})
        self.coverage = {'truncated': False}
        self.llm_calls = 0
        self.tokens = {'prompt': 0, 'completion': 0}
        self.progress = lambda stage: None

    def events(self):
        return [{'evidence_id': 'real-id', 'source': 'sysmon', 'host': 'LAB',
                 'description': 'Controlled autorun change', 'normalized': {}}]

    def checkpoint(self):
        pass

    def remaining(self):
        return 30


def findings():
    items = [{'rule_id': 'run_key', 'agent': 'persistence', 'severity': 'medium', 'confidence': 'medium',
              'title': 'Autorun configuration', 'technique_ids': ['T1547.001'],
              'limitations': [], 'evidence_ids': ['real-id']}]
    recommend(items)
    return items


def fake_client(monkeypatch, content=None, fail=False):
    calls = []

    class Client:
        def __init__(self, **kwargs):
            assert kwargs['max_retries'] == 0
            self.chat = SimpleNamespace(completions=self)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def create(self, **kwargs):
            calls.append(kwargs)
            assert 'real-id' in kwargs['messages'][1]['content']
            if fail:
                raise RuntimeError('Mock provider failure')
            return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=20, completion_tokens=30),
                                   choices=[SimpleNamespace(message=SimpleNamespace(content=content))])

    monkeypatch.setattr(settings, 'gemini_api_key', 'mock-key')
    monkeypatch.setattr(response_agent, 'OpenAI', Client)
    return calls


def valid_plan(reference='real-id'):
    return json.dumps({'summary': 'Xác minh và lưu bằng chứng trước khi khắc phục.',
                       'steps': [{'title': 'Xác minh cấu hình', 'action': 'Đối chiếu thay đổi với người quản trị.',
                                  'condition': 'Chưa xóa cấu hình khi chưa xác minh.',
                                  'verification': 'Ghi nhận chủ sở hữu và kết quả đối chiếu.',
                                  'evidence_ids': [reference]}], 'limitations': ['Chưa chứng minh malware.']})


def test_ai_response_is_grounded_and_accounts_for_usage(monkeypatch):
    calls = fake_client(monkeypatch, valid_plan())
    tools = ResponseTools()
    plan = response_agent.propose_response(findings(), [], {'severity': 'medium'}, tools, 'gemini')
    assert plan['source'] == 'ai' and plan['status'] == 'completed'
    assert plan['steps'][0]['evidence_ids'] == ['real-id']
    assert len(calls) == tools.llm_calls == 1
    assert tools.tokens == {'prompt': 20, 'completion': 30}


@pytest.mark.parametrize('content', [valid_plan('invented-id'), '{}', 'not JSON'])
def test_invalid_ai_response_falls_back_without_losing_actions(monkeypatch, content):
    fake_client(monkeypatch, content)
    plan = response_agent.propose_response(findings(), [], {}, ResponseTools(), 'gemini')
    assert plan['source'] == 'local_playbook' and plan['status'] == 'unavailable'
    assert plan['steps'] and all('invented-id' not in step['evidence_ids'] for step in plan['steps'])


def test_provider_error_keeps_local_plan(monkeypatch):
    fake_client(monkeypatch, fail=True)
    plan = response_agent.propose_response(findings(), [], {}, ResponseTools(), 'gemini')
    assert plan['source'] == 'local_playbook' and plan['steps']


@pytest.mark.parametrize('case', ['offline', 'missing_key', 'call_budget', 'token_budget'])
def test_no_provider_call_when_unavailable_or_offline(monkeypatch, case):
    calls = fake_client(monkeypatch, valid_plan())
    tools = ResponseTools()
    if case == 'missing_key':
        monkeypatch.setattr(settings, 'gemini_api_key', '')
    elif case == 'call_budget':
        tools.llm_calls = settings.max_llm_calls
    elif case == 'token_budget':
        tools.tokens['prompt'] = settings.max_llm_tokens
    plan = response_agent.propose_response(findings(), [], {}, tools, 'offline' if case == 'offline' else 'gemini')
    assert plan['source'] == 'local_playbook' and plan['steps']
    assert not calls


def test_reserved_call_allows_response_with_single_call_budget(monkeypatch):
    calls = fake_client(monkeypatch, valid_plan())
    monkeypatch.setattr(settings, 'max_llm_calls', 1)
    tools = ResponseTools()
    tools.reserved_llm_calls = 1
    assert specialists.interpret('persistence', tools, 'gemini')['status'] == 'llm_budget_exhausted'
    plan = response_agent.propose_response(findings(), [], {}, tools, 'gemini')
    assert plan['source'] == 'ai' and len(calls) == 1 and tools.llm_calls == 1


def test_response_respects_cancellation(monkeypatch):
    calls = fake_client(monkeypatch, valid_plan())
    tools = ResponseTools()
    def cancel():
        raise Cancelled('Cancelled')
    tools.checkpoint = cancel
    with pytest.raises(Cancelled):
        response_agent.propose_response(findings(), [], {}, tools, 'gemini')
    assert not calls


def test_offline_pipeline_persists_and_exports_one_consolidated_plan():
    with TestClient(app) as client:
        scope = upload_case(client)
        result = client.post('/api/v1/investigate', json=scope).json()
        plan = result['response_plan']
        assert plan['source'] == 'local_playbook' and plan['status'] == 'offline'
        assert len(plan['steps']) < sum(len(f['recommendations']) for f in result['findings'])
        known = {e['evidence_id'] for e in result['evidence']}
        assert all(set(step['evidence_ids']) <= known for step in plan['steps'])
        saved = client.get(f"/api/v1/investigations/{result['investigation_id']}").json()
        assert saved['result']['response_plan'] == plan
        report = client.get(f"/api/v1/investigations/{result['investigation_id']}/report?format=markdown").text
        assert plan['summary'] in report and plan['steps'][0]['title'] in report


def test_provider_pipeline_includes_response_advisor_and_single_report_plan(monkeypatch):
    monkeypatch.setattr(settings, 'gemini_api_key', 'mock-key')

    class Client:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=self)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def create(self, **kwargs):
            if 'scoped_evidence' not in json.loads(kwargs['messages'][1]['content']):
                payload = json.loads(kwargs['messages'][1]['content'])
                reference = payload['findings'][0]['evidence_ids'][0]
                content = valid_plan(reference)
                message = SimpleNamespace(content=content)
            elif isinstance(kwargs.get('tool_choice'), dict):
                call = SimpleNamespace(id='read-events', function=SimpleNamespace(name='query_events', arguments='{}'))
                message = SimpleNamespace(tool_calls=[call], content=None,
                                          model_dump=lambda **kw: {'role': 'assistant', 'content': 'Read scoped events'})
            else:
                tool_messages = [m for m in kwargs['messages'] if m['role'] == 'tool']
                payload = (json.loads(tool_messages[-1]['content']) if tool_messages else
                           {'data': json.loads(kwargs['messages'][1]['content'])['scoped_evidence']})
                content = json.dumps({'text': 'Mock investigation assessment',
                                      'evidence_ids': [payload['data'][0]['evidence_id']], 'limitations': []})
                message = SimpleNamespace(content=content, tool_calls=None,
                                          model_dump=lambda **kw: {'role': 'assistant', 'content': content})
            return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=10, completion_tokens=10),
                                   choices=[SimpleNamespace(message=message)])

    monkeypatch.setattr(specialists, 'OpenAI', Client)
    monkeypatch.setattr(response_agent, 'OpenAI', Client)
    with TestClient(app) as client:
        scope = upload_case(client)
        scope.update(mode='gemini', strategy='multi_agent')
        response = client.post('/api/v1/investigate', json=scope)
        assert response.status_code == 200, response.text
        result = response.json()
        assert result['response_plan']['source'] == 'ai'
        assert result['response_plan']['status'] == 'completed'
        assert all(a['status'] == 'completed' for a in result['assessments'])
        assert result['timings']['llm_calls'] == 4
        assert result['timings']['llm_calls'] <= settings.max_llm_calls
        assert next(a for a in result['assessments'] if a['agent'] == 'response')['status'] == 'completed'
        report = client.get(f"/api/v1/investigations/{result['investigation_id']}/report?format=markdown").text
        assert report.count('Response recommendations') == 1
