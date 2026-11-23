import time
from types import SimpleNamespace

import httpx
from openai import APIStatusError, APITimeoutError
import pytest

from app.agents.provider_runtime import completion, decode_json, diagnostics, output_format, ProviderBudgetError, ProviderOutputError
from app.config import settings
from app.schemas.domain import Assessment
from app.tools.shared import Cancelled


class Budget:
    def __init__(self, remaining=600, reserved=0):
        self.llm_calls = 0
        self.tokens = {'prompt': 0, 'completion': 0}
        self.reserved_llm_calls = reserved
        self.seconds = remaining

    def checkpoint(self):
        pass

    def remaining(self):
        return self.seconds


class Client:
    def __init__(self, failures=(), finish='stop'):
        self.chat = SimpleNamespace(completions=self)
        self.failures = list(failures)
        self.calls = []
        self.finish = finish

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.failures:
            raise self.failures.pop(0)
        return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=20, completion_tokens=10),
                               choices=[SimpleNamespace(finish_reason=self.finish)])


def http_error(status):
    response = httpx.Response(status, request=httpx.Request('POST', 'https://example.invalid'))
    return APIStatusError('synthetic error', response=response, body=None)


@pytest.mark.parametrize('error', [APITimeoutError(request=httpx.Request('POST', 'https://example.invalid')),
                                  http_error(503), http_error(429)])
def test_transient_failure_retries_once_and_counts_each_attempt(monkeypatch, error):
    monkeypatch.setattr(settings, 'llm_max_retries', 1)
    monkeypatch.setattr(time, 'sleep', lambda seconds: None)
    budget = Budget()
    client = Client([error])
    completion(client, budget, 'response', 'gemini', model='mock', messages=[])
    assert len(client.calls) == budget.llm_calls == 2
    assert budget.tokens == {'prompt': 20, 'completion': 10}
    assert all(c['reasoning_effort'] == 'low' for c in client.calls)


@pytest.mark.parametrize('status', [400, 401, 403, 404])
def test_configuration_errors_never_retry(monkeypatch, status):
    monkeypatch.setattr(settings, 'llm_max_retries', 1)
    budget = Budget()
    client = Client([http_error(status)])
    with pytest.raises(APIStatusError):
        completion(client, budget, 'response', 'gemini', model='mock', messages=[])
    assert budget.llm_calls == len(client.calls) == 1


def test_timeout_does_not_spend_the_response_reservation(monkeypatch):
    monkeypatch.setattr(settings, 'max_llm_calls', 2)
    monkeypatch.setattr(settings, 'llm_max_retries', 1)
    budget = Budget(reserved=1)
    client = Client([APITimeoutError(request=httpx.Request('POST', 'https://example.invalid'))])
    with pytest.raises(APITimeoutError):
        completion(client, budget, 'persistence', 'gemini', model='mock', messages=[])
    assert budget.llm_calls == 1


def test_specialist_timeout_reserves_advisor_time(monkeypatch):
    monkeypatch.setattr(settings, 'llm_timeout_seconds', 60)
    budget = Budget(remaining=80, reserved=1)
    client = Client()
    completion(client, budget, 'persistence', 'gemini', model='mock', messages=[])
    assert client.calls[0]['timeout'] == 17
    budget.seconds = 30
    with pytest.raises(ProviderBudgetError):
        completion(client, budget, 'persistence', 'gemini', model='mock', messages=[])
    completion(client, budget, 'response', 'gemini', model='mock', messages=[])
    assert client.calls[-1]['timeout'] == 29


def test_deepseek_does_not_receive_gemini_parameters():
    client = Client()
    completion(client, Budget(), 'response', 'deepseek', model='mock', messages=[])
    assert 'reasoning_effort' not in client.calls[0]


def test_truncated_output_is_identified_not_accepted():
    budget = Budget()
    with pytest.raises(ProviderOutputError) as exc:
        completion(Client(finish='length'), budget, 'response', 'gemini', model='mock', messages=[])
    assert diagnostics(exc.value)['error_code'] == 'output_truncated'
    assert budget.llm_calls == 1


def test_json_fences_are_supported_but_invalid_or_empty_content_rejected():
    text = '```json\n{"text":"Assessment", "evidence_ids":["real-id"], "limitations":[]}\n```'
    assert decode_json(text, Assessment).evidence_ids == ['real-id']
    with pytest.raises(ProviderOutputError):
        decode_json('', Assessment)
    with pytest.raises(ValueError):
        decode_json('{broken', Assessment)


def test_cancellation_prevents_provider_request():
    budget = Budget()
    def cancel():
        raise Cancelled('Test cancellation')
    budget.checkpoint = cancel
    client = Client()
    with pytest.raises(Cancelled):
        completion(client, budget, 'response', 'gemini', model='mock', messages=[])
    assert not client.calls and budget.llm_calls == 0


def test_gemini_schema_requires_a_list_of_limitations():
    schema = output_format('gemini', Assessment)
    assert schema['type'] == 'json_schema'
    assert schema['json_schema']['schema']['properties']['limitations']['type'] == 'array'
    assert output_format('deepseek', Assessment) == {'type': 'json_object'}


def test_usage_counts_thinking_tokens_in_reported_total():
    client = Client()
    client.create = lambda **kwargs: SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20, total_tokens=170),
        choices=[SimpleNamespace(finish_reason='stop')])
    budget = Budget()
    completion(client, budget, 'response', 'gemini', model='mock', messages=[])
    assert budget.tokens == {'prompt': 100, 'completion': 70}


@pytest.mark.parametrize('status, expected', [(401, 'authentication'), (403, 'authentication'),
                                             (404, 'model_not_found'), (429, 'rate_limit'),
                                             (503, 'provider_unavailable'), (400, 'invalid_request')])
def test_provider_error_codes_are_actionable_and_do_not_expose_response_bodies(status, expected):
    error = http_error(status)
    error.body = {'api_key': 'must-not-be-logged'}
    detail = diagnostics(error)
    assert detail['error_code'] == expected
    assert 'must-not-be-logged' not in str(detail)
