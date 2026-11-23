import json
from types import SimpleNamespace
from app.agents import specialists
from app.config import settings


class FakeTools:
    request = SimpleNamespace(model_dump=lambda **kwargs: {"dataset_ids": ["allowed"]})
    coverage = {"truncated": False, "returned_records": 26}
    tokens = {"prompt": 0, "completion": 0}
    llm_calls = 0

    def checkpoint(self):
        pass

    def remaining(self):
        return 30

    def run(self, role, name, **arguments):
        assert "dataset_id" not in arguments
        return [{"evidence_id": "real-id", "description": "Untrusted log content"}]


def test_provider_tool_scope_and_reference_validation(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "synthetic-test-key")

    def run_with_reference(reference):
        class Client:
            def __init__(self, **kwargs):
                assert kwargs["max_retries"] == 0
                self.chat = SimpleNamespace(completions=self)
                self.count = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def create(self, **kwargs):
                self.count += 1
                if self.count == 1 and kwargs.get('tool_choice') != 'none':
                    calls = [SimpleNamespace(id="call-1", function=SimpleNamespace(name="query_events", arguments='{"dataset_id":"outside-scope"}'))]
                    message = SimpleNamespace(tool_calls=calls, content=None, model_dump=lambda **kw: {"role": "assistant", "content": "tool requested"})
                else:
                    assert 'tools' not in kwargs
                    content = json.dumps({"text": "Giả thuyết cần xác minh", "evidence_ids": [reference], "limitations": ["Lab only"]})
                    message = SimpleNamespace(tool_calls=None, content=content, model_dump=lambda **kw: {"role": "assistant", "content": content})
                return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5))
        monkeypatch.setattr(specialists, "OpenAI", Client)
        tools = FakeTools()
        tools.tokens = {"prompt": 0, "completion": 0}
        return specialists.interpret("persistence", tools, "gemini")

    assert run_with_reference("real-id")["status"] == "completed"
    assert run_with_reference("invented-id")["status"] == "unavailable"
