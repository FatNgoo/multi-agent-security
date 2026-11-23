import json

import pytest
import requests

from scripts.target import require_verification_api


@pytest.mark.parametrize('environment', ['product', 'development', None, 'verification'])
def test_demo_target_requires_explicit_verification_environment(monkeypatch, environment):
    calls = []
    def health_only(url, **kwargs):
        calls.append(url)
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({'status': 'healthy', 'environment': environment}).encode()
        return response
    monkeypatch.setattr(requests, 'get', health_only)
    if environment == 'verification':
        assert require_verification_api('http://localhost:18000')['environment'] == 'verification'
    else:
        with pytest.raises(RuntimeError, match='Refusing demo/test writes'):
            require_verification_api('http://localhost:8000')
    assert len(calls) == 1 and calls[0].endswith('/health')
