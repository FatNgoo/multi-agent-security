"""Reject automatic demo writes to product or unidentified API deployments."""
import requests

VERIFICATION_API = "http://127.0.0.1:18000"


def require_verification_api(api_url):
    response = requests.get(api_url.rstrip('/') + '/health', timeout=10)
    response.raise_for_status()
    health = response.json()
    if health.get('environment') != 'verification':
        raise RuntimeError(
            'Refusing demo/test writes: API is not marked as verification. '
            'Start verification/compose.yaml and use http://127.0.0.1:18000. '
            'Upload your own logs manually to the product UI.'
        )
    return health
