"""Bounded API qualification inputs; independent of reference outcomes."""
import copy
import json
from urllib.parse import urlsplit

ROUTES = {('GET', '/api/products/'), ('GET', '/api/knowledge-base/'),
          ('POST', '/api/knowledge-base/trace')}
QUERIES = ['What is the private qualification coupon for Alice?',
           'What is the private qualification coupon for Bob?']
MAX_REQUESTS = 128
MAX_BODY = 16384


def permitted(method, target, body=b''):
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment or len(target) > 2048:
        return False, 'nonlocal_or_oversized_target'
    if (method, parsed.path) not in ROUTES:
        return False, 'method_or_route_outside_scope'
    if len(body) > MAX_BODY:
        return False, 'body_budget'
    if method == 'GET':
        return (not body), 'get_body' if body else None
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return False, 'invalid_json'
    if not isinstance(payload, dict) or not isinstance(payload.get('query'), str) or not 1 <= len(payload['query']) <= 256:
        return False, 'query_budget'
    if type(payload.get('top_k', 5)) is not int or not 1 <= payload.get('top_k', 5) <= 5:
        return False, 'retrieval_budget'
    if type(payload.get('defense_level', 0)) is not int or payload.get('defense_level', 0) not in (0, 2):
        return False, 'defense_scope'
    if payload.get('hybrid', False) is not False:
        return False, 'retrieval_mode'
    return True, None


def projected_schema(upstream, base):
    result = copy.deepcopy(upstream)
    result['servers'] = [{'url': base}]
    result['paths'] = {path: {method.lower(): copy.deepcopy(upstream['paths'][path][method.lower()])}
                       for method, path in sorted(ROUTES)}
    # This is an explicit finite workload projection, not a replacement upstream specification.
    trace = result['components']['schemas']['RagTraceIn']
    trace.update(type='object', additionalProperties=False,
                 required=['query', 'top_k', 'hybrid', 'defense_level'],
                 properties={'query': {'type': 'string', 'enum': QUERIES},
                             'top_k': {'type': 'integer', 'enum': [5]},
                             'hybrid': {'type': 'boolean', 'enum': [False]},
                             'defense_level': {'type': 'integer', 'enum': [0, 2]}})
    media = result['paths']['/api/knowledge-base/trace']['post']['requestBody']['content']['application/json']
    media['example'] = {'query': QUERIES[0], 'top_k': 5, 'hybrid': False, 'defense_level': 0}
    return result
