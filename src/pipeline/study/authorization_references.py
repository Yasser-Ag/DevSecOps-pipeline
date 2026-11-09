"""Evaluate source-linked ownership independently of a detector's judgment."""
import base64
import hashlib
import json

from study.api_references import location_matches


def account_email(run_id,role):
    """Bound fixture claim lengths while retaining a run-specific identity."""
    if role not in ('a','b'):raise ValueError('Unknown account role')
    return role+'-'+hashlib.sha256(run_id.encode()).hexdigest()[:12]+'@example.com'


def expected_access(actor,owner,mode):
    if mode not in ('raw','gated'):raise ValueError('Unknown experimental mode')
    if actor not in ('a','b'):return 'unauthenticated'
    if actor==owner:return 'own_object'
    return 'cross_user_disclosure' if mode=='raw' else 'cross_user_denied'


def validate_access(response,actor,owner,mode,vehicle_id,email):
    relation=expected_access(actor,owner,mode)
    content=location_matches(response,vehicle_id,email)
    if relation in ('own_object','cross_user_disclosure'):return content
    return response['status'] in (401,403) and not content


def decode_trace(row):
    if row.get('harness_error'):raise ValueError('Transport harness failed')
    body=base64.b64decode(row['response_body_b64'],validate=True)
    if hashlib.sha256(body).hexdigest()!=row['response_sha256']:raise ValueError('Changed response bytes')
    try:value=json.loads(body)
    except ValueError:value=body.decode(errors='replace')
    return {'status':row['status'],'body':value}


def single_route_schema(upstream,vehicle_id,role):
    template='/identity/api/v2/vehicle/{vehicleId}/location'
    route=template.replace('{vehicleId}',vehicle_id)
    result=json.loads(json.dumps(upstream));entry=result['paths'][template]
    entry.pop('parameters',None)
    entry['get']['operationId']='location_'+role
    entry['get'].pop('parameters',None)
    result['paths']={route:{'get':entry['get']}}
    result['servers']=[{'url':'http://authorization-proxy:8080'}]
    return result
