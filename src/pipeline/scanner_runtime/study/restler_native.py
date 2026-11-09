"""Preserve RESTler bucket units and distinguish stored replay from observed traffic."""
import hashlib
import json
import re


def request_identity(text):
    head,separator,body=text.partition('\r\n\r\n')
    if not separator:raise ValueError('Missing HTTP request header boundary')
    lines=head.split('\r\n');match=re.fullmatch(r'([A-Z]+) (\S+) HTTP/1\.[01]',lines[0])
    if not match:raise ValueError('Unsupported request line')
    auth=[line.split(':',1)[1].strip() for line in lines[1:] if line.lower().startswith('authorization:')]
    if len(auth)>1:raise ValueError('Ambiguous authorization header')
    return {'method':match[1],'path':match[2],
            'authorization_sha256':hashlib.sha256(auth[0].encode()).hexdigest() if auth else None,
            'body_sha256':hashlib.sha256(body.encode()).hexdigest()}


def response_content(text):
    head,separator,body=text.partition('\r\n\r\n')
    if not separator:raise ValueError('Missing HTTP response header boundary')
    match=re.match(r'HTTP/1\.[01] ([0-9]{3})(?: |$)',head)
    if not match:raise ValueError('Unsupported response status')
    try:content=json.loads(body)
    except ValueError:content=body
    return {'status':int(match[1]),'body':content,'body_sha256':hashlib.sha256(body.encode()).hexdigest()}


def parse_bucket(raw,path):
    required={'checker_name','reproducible','verb','endpoint','request_sequence','status_code'}
    if not required<=raw.keys():raise ValueError('Unsupported RESTler bucket schema')
    if not isinstance(raw['request_sequence'],list) or not raw['request_sequence']:raise ValueError('Empty native sequence')
    sequence=[]
    for index,item in enumerate(raw['request_sequence']):
        sequence.append({'native_pointer':f'/request_sequence/{index}',
            'request':request_identity(item['replay_request']),'response':response_content(item['response'])})
    return {'native_path':path,'unit':'native_bug_bucket','checker':raw['checker_name'],
            'reported_endpoint':raw['endpoint'],'reported_method':raw['verb'].strip(),
            'reported_status':str(raw['status_code']),'native_reproducible':raw['reproducible'],
            'reproduction_interpretation':'For NameSpaceRuleChecker this version passes reproduce=False; false is not a failed independent replay.',
            'stored_sequence':sequence,
            'scope':'Stored sequence is not assumed to contain shadow-user traffic; compare external request evidence.'}
