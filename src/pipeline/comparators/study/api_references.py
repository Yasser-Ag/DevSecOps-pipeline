"""Independent crAPI ownership and response predicates, not detector-derived labels."""
import hashlib
import html
import json
import re


def vehicle_mail(body):
    text=html.unescape(re.sub('<[^>]+>',' ',body))
    vin=re.search(r'VIN:\s*([A-Za-z0-9]+)',text)
    pin=re.search(r'Pincode:\s*([A-Za-z0-9]+)',text)
    if not vin or not pin:raise ValueError('Vehicle enrollment details absent')
    return {'vin':vin[1],'pincode':pin[1]}


def ownership(accounts):
    ids=[]
    for role in ('a','b'):
        rows=accounts[role]['vehicles']
        if len(rows)!=1:raise ValueError('Expected one independently enrolled vehicle per account')
        ids.append(rows[0]['uuid'])
    if ids[0]==ids[1] or accounts['a']['email']==accounts['b']['email']:
        raise ValueError('Accounts or owned objects are not distinct')
    return dict(zip(('a','b'),ids))


def location_matches(response,vehicle_id,owner_email):
    body=response.get('body')
    return (response['status']==200 and isinstance(body,dict) and body.get('carId')==vehicle_id
        and body.get('email')==owner_email and isinstance(body.get('vehicleLocation'),dict)
        and all(k in body['vehicleLocation'] for k in ('latitude','longitude')))


def project_schema(upstream,vehicle_ids,base):
    result=json.loads(json.dumps(upstream))
    location='/identity/api/v2/vehicle/{vehicleId}/location';listing='/identity/api/v2/vehicle/vehicles'
    paths={listing:result['paths'][listing]}
    for role,vehicle in vehicle_ids.items():
        route=location.replace('{vehicleId}',vehicle)
        entry=json.loads(json.dumps(result['paths'][location]));entry.pop('parameters',None)
        entry['get']['operationId']='location_'+role
        paths[route]=entry
    result['paths']=paths;result['servers']=[{'url':base}]
    return result


def bearer_digest(token):return hashlib.sha256(('Bearer '+token).encode()).hexdigest()
