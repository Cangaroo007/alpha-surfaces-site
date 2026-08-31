import os, sys, json, urllib.request, urllib.error, urllib.parse
T = os.environ.get('PIPEDRIVE_API_TOKEN')
if not T: sys.exit('no token')
B = 'https://alphasurfacescomau.pipedrive.com/api/v1'
APPLY = '--apply' in sys.argv

def call(m, p, body=None, **q):
    q['api_token'] = T
    u = f'{B}{p}?' + urllib.parse.urlencode(q)
    d = json.dumps(body).encode() if body else None
    r = urllib.request.Request(u, data=d, method=m, headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(r) as x: return x.status, json.load(x)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')

fl = call('GET','/organizationFields')[1].get('data') or []
addr = next((f for f in fl if f.get('key')=='address'), None)
if not addr: sys.exit('no address field')
print(f"address field_id = {addr['id']}")

st, h = call('GET','/filters/helpers')
ops = (h.get('data') or {}).get('operators')
print('\noperators available:')
print(json.dumps(ops, indent=1)[:1200])

REGIONS = [
 ('Sunshine Coast', ['455','456','457']),
 ('Brisbane north', ['400','401','402','403','450','451']),
 ('Gold Coast',     ['420','421','422']),
 ('Cairns',         ['486','487','488']),
 ('Townsville',     ['481']),
 ('Mackay',         ['474','475']),
 ('Sydney west',    ['216','217','274','275','276']),
 ('Sydney north',   ['206','207','209','210']),
]

def conds(prefixes):
    return {'glue':'and','conditions':[
      {'glue':'or','conditions':[
        {'object':'organization','field_id':addr['id'],
         'operator':'LIKE \'$%\'','value':p,'extra_value':'postal_code'}
        for p in prefixes]}]}

if not APPLY:
    print('\nWould create:')
    for n, p in REGIONS: print(f'  Trip — {n}   postcodes starting {", ".join(p)}')
    print('\nreport only. add --apply to create ONE test filter (Sunshine Coast).')
    sys.exit()

n, p = REGIONS[0]
st, r = call('POST','/filters', {'name': f'Trip — {n}', 'type':'org', 'conditions': conds(p)})
print(f'\ncreate: HTTP {st}')
print(json.dumps(r)[:500])
