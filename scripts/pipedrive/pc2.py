import os, sys, json, re, time, urllib.request, urllib.error, urllib.parse
T = os.environ.get('PIPEDRIVE_API_TOKEN')
if not T: sys.exit('no token')
B = 'https://alphasurfacescomau.pipedrive.com/api/v1'
APPLY = '--apply' in sys.argv
N = int(sys.argv[-1]) if APPLY and sys.argv[-1].isdigit() else 25

def call(m, p, body=None, **q):
    q['api_token'] = T
    u = f'{B}{p}?' + urllib.parse.urlencode(q)
    d = json.dumps(body).encode() if body else None
    r = urllib.request.Request(u, data=d, method=m, headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(r) as x: return x.status, json.load(x)
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read().decode() or '{}')

fl = call('GET','/organizationFields')[1].get('data') or []
OPT = {f['key']: {str(o['id']): o['label'] for o in (f.get('options') or [])} for f in fl}
K = {}
for f in fl:
    n = (f.get('name') or '').strip().lower()
    if n == 'suburb': K['sub'] = f['key']
    if n == 'state': K['st'] = f['key']
    if n in ('post code','postcode'): K['pc'] = f['key']
print('custom fields found:', K or 'NONE')

def v(o, w):
    k = K.get(w)
    if not k or o.get(k) in (None,''): return ''
    m = OPT.get(k) or {}
    return ', '.join(m.get(str(x).strip(), str(x).strip()) for x in str(o[k]).split(','))

def compose(o):
    s = str(o.get('address') or '').strip().rstrip(', ')
    parts = [s] if re.search(r'\b\d{4}\b', s) else [p for p in (s, v(o,'sub'), v(o,'st'), v(o,'pc')) if p]
    return re.sub(r'\s+', ' ', ', '.join(parts).strip(' ,'))

orgs, start = [], 0
while True:
    _, r = call('GET','/organizations', start=start, limit=500)
    orgs += r.get('data') or []
    pg = (r.get('additional_data') or {}).get('pagination') or {}
    if not pg.get('more_items_in_collection'): break
    start = pg['next_start']

miss = [o for o in orgs if not str(o.get('address_postal_code') or '').strip()]
cand = [(o, compose(o)) for o in miss]
good = [(o,a) for o,a in cand if re.search(r'\b\d{4}\b', a)]
some = [(o,a) for o,a in cand if a and not re.search(r'\b\d{4}\b', a)]

print(f'{len(orgs)} orgs, {len(miss)} without postcode')
print(f'  {len(good)} composable WITH postcode')
print(f'  {len(some)} address but no postcode')
print(f'  {len(miss)-len(good)-len(some)} nothing')
best = len(orgs) - len(miss) + len(good)
print(f'best case: {best}/{len(orgs)} ({100*best//len(orgs)}%)')
for o,a in good[:10]: print(f"  {o['id']:>5} {str(o.get('name'))[:28]:<30}{a[:60]}")

if not APPLY: sys.exit('\nreport only. add:  --apply 25')

ok = filled = 0
for o,a in good[:N]:
    st, r = call('PUT', f"/organizations/{o['id']}", {'address': a})
    if st == 200 and r.get('success'):
        ok += 1
        if (r.get('data') or {}).get('address_postal_code'): filled += 1
    else: print(f"  FAIL {o['id']} {st}")
    time.sleep(0.25)
print(f'{ok} written, {filled} now have a structured postcode')
if ok and not filled: print('Pipedrive did NOT geocode on write — stop and tell me.')
