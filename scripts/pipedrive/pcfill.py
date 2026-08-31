import os, sys, re, json, time, urllib.request, urllib.error, urllib.parse
T = os.environ.get('PIPEDRIVE_API_TOKEN')
if not T: sys.exit('no token')
H = 'https://alphasurfacescomau.pipedrive.com'
PC = 'c76437ab9001412cd0f29371e26a5db6352b6553'
APPLY = '--apply' in sys.argv
N = int(sys.argv[-1]) if APPLY and sys.argv[-1].isdigit() else 25

def g(path, **q):
    q['api_token'] = T
    with urllib.request.urlopen(f'{H}/api/v1{path}?' + urllib.parse.urlencode(q)) as r:
        return json.load(r)

def put(i, body):
    u = f'{H}/api/v1/organizations/{i}?api_token=' + urllib.parse.quote(T)
    r = urllib.request.Request(u, data=json.dumps(body).encode(), method='PUT',
                               headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(r) as x: return x.status, json.load(x)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')

orgs, s = [], 0
while True:
    r = g('/organizations', start=s, limit=500)
    orgs += r.get('data') or []
    p = (r.get('additional_data') or {}).get('pagination') or {}
    if not p.get('more_items_in_collection'): break
    s = p['next_start']

def cl(v):
    m = re.findall(r'\b(\d{4})\b', str(v or ''))
    return m[0] if m else ''

plan, agree, differ, none = [], 0, [], 0
for o in orgs:
    a, c = cl(o.get('address_postal_code')), cl(o.get(PC))
    if a and c:
        if a == c: agree += 1
        else: differ.append((o, c, a))
    elif a: plan.append((o, a))
    elif not c: none += 1

print(f'{len(orgs)} orgs')
print(f'  {agree} agree')
print(f'  {len(plan)} to write')
print(f'  {len(differ)} disagree (skipped)')
print(f'  {none} have neither')
for o, c, a in differ[:15]:
    print(f"  DIFF {o['id']:>5} {str(o.get('name'))[:30]:<32} custom={c} address={a}")
print('sample writes:')
for o, pc in plan[:10]:
    print(f"  {o['id']:>5} {str(o.get('name'))[:30]:<32} {pc}")

if not APPLY: sys.exit('\nreport only. add:  --apply 25')

ok = fail = 0
for o, pc in plan[:N]:
    st, r = put(o['id'], {PC: float(pc)})
    if st == 200 and r.get('success'): ok += 1
    else: fail += 1; print(f"  FAIL {o['id']} {st}")
    time.sleep(0.2)
print(f'{ok} written, {fail} failed')
if ok:
    d = g(f"/organizations/{plan[0][0]['id']}").get('data') or {}
    print(f"verify {plan[0][0]['id']}: Post code = {d.get(PC)!r}")
