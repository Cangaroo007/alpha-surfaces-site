import os, sys, json, re, time, urllib.request, urllib.error
T = os.environ.get('PIPEDRIVE_API_TOKEN')
if not T: sys.exit('no token')
H = 'https://alphasurfacescomau.pipedrive.com'
APPLY = '--apply' in sys.argv
N = int(sys.argv[-1]) if APPLY and sys.argv[-1].isdigit() else 25

ST = {'QLD':'QLD','QUEENSLAND':'QLD','NSW':'NSW','NEW SOUTH WALES':'NSW','VIC':'VIC',
      'VICTORIA':'VIC','SA':'SA','SOUTH AUSTRALIA':'SA','WA':'WA','WESTERN AUSTRALIA':'WA',
      'TAS':'TAS','TASMANIA':'TAS','NT':'NT','ACT':'ACT'}

def api(method, path, body=None):
    r = urllib.request.Request(H + path, method=method,
        data=json.dumps(body).encode() if body else None,
        headers={'Content-Type':'application/json','x-api-token':T})
    try:
        with urllib.request.urlopen(r) as x: return x.status, json.load(x)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')

fl = api('GET','/api/v1/organizationFields')[1].get('data') or []
OPT = {f['key']:{str(o['id']):o['label'] for o in (f.get('options') or [])} for f in fl}
K = {}
for f in fl:
    n = (f.get('name') or '').strip().lower()
    if n=='suburb': K['sub']=f['key']
    if n=='state': K['st']=f['key']
    if n in ('post code','postcode'): K['pc']=f['key']

def cf(o, w):
    k = K.get(w)
    if not k or o.get(k) in (None,''): return ''
    m = OPT.get(k) or {}
    return m.get(str(o[k]).strip(), str(o[k]).strip()).strip()

def parse(o):
    raw = str(o.get('address') or '').strip()
    up = raw.upper()
    pc = (re.findall(r'\b(\d{4})\b', raw) or [''])[-1] or cf(o,'pc')
    pc = (re.findall(r'\b(\d{4})\b', str(pc)) or [''])[0]
    st = ''
    for k in sorted(ST, key=len, reverse=True):
        if re.search(r'\b'+re.escape(k)+r'\b', up): st = ST[k]; break
    if not st:
        c = cf(o,'st').upper()
        st = ST.get(c, '')
    loc = cf(o,'sub')
    if not loc and raw:
        seg = [s.strip() for s in raw.split(',') if s.strip()]
        for s in reversed(seg):
            t = re.sub(r'\b\d{4}\b','',s)
            for k in ST: t = re.sub(r'\b'+re.escape(k)+r'\b','',t,flags=re.I)
            t = re.sub(r'\b(AUSTRALIA)\b','',t,flags=re.I).strip(' ,-')
            if t and not re.match(r'^(shop|unit|suite|level|p\.?o\.? box)', t, re.I) \
               and not re.search(r'\d+\s*/', t) and len(t) > 2:
                loc = t; break
    street = bool(re.search(r'\d+\s*[a-zA-Z]?\s*/?\s*\d*\s+\w+', raw)) and \
             not re.match(r'^\s*p\.?\s*o\.?\s*box', raw, re.I)
    return loc.title() if loc else '', st, pc, street

orgs, start = [], 0
while True:
    _, r = api('GET', f'/api/v1/organizations?start={start}&limit=500&api_token=' +
               urllib.parse.quote(T) if False else f'/api/v2/organizations?limit=500' +
               (f'&cursor={start}' if start else ''))
    orgs += r.get('data') or []
    start = ((r.get('additional_data') or {}).get('next_cursor'))
    if not start: break

miss = [o for o in orgs if not ((o.get('address') or {}).get('postal_code'))]
plan, nostreet, skip = [], [], []
for o in miss:
    a = o.get('address') or {}
    o['address'] = a.get('value')
    loc, st, pc, street = parse(o)
    if not (pc or (loc and st)): skip.append(o); continue
    (plan if street else nostreet).append((o, loc, st, pc))

print(f'{len(orgs)} orgs · {len(miss)} without a structured postcode')
print(f'  {len(plan)} parseable WITH a street  <-- writing these')
print(f'  {len(nostreet)} parseable but no street (PO box / suburb only) — flagged, not written')
print(f'  {len(skip)} unparseable')
now = len(orgs)-len(miss)
print(f'\ncoverage: {now} ({100*now//len(orgs)}%)  ->  {now+len(plan)} ({100*(now+len(plan))//len(orgs)}%)')
print('\nsample:')
for o,loc,st,pc in plan[:12]:
    print(f"  {o['id']:>5} {str(o.get('name'))[:26]:<28} {loc:<18}{st:<5}{pc}")

if not APPLY: sys.exit('\nreport only. add:  --apply 25')

ok = fail = 0
for o,loc,st,pc in plan[:N]:
    body = {'address': {'value': o.get('address') or f'{loc} {st} {pc}'}}
    if loc: body['address']['locality'] = loc
    if st:  body['address']['admin_area_level_1'] = st
    if pc:  body['address']['postal_code'] = pc
    body['address']['country'] = 'Australia'
    s, r = api('PATCH', f"/api/v2/organizations/{o['id']}", body)
    if s == 200: ok += 1
    else: fail += 1; print(f"  FAIL {o['id']} {s} {str(r.get('error'))[:90]}")
    time.sleep(0.2)
print(f'{ok} written, {fail} failed')
