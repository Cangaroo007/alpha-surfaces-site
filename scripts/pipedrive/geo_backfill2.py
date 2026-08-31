import os, sys, json, re, time, urllib.request, urllib.error, urllib.parse
T = os.environ.get('PIPEDRIVE_API_TOKEN')
if not T: sys.exit('no token')
H = 'https://alphasurfacescomau.pipedrive.com'
APPLY = '--apply' in sys.argv
N = int(sys.argv[-1]) if APPLY and sys.argv[-1].isdigit() else 25

ST = {'QLD':'QLD','QUEENSLAND':'QLD','NSW':'NSW','NEW SOUTH WALES':'NSW','VIC':'VIC',
      'VICTORIA':'VIC','SA':'SA','SOUTH AUSTRALIA':'SA','WA':'WA','WESTERN AUSTRALIA':'WA',
      'TAS':'TAS','TASMANIA':'TAS','NT':'NT','ACT':'ACT'}
# Valid AU postcode ranges by state — rejects street numbers masquerading as postcodes.
RANGE = {'NSW':[(1000,2599),(2619,2899),(2921,2999)],'ACT':[(200,299),(2600,2618),(2900,2920)],
         'VIC':[(3000,3999),(8000,8999)],'QLD':[(4000,4999),(9000,9999)],
         'SA':[(5000,5799),(5800,5999)],'WA':[(6000,6797),(6800,6999)],
         'TAS':[(7000,7799),(7800,7999)],'NT':[(800,899),(900,999)]}

def ok_pc(pc, st):
    if not re.fullmatch(r'\d{4}', pc or ''): return False
    n = int(pc)
    if st and st in RANGE: return any(a <= n <= b for a, b in RANGE[st])
    return any(a <= n <= b for r in RANGE.values() for a, b in r)

def v1(path, **q):
    q['api_token'] = T
    u = f'{H}/api/v1{path}?' + urllib.parse.urlencode(q)
    return json.load(urllib.request.urlopen(u))

def v2patch(i, body):
    r = urllib.request.Request(f'{H}/api/v2/organizations/{i}', method='PATCH',
        data=json.dumps(body).encode(),
        headers={'Content-Type':'application/json','x-api-token':T})
    try:
        with urllib.request.urlopen(r) as x: return x.status, json.load(x)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')

fl = v1('/organizationFields').get('data') or []
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

BAD = re.compile(r'\d|\(|\)|/|\bshop\b|\bunit\b|\bsuite\b|\blevel\b|\bbox\b|\btenancy\b|\bcnr\b', re.I)

def clean_loc(t):
    t = re.sub(r'\b\d{4}\b', '', t or '')
    for k in ST: t = re.sub(r'\b'+re.escape(k)+r'\b', ' ', t, flags=re.I)
    t = re.sub(r'\b(AUSTRALIA)\b', ' ', t, flags=re.I)
    t = re.sub(r'\s+', ' ', t).strip(' ,-')
    return '' if (not t or BAD.search(t) or len(t) < 3) else t.title()

def parse(o):
    raw = str(o.get('address') or '').strip()
    up = raw.upper()
    st = ''
    for k in sorted(ST, key=len, reverse=True):
        if re.search(r'\b'+re.escape(k)+r'\b', up): st = ST[k]; break
    if not st: st = ST.get(cf(o,'st').upper().strip(), '')
    # postcode: prefer the custom field, else a trailing 4-digit token that
    # sits after the state or at the end — never a leading street number.
    pc = ''
    c = re.findall(r'\b(\d{4})\b', cf(o,'pc'))
    if c: pc = c[0]
    if not pc:
        tail = raw.split(',')[-1] if ',' in raw else raw
        cands = re.findall(r'\b(\d{4})\b', tail)
        if cands: pc = cands[-1]
    if not ok_pc(pc, st): pc = ''
    loc = clean_loc(cf(o,'sub'))
    if not loc:
        for seg in reversed([s.strip() for s in raw.split(',') if s.strip()]):
            c2 = clean_loc(seg)
            if c2: loc = c2; break
    has_street = bool(re.search(r'\b\d+[a-zA-Z]?\b', raw.split(',')[0])) and \
                 not re.match(r'^\s*p\.?\s*o\.?\s*box', raw, re.I)
    return loc, st, pc, has_street

orgs, start = [], 0
while True:
    r = v1('/organizations', start=start, limit=500)
    orgs += r.get('data') or []
    pg = (r.get('additional_data') or {}).get('pagination') or {}
    if not pg.get('more_items_in_collection'): break
    start = pg['next_start']

miss = [o for o in orgs if not str(o.get('address_postal_code') or '').strip()]
plan, weak, skip = [], [], []
for o in miss:
    loc, st, pc, street = parse(o)
    if pc and st and loc and street: plan.append((o, loc, st, pc))
    elif pc or (loc and st): weak.append((o, loc, st, pc))
    else: skip.append(o)

now = len(orgs) - len(miss)
print(f'{len(orgs)} orgs · {len(miss)} without a postcode')
print(f'  {len(plan)} full + validated (suburb, state, postcode, street)  <-- write')
print(f'  {len(weak)} partial — review, not written')
print(f'  {len(skip)} nothing usable')
print(f'\ncoverage: {now} ({100*now//len(orgs)}%) -> {now+len(plan)} ({100*(now+len(plan))//len(orgs)}%)')
print(f'\n{"id":>6} {"name":<28}{"suburb":<20}{"st":<5}{"pc":<6}source')
for o,loc,st,pc in plan[:20]:
    print(f"  {o['id']:>5} {str(o.get('name'))[:26]:<28}{loc:<20}{st:<5}{pc:<6}{str(o.get('address'))[:40]}")

if not APPLY: sys.exit('\nreport only. add:  --apply 25')
ok = fail = 0
for o,loc,st,pc in plan[:N]:
    s, r = v2patch(o['id'], {'address': {
        'value': o.get('address'), 'locality': loc,
        'admin_area_level_1': st, 'postal_code': pc, 'country': 'Australia'}})
    if s == 200: ok += 1
    else: fail += 1; print(f"  FAIL {o['id']} {s} {str(r.get('error'))[:80]}")
    time.sleep(0.2)
print(f'{ok} written, {fail} failed')
