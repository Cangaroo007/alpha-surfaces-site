#!/usr/bin/env python3
# READ-ONLY. Builds a review sheet for stonemasons missing structured address data.
# Resolves enum option IDs to labels and parses the freeform address field.
import os, sys, json, csv, re, urllib.request, urllib.parse

TOKEN = os.environ.get('PIPEDRIVE_API_TOKEN')
if not TOKEN: sys.exit('PIPEDRIVE_API_TOKEN not set')
BASE = 'https://alphasurfacescomau.pipedrive.com/api/v1'
CAT  = '14f7ff9216111e222ce489e888e81ee3f63f35e6'

STATES = {'QLD':'QLD','QUEENSLAND':'QLD','NSW':'NSW','NEW SOUTH WALES':'NSW',
          'VIC':'VIC','VICTORIA':'VIC','SA':'SA','SOUTH AUSTRALIA':'SA',
          'WA':'WA','WESTERN AUSTRALIA':'WA','TAS':'TAS','TASMANIA':'TAS',
          'NT':'NT','ACT':'ACT'}

def get(path, **p):
    p['api_token'] = TOKEN
    with urllib.request.urlopen(f'{BASE}{path}?' + urllib.parse.urlencode(p)) as r:
        return json.load(r)

fields = get('/organizationFields').get('data') or []
optmap = {f['key']: {str(o['id']): o['label'] for o in (f.get('options') or [])} for f in fields}
oid = next(k for k, v in optmap[CAT].items() if v.strip().lower() == 'stonemason')
watch = {f['key']: f['name'] for f in fields
         if (f.get('name') or '').strip().lower() in ('state','suburb','post code','postcode','region')}

def label(key, raw):
    if raw in (None, ''): return ''
    m = optmap.get(key) or {}
    parts = [str(x).strip() for x in str(raw).split(',')]
    return ', '.join(m.get(p, p) for p in parts)

def parse(addr):
    if not addr: return '', '', ''
    pc = ''
    m = re.findall(r'\b(\d{4})\b', addr)
    if m: pc = m[-1]
    st = ''
    up = addr.upper()
    for k in sorted(STATES, key=len, reverse=True):
        if re.search(r'\b' + re.escape(k) + r'\b', up):
            st = STATES[k]; break
    seg = ''
    for chunk in reversed([c.strip() for c in addr.split(',')]):
        c = chunk.upper()
        if st and re.search(r'\b' + re.escape(st) + r'\b', c) or (pc and pc in chunk):
            seg = chunk; break
    if not seg:
        seg = addr.split(',')[-1].strip()
    sub = seg
    for k in STATES: sub = re.sub(r'\b' + re.escape(k) + r'\b', '', sub, flags=re.I)
    sub = re.sub(r'\b\d{4}\b', '', sub)
    sub = re.sub(r'\b(AUSTRALIA)\b', '', sub, flags=re.I)
    return sub.strip(' ,-'), st, pc

rows, start = [], 0
while True:
    r = get('/organizations', start=start, limit=500)
    for o in r.get('data') or []:
        if oid not in [v.strip() for v in str(o.get(CAT) or '').split(',')]: continue
        if o.get('address_locality') or o.get('address_postal_code'): continue
        addr = o.get('address') or ''
        extras = {lbl: label(k, o.get(k)) for k, lbl in watch.items()}
        sub, st, pc = parse(addr)
        sub = sub or extras.get('Suburb') or ''
        st  = st  or extras.get('State') or ''
        pc  = pc  or extras.get('Post code') or extras.get('Postcode') or ''
        rows.append({
            'pipedrive_id': o['id'],
            'name': o.get('name'),
            'address_in_pipedrive': addr,
            **extras,
            'suggested_suburb': sub,
            'suggested_state': st,
            'suggested_postcode': pc,
            'needs_research': 'YES' if not (sub or pc) else '',
            'alpha_confirmed': '',
            'people': o.get('people_count') or 0,
        })
    pg = (r.get('additional_data') or {}).get('pagination') or {}
    if not pg.get('more_items_in_collection'): break
    start = pg['next_start']

rows.sort(key=lambda x: (x['needs_research'] == '', (x['name'] or '').lower()))
with open('stonemason_address_review.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

need = [r for r in rows if r['needs_research'] == 'YES']
print(f'{len(rows)} rows → stonemason_address_review.csv')
print(f'{len(rows)-len(need)} have a usable suburb or postcode already')
print(f'{len(need)} genuinely need research:')
for r in need: print('   ', r['name'])

seen = {}
for r in rows: seen.setdefault((r['name'] or '').strip().lower(), []).append(r['pipedrive_id'])
dupes = {k: v for k, v in seen.items() if len(v) > 1}
if dupes:
    print(f'\nDuplicate names in this set — merge candidates:')
    for k, v in dupes.items(): print('   ', k, v)
