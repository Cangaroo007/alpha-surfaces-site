import os, sys, csv, json, urllib.request, urllib.parse
from collections import defaultdict
T = os.environ.get('PIPEDRIVE_API_TOKEN')
if not T: sys.exit('no token')
B = 'https://alphasurfacescomau.pipedrive.com/api/v1'
CAT = '14f7ff9216111e222ce489e888e81ee3f63f35e6'

def get(p, **q):
    q['api_token'] = T
    with urllib.request.urlopen(f'{B}{p}?' + urllib.parse.urlencode(q)) as r:
        return json.load(r)

fld = next(f for f in get('/organizationFields').get('data') or [] if f.get('key') == CAT)
OPT = {str(o['id']): o['label'] for o in fld.get('options') or []}

orgs, start = [], 0
while True:
    r = get('/organizations', start=start, limit=500)
    orgs += r.get('data') or []
    pg = (r.get('additional_data') or {}).get('pagination') or {}
    if not pg.get('more_items_in_collection'): break
    start = pg['next_start']

rows = defaultdict(lambda: defaultdict(int))
for o in orgs:
    pc = str(o.get('address_postal_code') or '').strip()
    if not pc: continue
    key = (pc, o.get('address_locality') or '', o.get('address_admin_area_level_1') or '')
    rows[key]['total'] += 1
    for v in str(o.get(CAT) or '').split(','):
        lbl = OPT.get(v.strip())
        if lbl: rows[key][lbl] += 1

cats = sorted({c for v in rows.values() for c in v if c != 'total'})
with open('alpha_postcode_density.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['postcode','suburb','state','total_orgs'] + cats)
    for (pc, sub, st), v in sorted(rows.items()):
        w.writerow([pc, sub, st, v['total']] + [v.get(c, 0) for c in cats])

print(f'{len(rows)} postcodes -> alpha_postcode_density.csv')
print(f'{sum(v["total"] for v in rows.values())} organisations covered')
sm = sorted(((k[0], v.get('Stonemason',0), v['total']) for k,v in rows.items()), key=lambda x: -x[1])
print('\ntop 15 postcodes by stonemason count:')
for pc, s, t in sm[:15]: print(f'   {pc}  stonemasons {s:>3}  all trades {t:>3}')
