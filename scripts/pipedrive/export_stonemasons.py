#!/usr/bin/env python3
# READ-ONLY against Pipedrive. Writes public/data/stonemasons.json for the Sprint B typeahead.
import os, sys, json, urllib.request, urllib.parse

TOKEN = os.environ.get('PIPEDRIVE_API_TOKEN')
if not TOKEN:
    sys.exit('PIPEDRIVE_API_TOKEN not set — check `railway status`')

BASE = 'https://alphasurfacescomau.pipedrive.com/api/v1'
CAT  = '14f7ff9216111e222ce489e888e81ee3f63f35e6'   # org Business Category (set)
OUT  = 'public/data/stonemasons.json'

def get(path, **p):
    p['api_token'] = TOKEN
    with urllib.request.urlopen(f'{BASE}{path}?' + urllib.parse.urlencode(p)) as r:
        return json.load(r)

fld = next((f for f in (get('/organizationFields').get('data') or []) if f.get('key') == CAT), None)
if not fld:
    sys.exit('Business Category field not found')
opt = next((o for o in (fld.get('options') or []) if str(o.get('label','')).strip().lower() == 'stonemason'), None)
if not opt:
    sys.exit('No "Stonemason" option on Business Category')
oid = str(opt['id'])
print(f'Stonemason option id = {oid}')

rows, start = [], 0
while True:
    r = get('/organizations', start=start, limit=500)
    for o in r.get('data') or []:
        if oid in [v.strip() for v in str(o.get(CAT) or '').split(',')]:
            rows.append({
                'id': o['id'],
                'name': o.get('name'),
                'suburb': o.get('address_locality') or '',
                'state': o.get('address_admin_area_level_1') or '',
                'postcode': o.get('address_postal_code') or '',
            })
    pg = (r.get('additional_data') or {}).get('pagination') or {}
    if not pg.get('more_items_in_collection'):
        break
    start = pg['next_start']

rows.sort(key=lambda x: (x['name'] or '').lower())
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, 'w') as f:
    json.dump(rows, f, indent=1)

blind = [r['name'] for r in rows if not r['suburb'] and not r['postcode']]
print(f'{len(rows)} stonemasons → {OUT}')
print(f'{len(blind)} have no suburb or postcode — ambiguous in the typeahead')
for n in blind[:15]:
    print('   ', n)
