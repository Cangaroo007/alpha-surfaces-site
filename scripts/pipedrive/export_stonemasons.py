#!/usr/bin/env python3
# READ-ONLY against Pipedrive. Writes public/data/stonemasons.json for the
# Sprint B typeahead on public/order-sample.html.
#
# Scope: EVERY organisation, not just those categorised Stonemason. Homeowners
# routinely know their cabinetmaker and not the stonemason who actually cuts the
# benchtop, and some cabinetmakers go straight to the stonemason themselves — so
# a Stonemason-only list fails the person most likely to need it. 1,280 of the
# 3,025 orgs are Cabinet Makers against 229 Stonemasons; filtering to Stonemason
# discarded the larger half of the answer.
#
# The filename stays stonemasons.json deliberately. A stale cached copy of
# order-sample.html would 404 on a renamed path and lose the lookup entirely;
# the old {id,name,suburb,state,postcode} shape is a strict subset of the new
# one, so an old client reads the new file without noticing `category`.
#
# Output is minified. Uncompressed it is ~320KB, but it is served through
# Cloudflare with content-encoding: gzip (verified), so the wire cost is ~60KB
# for a single cached fetch.
import os, sys, json, time, urllib.request, urllib.parse

TOKEN = os.environ.get('PIPEDRIVE_API_TOKEN')
if not TOKEN:
    sys.exit('PIPEDRIVE_API_TOKEN not set — check `railway status`')

BASE = 'https://alphasurfacescomau.pipedrive.com/api/v1'
CAT  = '14f7ff9216111e222ce489e888e81ee3f63f35e6'   # org Business Category (set)
OUT  = 'public/data/stonemasons.json'

# Ranked ahead of other categories on an equal-quality name match, because these
# are the businesses that actually stand between Alpha and an installed benchtop.
TRADE_FIRST = ('Stonemason', 'Cabinet Maker')


def get(path, **p):
    p['api_token'] = TOKEN
    with urllib.request.urlopen(f'{BASE}{path}?' + urllib.parse.urlencode(p), timeout=60) as r:
        return json.load(r)


fld = next((f for f in (get('/organizationFields').get('data') or []) if f.get('key') == CAT), None)
if not fld:
    sys.exit('Business Category field not found')
options = {str(o['id']): o.get('label') for o in (fld.get('options') or [])}

rows, start = [], 0
while True:
    r = get('/organizations', start=start, limit=500)
    for o in r.get('data') or []:
        ids = [v.strip() for v in str(o.get(CAT) or '').split(',') if v.strip()]
        labels = [options.get(i) for i in ids if options.get(i)]
        rows.append({
            'id': o['id'],
            'name': o.get('name'),
            'suburb': o.get('address_locality') or '',
            'state': o.get('address_admin_area_level_1') or '',
            'postcode': o.get('address_postal_code') or '',
            'category': labels[0] if labels else '',
        })
    pg = (r.get('additional_data') or {}).get('pagination') or {}
    if not pg.get('more_items_in_collection'):
        break
    start = pg['next_start']
    time.sleep(0.1)

# Trade categories first, then alphabetical. The client preserves this order for
# equal-quality matches, so "Smith" surfaces the stonemason before the pool builder.
rows.sort(key=lambda x: (x['category'] not in TRADE_FIRST, (x['name'] or '').lower()))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, 'w') as f:
    json.dump(rows, f, separators=(',', ':'))

from collections import Counter
counts = Counter(r['category'] or '(uncategorised)' for r in rows)
blind = [r['name'] for r in rows if not r['suburb'] and not r['postcode']]
print(f'{len(rows)} organisations → {OUT} ({os.path.getsize(OUT):,} bytes minified)')
for label, n in counts.most_common():
    print(f'  {n:>5}  {label}')
print(f'\n{len(blind)} have no suburb or postcode — ambiguous in the typeahead')
for n in blind[:10]:
    print('   ', n)
