#!/usr/bin/env python3
# READ-ONLY. Postcode coverage and how many orgs fall in each proposed region.
import os, sys, json, re, urllib.request, urllib.parse
from collections import Counter

TOKEN = os.environ.get('PIPEDRIVE_API_TOKEN')
if not TOKEN: sys.exit('PIPEDRIVE_API_TOKEN not set')
BASE = 'https://alphasurfacescomau.pipedrive.com/api/v1'
CAT  = '14f7ff9216111e222ce489e888e81ee3f63f35e6'

REGIONS = [
    ('Sunshine Coast',      4550, 4575),
    ('Brisbane metro',      4000, 4206),
    ('Gold Coast',          4207, 4287),
    ('Toowoomba / Darling', 4350, 4405),
    ('Wide Bay / Bundaberg',4650, 4680),
    ('Mackay',              4740, 4751),
    ('Townsville',          4810, 4819),
    ('Cairns',              4868, 4879),
    ('Sydney metro',        2000, 2234),
    ('Sydney west',         2745, 2770),
    ('Central Coast NSW',   2250, 2263),
    ('Newcastle / Hunter',  2280, 2340),
    ('Wollongong',          2500, 2534),
    ('Melbourne metro',     3000, 3207),
]

def get(path, **p):
    p['api_token'] = TOKEN
    with urllib.request.urlopen(f'{BASE}{path}?' + urllib.parse.urlencode(p)) as r:
        return json.load(r)

fld = next(f for f in get('/organizationFields').get('data') or [] if f.get('key') == CAT)
optmap = {str(o['id']): o['label'] for o in fld.get('options') or []}

orgs, start = [], 0
while True:
    r = get('/organizations', start=start, limit=500)
    orgs += r.get('data') or []
    pg = (r.get('additional_data') or {}).get('pagination') or {}
    if not pg.get('more_items_in_collection'): break
    start = pg['next_start']

with_pc = [o for o in orgs if str(o.get('address_postal_code') or '').strip()]
print(f'{len(orgs)} organisations')
print(f'{len(with_pc)} have a structured postcode  ({100*len(with_pc)//max(len(orgs),1)}%)')
print(f'{len(orgs)-len(with_pc)} do NOT — invisible to any postcode filter\n')

rows = []
for o in with_pc:
    m = re.search(r'\b(\d{4})\b', str(o.get('address_postal_code')))
    if not m: continue
    pc = int(m.group(1))
    cats = [optmap.get(v.strip(), '') for v in str(o.get(CAT) or '').split(',') if v.strip()]
    rows.append((pc, cats))

print(f'{"region":<24}{"total":>7}{"stonemason":>12}{"cab maker":>11}{"architect":>11}')
print('-' * 65)
for name, lo, hi in REGIONS:
    inr = [c for pc, c in rows if lo <= pc <= hi]
    sm = sum(1 for c in inr if 'Stonemason' in c)
    cm = sum(1 for c in inr if 'Cabinet Maker' in c)
    ar = sum(1 for c in inr if 'Architect' in c)
    print(f'{name:<24}{len(inr):>7}{sm:>12}{cm:>11}{ar:>11}')

covered = sum(1 for pc, _ in rows if any(lo <= pc <= hi for _, lo, hi in REGIONS))
print(f'\n{covered} of {len(rows)} geocoded orgs fall inside a defined region')
print(f'{len(rows)-covered} sit outside them — regional, interstate, or a range needs widening')

print('\nTop 15 postcodes overall:')
for pc, n in Counter(pc for pc, _ in rows).most_common(15):
    print(f'   {pc}   {n}')
