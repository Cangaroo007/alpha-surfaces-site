#!/usr/bin/env python3
# Re-submits existing freeform addresses so Pipedrive geocodes them and fills
# the structured subfields the postcode filters depend on.
# REPORT ONLY by default. --apply [N] writes at most N records.
import os, sys, json, re, time, urllib.request, urllib.error, urllib.parse
from collections import Counter

TOKEN = os.environ.get('PIPEDRIVE_API_TOKEN')
if not TOKEN: sys.exit('PIPEDRIVE_API_TOKEN not set')
BASE = 'https://alphasurfacescomau.pipedrive.com/api/v1'
APPLY = '--apply' in sys.argv
LIMIT = int(sys.argv[sys.argv.index('--apply') + 1]) if APPLY and len(sys.argv) > sys.argv.index('--apply') + 1 else 25

STATES = ('QLD','NSW','VIC','SA','WA','TAS','NT','ACT')

def call(method, path, body=None, **q):
    q['api_token'] = TOKEN
    url = f'{BASE}{path}?' + urllib.parse.urlencode(q)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.load(r)
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read().decode() or '{}')

orgs, start = [], 0
while True:
    st, r = call('GET', '/organizations', start=start, limit=500)
    orgs += r.get('data') or []
    pg = (r.get('additional_data') or {}).get('pagination') or {}
    if not pg.get('more_items_in_collection'): break
    start = pg['next_start']

missing = [o for o in orgs if not str(o.get('address_postal_code') or '').strip()]
has_text = [o for o in missing if str(o.get('address') or '').strip()]
no_text  = [o for o in missing if not str(o.get('address') or '').strip()]

def quality(a):
    a = str(a or '')
    pc = bool(re.search(r'\b\d{4}\b', a))
    st = any(re.search(r'\b' + s + r'\b', a.upper()) for s in STATES)
    num = bool(re.search(r'\b\d+[a-zA-Z]?[/\- ]', a))
    if pc and st: return 'strong'
    if pc or st: return 'partial'
    if num: return 'weak'
    return 'unusable'

buckets = Counter(quality(o.get('address')) for o in has_text)

print(f'{len(orgs)} organisations')
print(f'{len(missing)} have no structured postcode')
print(f'  {len(has_text)} have freeform address text — candidates for re-geocoding')
print(f'  {len(no_text)} have no address at all — research or leave\n')
print('Address text quality:')
for k in ('strong','partial','weak','unusable'):
    print(f'  {k:<10}{buckets.get(k,0):>6}')
print(f'\nBest case: {len(orgs)-len(missing)+buckets.get("strong",0)+buckets.get("partial",0)} '
      f'of {len(orgs)} geocoded '
      f'({100*(len(orgs)-len(missing)+buckets.get("strong",0)+buckets.get("partial",0))//len(orgs)}%)')

print('\nSample of strong candidates:')
for o in [x for x in has_text if quality(x.get('address')) == 'strong'][:10]:
    print(f"  {o['id']:>5}  {str(o.get('name'))[:34]:<36}{str(o.get('address'))[:60]}")

if not APPLY:
    print('\nReport only. Re-run with:  --apply 25   to geocode 25 strong candidates.')
    sys.exit()

targets = [o for o in has_text if quality(o.get('address')) == 'strong'][:LIMIT]
print(f'\n--- re-submitting {len(targets)} addresses ---')
ok = fail = filled = 0
for o in targets:
    st, r = call('PUT', f"/organizations/{o['id']}", {'address': str(o.get('address')).strip()})
    if st == 200 and r.get('success'):
        ok += 1
        if (r.get('data') or {}).get('address_postal_code'): filled += 1
    else:
        fail += 1
        print(f"  FAILED {o['id']} {st} {str(r.get('error'))[:100]}")
    time.sleep(0.25)
print(f'{ok} written, {fail} failed, {filled} now carry a postcode')
if ok and not filled:
    print('\nWrote cleanly but no postcodes appeared — Pipedrive is not re-geocoding')
    print('on PUT. Stop here and tell me; the fallback is setting the subfields directly.')
