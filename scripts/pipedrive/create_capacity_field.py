#!/usr/bin/env python3
# Creates the org field 'Slabs Fabricated/Week'. Report-only by default.
import os, sys, json, urllib.request, urllib.error, urllib.parse

TOKEN = os.environ.get('PIPEDRIVE_API_TOKEN')
if not TOKEN: sys.exit('PIPEDRIVE_API_TOKEN not set — check `railway status`')
BASE, APPLY = 'https://alphasurfacescomau.pipedrive.com/api/v1', '--apply' in sys.argv
NAME = 'Slabs Fabricated/Week'

def call(method, path, body=None):
    url = f'{BASE}{path}?api_token=' + urllib.parse.quote(TOKEN)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.load(r)
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read().decode() or '{}')

st, r = call('GET', '/organizationFields')
existing = [f for f in (r.get('data') or []) if f.get('name','').strip().lower() == NAME.lower()]
if existing:
    f = existing[0]
    print(f"Already exists: {f['name']}  key={f['key']}  type={f['field_type']}")
    sys.exit()

print(f"Will create org field: {NAME}  type=double (numeric)")
print("  Rationale: reps are told slabs per WEEK. Grade derives from this,")
print("  monthly = weekly x 4.33. Separate from 'Slabs/Month Target' (a sales target).")
if not APPLY:
    sys.exit('\nReport only. Re-run with --apply to create.')

st, r = call('POST', '/organizationFields', {'name': NAME, 'field_type': 'double'})
if st in (200, 201) and r.get('success'):
    print(f"Created. key={r['data']['key']}")
    print("Add this to the systems record.")
else:
    print(f"FAILED {st} {json.dumps(r)[:300]}")
