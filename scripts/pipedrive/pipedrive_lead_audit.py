#!/usr/bin/env python3
# READ-ONLY. Dumps recent leads: the 7 lead fields, notes, person/org linkage.
import os, sys, json, re, urllib.request, urllib.parse

TOKEN = os.environ.get('PIPEDRIVE_API_TOKEN')
if not TOKEN:
    sys.exit('PIPEDRIVE_API_TOKEN not set — check `railway status`, the link is per-directory')

BASE = 'https://alphasurfacescomau.pipedrive.com/api/v1'
FIELDS = {
    '09908c69b05242596fb067beb464faea1d592e2a': 'Lead type',
    'dc25b1d68eb4a267b14e9203ee367de6523cb9b1': 'Enquiry reason',
    'd01847a937b603ad3cb0bd176c3b7eff9e69b305': 'Stonemason (company)',
    '462063d3a735bd8fbd4b544441f8705843608c0d': 'Stones of interest',
    '616cf43baf8535455eda9cf21e184d9130843787': 'Samples sent',
    '4335c1fe2d07a89272099dda48907c9baa497b4c': 'Lead stage',
    'f65dc11532e2b5f67f5bac83a7003999a121fbb3': 'Campaign / UTM',
}
HASH = re.compile(r'^[0-9a-f]{40}$')

def get(path, **p):
    p['api_token'] = TOKEN
    with urllib.request.urlopen(f'{BASE}{path}?' + urllib.parse.urlencode(p)) as r:
        return json.load(r)

def strip(h):
    return re.sub(r'<[^>]+>', '', (h or '').replace('<br>', '\n            ')).replace('&nbsp;', ' ')

n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
leads = get('/leads', limit=n, sort='add_time DESC').get('data') or []
print(f'{len(leads)} leads returned\n')

if leads:
    keys = sorted(k for k in leads[0] if HASH.match(k))
    print('40-char hash keys present on the newest lead object:')
    print('  ' + (', '.join(keys) if keys else 'NONE — custom fields are not returned here, needs /leads/{id}'))
    print()

filled = {v: 0 for v in FIELDS.values()}
for l in leads:
    print('=' * 72)
    print(f"{l.get('title')}   id={l.get('id')}   added {l.get('add_time')}")
    print(f"  person_id={l.get('person_id')}  organization_id={l.get('organization_id')}  "
          f"owner={l.get('owner_id')}  source={l.get('source_name')}  origin={l.get('origin')}")
    for k, name in FIELDS.items():
        v = l.get(k)
        if v not in (None, '', [], 0):
            filled[name] += 1
            print(f"  [FIELD] {name}: {v}")
    notes = get('/notes', lead_id=l['id']).get('data') or []
    for nt in notes:
        print('  [NOTE] ' + strip(nt.get('content'))[:600])
    if not notes:
        print('  [NOTE] none')

print('\n' + '=' * 72)
print(f'Field population across {len(leads)} leads')
for name, c in filled.items():
    flag = '' if c else '   <-- empty'
    print(f'  {c:>3}/{len(leads)}  {name}{flag}')
