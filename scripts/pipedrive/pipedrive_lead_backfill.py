#!/usr/bin/env python3
# Parses existing lead notes and writes them to the seven lead fields.
# DEFAULT: report only. Pass --apply to write.
import os, sys, re, json, urllib.request, urllib.error, urllib.parse
from collections import Counter

TOKEN = os.environ.get('PIPEDRIVE_API_TOKEN')
if not TOKEN: sys.exit('PIPEDRIVE_API_TOKEN not set — check `railway status`')
BASE = 'https://alphasurfacescomau.pipedrive.com/api/v1'
APPLY = '--apply' in sys.argv

F_TYPE   = '09908c69b05242596fb067beb464faea1d592e2a'
F_REASON = 'dc25b1d68eb4a267b14e9203ee367de6523cb9b1'
F_STONES = '462063d3a735bd8fbd4b544441f8705843608c0d'
F_STAGE  = '4335c1fe2d07a89272099dda48907c9baa497b4c'

TYPE = {
    'homeowner': 292, 'stonemason': 293, 'fabricator': 293,
    'cabinet maker': 294, 'cabinetmaker': 294, 'joiner': 294,
    'project home builder': 295, 'builder': 296, 'developer': 296,
    'builder/developer': 296, 'architect': 297,
    'interior designer': 298, 'designer': 298,
    'tile outlet': 299, 'retailer': 299, 'stockist': 299,
    'retailer/stockist': 299, 'other': 300,
}
AMBIGUOUS = {'architect/designer', 'architect / designer'}

REASON = {
    'product information': 303, 'general enquiry': 303, 'general': 303,
    'pricing': 306, 'price': 306, 'warranty': 302,
    'where to buy': 305, 'stockist': 305, 'partner': 304,
    'partner enquiry': 304, 'other': 307,
}
STAGE_NEW = 308

def call(method, path, body=None, **q):
    q['api_token'] = TOKEN
    url = f'{BASE}{path}?' + urllib.parse.urlencode(q)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')

def plain(html):
    t = (html or '').replace('<br>', '\n').replace('<br/>', '\n').replace('</p>', '\n')
    t = re.sub(r'<[^>]+>', '', t)
    return t.replace('&nbsp;', ' ').replace('&amp;', '&')

def field(text, name):
    m = re.search(rf'^\s*{name}\s*:\s*(.+)$', text, re.I | re.M)
    if not m: return ''
    v = m.group(1).strip()
    return '' if v in ('—', '-', '', 'None') else v

leads, start = [], 0
while True:
    st, r = call('GET', '/leads', limit=100, start=start, sort='add_time DESC')
    batch = r.get('data') or []
    leads += batch
    pg = (r.get('additional_data') or {}).get('pagination') or {}
    if not pg.get('more_items_in_collection'): break
    start = pg['next_start']

print(f'{len(leads)} leads\n')
stats = Counter()
unmapped_roles, unmapped_reasons, plan = Counter(), Counter(), []

for l in leads:
    st, r = call('GET', '/notes', lead_id=l['id'])
    notes = r.get('data') or []
    if not notes:
        stats['no note'] += 1
        continue
    text = '\n'.join(plain(n.get('content')) for n in notes)

    patch, why = {}, []
    is_sample = bool(re.search(r'^\s*Sample Request', text, re.I | re.M))

    role = field(text, 'Role').strip().lower()
    if role:
        if role in AMBIGUOUS:
            unmapped_roles[role] += 1
            why.append('AMBIGUOUS role, left blank')
        elif role in TYPE:
            patch[F_TYPE] = TYPE[role]
        else:
            unmapped_roles[role] += 1
            why.append(f'unmapped role "{role}"')

    if is_sample:
        patch[F_REASON] = 301
    else:
        rs = field(text, 'Reason').strip().lower()
        if rs:
            if rs in REASON: patch[F_REASON] = REASON[rs]
            else: unmapped_reasons[rs] += 1; why.append(f'unmapped reason "{rs}"')

    stones = field(text, 'Stones')
    if stones: patch[F_STONES] = stones[:255]

    patch[F_STAGE] = STAGE_NEW

    if not patch:
        stats['nothing to write'] += 1
        continue
    plan.append((l, patch, why))
    stats['will write'] += 1

print('--- plan ---')
for l, patch, why in plan[:12]:
    print(f"  {(l.get('title') or '')[:62]}")
    print(f"    type={patch.get(F_TYPE)} reason={patch.get(F_REASON)} "
          f"stones={str(patch.get(F_STONES))[:40]!r} stage={patch.get(F_STAGE)}"
          + (f"   [{'; '.join(why)}]" if why else ''))
if len(plan) > 12: print(f'  … and {len(plan)-12} more')

print(f'\n{dict(stats)}')
if unmapped_roles:   print(f'roles needing a decision: {dict(unmapped_roles)}')
if unmapped_reasons: print(f'reasons needing a decision: {dict(unmapped_reasons)}')

if not APPLY:
    print('\nReport only. Re-run with --apply to write.')
    sys.exit()

print('\n--- writing ---')
ok = fail = 0
for l, patch, _ in plan:
    st, r = call('PATCH', f"/leads/{l['id']}", patch)
    if st == 200 and r.get('success'): ok += 1
    else:
        fail += 1
        print(f"  FAILED {l['id']} {st} {str(r.get('error'))[:120]}")
print(f'{ok} written, {fail} failed')
print('\nPipedrive returns 200 True even when it silently drops keys.')
print('Open three leads in the UI and confirm before trusting this.')
