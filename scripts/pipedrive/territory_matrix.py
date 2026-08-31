import os, sys, csv, json, re, urllib.request, urllib.parse
from collections import Counter, defaultdict
T = os.environ.get('PIPEDRIVE_API_TOKEN')
if not T: sys.exit('no token')
B = 'https://alphasurfacescomau.pipedrive.com/api/v1'
CAT = '14f7ff9216111e222ce489e888e81ee3f63f35e6'
GR  = '80907c595c9a19cba2ef8b5de8eb39a06361b6fa'
PC  = 'c76437ab9001412cd0f29371e26a5db6352b6553'

TERRITORIES = [
 ('GC North',        4207, 4213),
 ('GC Central',      4214, 4218),
 ('GC South',        4219, 4230),
 ('GC Hinterland',   4270, 4287),
 ('Tweed / Nth NSW', 2478, 2490),
 ('SC South',        4550, 4556),
 ('SC Central',      4557, 4564),
 ('SC North',        4565, 4575),
 ('Moreton Bay',     4500, 4520),
 ('Brisbane North',  4000, 4054),
 ('Brisbane Inner',  4055, 4099),
 ('Brisbane South',  4100, 4180),
 ('Redlands/Bay',    4157, 4184),
 ('Logan/Ipswich',   4300, 4310),
 ('Toowoomba',       4350, 4405),
 ('Wide Bay',        4650, 4680),
 ('Gladstone/Rocky', 4700, 4720),
 ('Mackay',          4740, 4751),
 ('Airlie/Whitsun',  4800, 4805),
 ('Townsville',      4806, 4825),
 ('Cairns/FNQ',      4852, 4885),
 ('Sydney metro',    2000, 2234),
 ('Sydney West',     2140, 2179),
 ('Sydney NW',       2145, 2170),
 ('Newcastle/Hunter',2280, 2340),
 ('Central Coast',   2250, 2263),
 ('Wollongong/Sth',  2500, 2540),
 ('Melbourne',       3000, 3207),
]

def g(path, **q):
    q['api_token'] = T
    with urllib.request.urlopen(f'{B}{path}?' + urllib.parse.urlencode(q)) as r:
        return json.load(r)

fl = g('/organizationFields', limit=500)['data']
co = {str(o['id']): o['label'] for o in next(x for x in fl if x['key']==CAT).get('options') or []}
go = {str(o['id']): o['label'] for o in next(x for x in fl if x['key']==GR).get('options') or []}

orgs, s = [], 0
while True:
    r = g('/organizations', start=s, limit=500)
    orgs += r.get('data') or []
    p = (r.get('additional_data') or {}).get('pagination') or {}
    if not p.get('more_items_in_collection'): break
    s = p['next_start']

def first(o, k, m):
    v = str(o.get(k) or '').split(',')[0].strip()
    return m.get(v, '') if v else ''

def pc(o):
    for v in (o.get(PC), o.get('address_postal_code')):
        m = re.findall(r'\b(\d{4})\b', str(v or ''))
        if m: return int(m[0])
    return None

def terr(p):
    if p is None: return None
    for name, lo, hi in TERRITORIES:
        if lo <= p <= hi: return name
    return 'Other placed'

rows = []
for o in orgs:
    rows.append({'t': terr(pc(o)), 'c': first(o,CAT,co) or 'Uncategorised',
                 'g': first(o,GR,go) or '-'})

CATS = ['Stonemason','Cabinet Maker','Architect','Designer','Builder/Developer',
        'Project Home Builder','Tile Outlet','Landscape Architect','Pool Builder',
        'Consumer/Public','Uncategorised']
GRADES = ['A','B','C','D','-']

by = defaultdict(lambda: {'cat': Counter(), 'gr': Counter(), 'smgr': Counter(), 'n': 0})
for r in rows:
    k = r['t'] or 'NO POSTCODE'
    b = by[k]; b['n'] += 1
    b['cat'][r['c'] if r['c'] in CATS else 'Uncategorised'] += 1
    b['gr'][r['g']] += 1
    if r['c'] == 'Stonemason': b['smgr'][r['g']] += 1

order = [n for n,_,_ in TERRITORIES] + ['Other placed','NO POSTCODE']
order = [k for k in order if k in by]

SHORT = {'Stonemason':'Stone','Cabinet Maker':'Cabinet','Architect':'Arch',
         'Designer':'Design','Builder/Developer':'Build','Project Home Builder':'PHB',
         'Tile Outlet':'Tile','Landscape Architect':'Lscape','Pool Builder':'Pool',
         'Consumer/Public':'Cons','Uncategorised':'None'}

print('\n' + '='*118)
print('BUSINESS TYPE BY TERRITORY')
print('='*118)
hdr = f'{"territory":<19}{"TOT":>5}' + ''.join(f'{SHORT[c]:>8}' for c in CATS)
print(hdr); print('-'*118)
for k in order:
    b = by[k]
    print(f'{k:<19}{b["n"]:>5}' + ''.join(f'{b["cat"].get(c,0) or "":>8}' for c in CATS))
print('-'*118)
tot = Counter()
for b in by.values(): tot.update(b['cat'])
print(f'{"TOTAL":<19}{sum(b["n"] for b in by.values()):>5}' + ''.join(f'{tot.get(c,0):>8}' for c in CATS))

print('\n' + '='*70)
print('GRADE BY TERRITORY   (all businesses)')
print('='*70)
print(f'{"territory":<19}{"TOT":>5}' + ''.join(f'{x:>8}' for x in GRADES) + f'{"graded%":>9}')
print('-'*70)
for k in order:
    b = by[k]; graded = b['n'] - b['gr'].get('-',0)
    pct = f'{100*graded//b["n"]}%' if b['n'] else '-'
    print(f'{k:<19}{b["n"]:>5}' + ''.join(f'{b["gr"].get(x,0) or "":>8}' for x in GRADES) + f'{pct:>9}')

print('\n' + '='*70)
print('STONEMASONS BY GRADE   — the trip target')
print('='*70)
print(f'{"territory":<19}{"TOT":>5}' + ''.join(f'{x:>8}' for x in GRADES) + f'{"A+B":>7}')
print('-'*70)
for k in order:
    b = by[k]; n = sum(b['smgr'].values())
    if not n: continue
    ab = b['smgr'].get('A',0) + b['smgr'].get('B',0)
    print(f'{k:<19}{n:>5}' + ''.join(f'{b["smgr"].get(x,0) or "":>8}' for x in GRADES) + f'{ab:>7}')

with open('territory_matrix.csv','w',newline='') as f:
    w = csv.writer(f)
    w.writerow(['territory','total'] + CATS + ['grade_'+x for x in GRADES] +
               ['stonemason_'+x for x in GRADES])
    for k in order:
        b = by[k]
        w.writerow([k, b['n']] + [b['cat'].get(c,0) for c in CATS] +
                   [b['gr'].get(x,0) for x in GRADES] +
                   [b['smgr'].get(x,0) for x in GRADES])
print('\nterritory_matrix.csv written')
