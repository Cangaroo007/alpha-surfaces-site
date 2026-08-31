import os, sys, csv, json, re, urllib.request, urllib.parse
from collections import defaultdict
T=os.environ.get('PIPEDRIVE_API_TOKEN')
if not T: sys.exit('no token')
B='https://alphasurfacescomau.pipedrive.com/api/v1'
CAT='14f7ff9216111e222ce489e888e81ee3f63f35e6'
GR='80907c595c9a19cba2ef8b5de8eb39a06361b6fa'
SRC=os.path.expanduser('~/Downloads/stonemasons_deduped.csv')

def norm(s):
    s=re.sub(r'[^a-z0-9]+',' ',str(s or '').lower())
    s=re.sub(r'\b(pty|ltd|p l|the|t a|t as|trading|as|and|co|group|australia|aust|inc)\b','',s)
    return re.sub(r'\s+',' ',s).strip()

def g(p,**q):
    q['api_token']=T
    with urllib.request.urlopen(f'{B}{p}?'+urllib.parse.urlencode(q)) as r: return json.load(r)

fl=g('/organizationFields',limit=500)['data']
co={str(o['id']):o['label'] for o in next(x for x in fl if x['key']==CAT).get('options') or []}
go={str(o['id']):o['label'] for o in next(x for x in fl if x['key']==GR).get('options') or []}
orgs,s=[],0
while True:
    r=g('/organizations',start=s,limit=500); orgs+=r.get('data') or []
    p=(r.get('additional_data') or {}).get('pagination') or {}
    if not p.get('more_items_in_collection'): break
    s=p['next_start']

def first(o,k,m):
    v=str(o.get(k) or '').split(',')[0].strip()
    return m.get(v,'') if v else ''

idx=defaultdict(list)
for o in orgs: idx[norm(o.get('name'))].append(o)

src=list(csv.DictReader(open(SRC)))
exact,fuzzy,new=[],[],[]
for r in src:
    k=norm(r['name'])
    if k in idx: exact.append((r,idx[k][0]))
    else:
        hits=[o for kk,v in idx.items() for o in v
              if kk and (kk.startswith(k[:12]) or k.startswith(kk[:12])) and len(k)>8]
        (fuzzy if hits else new).append((r,hits[0] if hits else None))

print(f'{len(src)} in file · {len(orgs)} in Pipedrive')
print(f'  {len(exact)} exact name match')
print(f'  {len(fuzzy)} probable match — REVIEW')
print(f'  {len(new)} not found — would be created\n')

gain=[(r,o) for r,o in exact if r['grade'] and not first(o,GR,go)]
notsm=[(r,o) for r,o in exact if first(o,CAT,co) not in ('Stonemason','')]
print(f'{len(gain)} existing records would GAIN a grade')
print(f'{len(notsm)} matched records are categorised as something OTHER than Stonemason:')
for r,o in notsm[:12]: print(f"   {o['name'][:38]:<40} currently {first(o,CAT,co)}")

print('\nprobable matches to review:')
for r,o in fuzzy[:25]:
    print(f"   file: {r['name'][:36]:<38} pipedrive: {o['name'][:36]}")

print(f'\nfirst 25 that look genuinely new:')
for r,_ in new[:25]: print(f"   {r['name'][:40]:<42}{r['suburb'][:18]:<20}{r['postcode']}")

with open('masterlist_match.csv','w',newline='') as f:
    w=csv.writer(f)
    w.writerow(['status','file_name','pd_id','pd_name','pd_category','pd_grade',
                'file_grade','file_suburb','file_postcode','file_email','file_owner'])
    for lbl,pairs in (('exact',exact),('review',fuzzy),('new',new)):
        for r,o in pairs:
            w.writerow([lbl,r['name'],o['id'] if o else '',o['name'] if o else '',
                        first(o,CAT,co) if o else '',first(o,GR,go) if o else '',
                        r['grade'],r['suburb'],r['postcode'],r['email'],r['owner']])
print('\nmasterlist_match.csv written')
