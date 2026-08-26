import json,os,sys,time,urllib.parse,urllib.request
T=os.environ.get("PIPEDRIVE_API_TOKEN","").strip()
if not T: sys.exit("PIPEDRIVE_API_TOKEN not set")
B="https://api.pipedrive.com/v1"
def call(p,q=None):
    q=dict(q or {}); q["api_token"]=T
    with urllib.request.urlopen(B+p+"?"+urllib.parse.urlencode(q),timeout=60) as r:
        return json.loads(r.read().decode())
def allrows(p):
    out,s=[],0
    while True:
        d=call(p,{"start":s,"limit":500}); out+=d.get("data") or []
        pg=(d.get("additional_data") or {}).get("pagination") or {}
        if not pg.get("more_items_in_collection"): break
        s=pg["next_start"]; time.sleep(0.35)
    return out
def opts(title,fs):
    print("\n"+"="*60+"\n"+title+"\n"+"="*60)
    for f in fs:
        if f.get("field_type") in ("enum","set") or f.get("key")=="label":
            print("\n  %s  [%s]  key=%s"%(f.get("name"),f.get("field_type"),f.get("key")))
            for o in (f.get("options") or []): print("      -",o.get("label"))
O=call("/organizationFields").get("data") or []
P=call("/personFields").get("data") or []
D=call("/dealFields").get("data") or []
opts("ORGANISATION option fields",O)
opts("PERSON option fields",P)
opts("DEAL / LEAD option fields (leads inherit these)",D)
print("\n"+"="*60+"\nCUSTOM FIELDS\n"+"="*60)
for n,fs in (("ORG",O),("PERSON",P),("DEAL/LEAD",D)):
    print("\n --- %s ---"%n)
    for f in fs:
        if f.get("edit_flag"): print("  %-32s %-10s %s"%(str(f.get("name"))[:32],f.get("field_type"),f.get("key")))
print("\n"+"="*60+"\nORGANISATIONS BY LABEL\n"+"="*60)
lab={}
for f in O:
    if f.get("key")=="label": lab={str(o["id"]):o["label"] for o in (f.get("options") or [])}
orgs=allrows("/organizations"); c={}
for o in orgs:
    k=lab.get(str(o.get("label")),"(none)"); c[k]=c.get(k,0)+1
for k,v in sorted(c.items(),key=lambda kv:-kv[1]): print("  %-32s %s"%(k,v))
print("\n  TOTAL organisations:",len(orgs))
