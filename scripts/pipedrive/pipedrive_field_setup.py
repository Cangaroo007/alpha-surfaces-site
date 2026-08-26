#!/usr/bin/env python3
"""Alpha Surfaces - Pipedrive field setup.  report | apply"""
import os, sys, json, urllib.request, urllib.parse, urllib.error

TOKEN  = os.environ.get("PIPEDRIVE_API_TOKEN") or os.environ.get("ALPHA_PIPEDRIVE_API_TOKEN")
DOMAIN = os.environ.get("PIPEDRIVE_DOMAIN") or os.environ.get("ALPHA_PIPEDRIVE_COMPANY_DOMAIN") or "alphasurfacescomau"
BASE   = f"https://{DOMAIN}.pipedrive.com/api/v1"
if not TOKEN:
    sys.exit("PIPEDRIVE_API_TOKEN not set. Check: railway status")

def call(method, path, payload=None):
    url = f"{BASE}{path}{'&' if '?' in path else '?'}api_token={urllib.parse.quote(TOKEN)}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code}: {e.read().decode()[:400]}"}

def get_all(path):
    out, start = [], 0
    while True:
        r = call("GET", f"{path}?start={start}&limit=500")
        if not r.get("success"):
            print(f"  ! {path}: {r.get('error')}"); return out
        out += r.get("data") or []
        more = (r.get("additional_data") or {}).get("pagination") or {}
        if not more.get("more_items_in_collection"): return out
        start = more["next_start"]

ENTITIES = [("organization","/organizationFields"),("person","/personFields"),("deal","/dealFields")]
PATH = dict(ENTITIES)
LINK_TYPES = {"org":"-> ORGANISATION record","people":"-> PERSON record","user":"-> USER"}
LOOK_FOR = ["grade","slab","stonemason","fabricator","business category","label",
            "capacity","call cycle","pricelist"]

def report():
    print(f"\nPipedrive: {DOMAIN}\n" + "="*78)
    me = call("GET","/users/me")
    if me.get("success"):
        d = me["data"]; print(f"Auth as: {d.get('name')} <{d.get('email')}>  admin={d.get('is_admin')}")
    print()
    index = {}
    for ent, path in ENTITIES:
        fields = get_all(path); index[ent] = fields
        hits = [f for f in fields if any(k in (f.get("name") or "").lower() for k in LOOK_FOR)]
        print(f"--- {ent.upper()} ({len(fields)} fields, {len(hits)} relevant) " + "-"*20)
        for f in hits:
            t = f.get("field_type")
            print(f"  {f['name']:<34} type={t:<16} "
                  f"{'custom' if f.get('edit_flag') else 'built-in':<9} {LINK_TYPES.get(t,'')}")
            print(f"      key={f['key']}")
            if f.get("options"):
                opts = [str(o.get("label")) for o in f["options"]]
                print(f"      options({len(opts)}): {', '.join(opts[:30])}")
        print()
    print("="*78); print("ANSWERS"); print("="*78)
    for target in ["Grade","Slabs/Month Target","Stonemason Used","Stonemason"]:
        found = []
        for ent in index:
            for f in index[ent]:
                if (f.get("name") or "").strip().lower() == target.lower():
                    t = f.get("field_type")
                    found.append(f"{ent.upper():<13} type={t:<14} " +
                        ("IS A RECORD LINK " + LINK_TYPES[t] if t in LINK_TYPES else "FREEFORM / NOT A LINK"))
        print(f"\n{target}:")
        print("\n".join("  "+x for x in found) if found else "  NOT FOUND")
    print("\n" + "="*78)
    print("Field types in use (shows whether org->org linking exists):")
    for ent, _ in ENTITIES:
        print(f"  {ent:<14} {', '.join(sorted(t for t in {f.get('field_type') for f in index[ent]} if t))}")
    print("\nRun `apply` next.\n")

DEAL_FIELDS = [
    ("Lead type","enum",["Homeowner","Stonemason","Cabinet maker","Project home builder",
                         "Builder/developer","Architect","Interior designer","Tile outlet","Other"]),
    ("Enquiry reason","enum",["Sample request","Warranty","General enquiry","Partner enquiry",
                              "Where to buy","Pricing","Other"]),
    ("Stonemason (company)","org",None),
    ("Stones of interest","varchar",None),
    ("Samples sent","date",None),
    ("Lead stage","enum",["New","Contacted","Samples sent","Awaiting stonemason","Passed to rep","Closed"]),
    ("Campaign / UTM","varchar",None),
]
PERSON_FIELDS = [("Stonemason (company)","org",None)]
RENAMES = [("person","Fabricator / installer","Stonemason (installer)")]
ADD_OPTIONS = [("organization","Business Category",["Project Home Builder","Consumer/Public"]),
               ("person","Business Category",["Project Home Builder","Consumer/Public","Landscape Architect"])]

def existing(ent):
    return {(f.get("name") or "").strip().lower(): f for f in get_all(PATH[ent])}

def apply():
    print(f"\nApplying to {DOMAIN}\n" + "="*78)
    keys = {}
    for ent, specs in (("deal",DEAL_FIELDS),("person",PERSON_FIELDS)):
        print(f"\n{ent.upper()} FIELDS")
        have = existing(ent)
        for name, ftype, options in specs:
            f = have.get(name.lower())
            if f:
                print(f"  exists   {ent}.{name:<26} type={f['field_type']:<8} key={f['key']}")
                keys[f"{ent}.{name}"] = f["key"]; continue
            body = {"name": name, "field_type": ftype}
            if options: body["options"] = [{"label":o} for o in options]
            r = call("POST", PATH[ent], body)
            if r.get("success"):
                print(f"  CREATED  {ent}.{name:<26} type={ftype:<8} key={r['data']['key']}")
                keys[f"{ent}.{name}"] = r["data"]["key"]
            else:
                print(f"  FAILED   {ent}.{name}: {r.get('error')}")
    print("\nRENAMES")
    for ent, old, new in RENAMES:
        have = existing(ent)
        if new.lower() in have: print(f"  exists   {ent}.{new}"); continue
        f = have.get(old.lower())
        if not f: print(f"  skip     {ent}.{old} not found"); continue
        r = call("PUT", f"{PATH[ent]}/{f['id']}", {"name": new})
        print(f"  {'RENAMED ' if r.get('success') else 'FAILED  '} {ent}: {old} -> {new}"
              + ("" if r.get("success") else f"  {r.get('error')}"))
    print("\nOPTIONS")
    for ent, fname, new_opts in ADD_OPTIONS:
        f = existing(ent).get(fname.lower())
        if not f: print(f"  skip     {ent}.{fname} not found"); continue
        labels = [str(o.get("label")) for o in (f.get("options") or [])]
        missing = [o for o in new_opts if o not in labels]
        if not missing: print(f"  exists   {ent}.{fname}: already present"); continue
        merged = [{"id":o["id"],"label":o["label"]} for o in f["options"]] + [{"label":o} for o in missing]
        r = call("PUT", f"{PATH[ent]}/{f['id']}", {"options": merged})
        print(f"  {'ADDED   ' if r.get('success') else 'FAILED  '} {ent}.{fname}: {', '.join(missing)}"
              + ("" if r.get("success") else f"  {r.get('error')}"))
    print("\n" + "="*78); print("FIELD KEYS")
    for k,v in keys.items(): print(f"  {k:<40} {v}")
    print()

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "report"
    if mode == "report": report()
    elif mode == "apply": apply()
    else: sys.exit("usage: pipedrive_field_setup.py [report|apply]")
