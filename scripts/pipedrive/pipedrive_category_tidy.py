#!/usr/bin/env python3
"""Alpha Surfaces - Business Category tidy-up.  report | dedupe | inherit"""
import os, sys, json, time, urllib.request, urllib.parse, urllib.error

TOKEN  = os.environ.get("PIPEDRIVE_API_TOKEN") or os.environ.get("ALPHA_PIPEDRIVE_API_TOKEN")
DOMAIN = os.environ.get("PIPEDRIVE_DOMAIN") or os.environ.get("ALPHA_PIPEDRIVE_COMPANY_DOMAIN") or "alphasurfacescomau"
BASE   = f"https://{DOMAIN}.pipedrive.com/api/v1"
if not TOKEN: sys.exit("PIPEDRIVE_API_TOKEN not set. Check: railway status")

ORG_CATEGORY    = "14f7ff9216111e222ce489e888e81ee3f63f35e6"
PERSON_CATEGORY = "da25035c39ec621856e3252165feaf9141423b88"
ORG_GRADE       = "80907c595c9a19cba2ef8b5de8eb39a06361b6fa"

PRIORITY = ["Stonemason","Cabinet Maker","Tile Outlet","Project Home Builder",
            "Builder/Developer","Architect","Designer","Landscape Architect",
            "Pool Builder","Consumer/Public"]
GRADE_PRIORITY = ["A","B","C","D"]

def call(method, path, payload=None):
    url = f"{BASE}{path}{'&' if '?' in path else '?'}api_token={urllib.parse.quote(TOKEN)}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type":"application/json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429: time.sleep(2*(attempt+1)); continue
            return {"success": False, "error": f"HTTP {e.code}: {e.read().decode()[:300]}"}
    return {"success": False, "error": "rate limited"}

def get_all(path, label):
    out, start = [], 0
    while True:
        r = call("GET", f"{path}?start={start}&limit=500")
        if not r.get("success"): sys.exit(f"  ! {label}: {r.get('error')}")
        out += r.get("data") or []
        more = (r.get("additional_data") or {}).get("pagination") or {}
        print(f"    {label}: {len(out)}", end="\r", flush=True)
        if not more.get("more_items_in_collection"):
            print(f"    {label}: {len(out)}   "); return out
        start = more["next_start"]

def opt_map(entity_path, key):
    for f in get_all(entity_path, "fields"):
        if f["key"] == key:
            return {str(o["id"]): str(o["label"]) for o in (f.get("options") or [])}
    sys.exit(f"field {key} not found on {entity_path}")

def values(rec, key):
    raw = rec.get(key)
    if raw in (None, "", []): return []
    if isinstance(raw, list): return [str(x) for x in raw]
    return [p.strip() for p in str(raw).split(",") if p.strip()]

def pick(labels, priority):
    for p in priority:
        if p in labels: return p
    return labels[0]

def report():
    print(f"\nPipedrive: {DOMAIN}\n" + "="*74)
    print("  loading option lists")
    org_cat_opts = opt_map("/organizationFields", ORG_CATEGORY)
    per_cat_opts = opt_map("/personFields", PERSON_CATEGORY)
    grade_opts   = opt_map("/organizationFields", ORG_GRADE)
    print("  loading records")
    orgs    = get_all("/organizations", "organizations")
    persons = get_all("/persons", "persons")

    def tally(records, key, opts, name):
        none = one = many = 0; multi_examples, combos = [], {}
        for r in records:
            v = values(r, key)
            if not v: none += 1
            elif len(v) == 1: one += 1
            else:
                many += 1
                labels = sorted(opts.get(x, x) for x in v)
                k = " + ".join(labels); combos[k] = combos.get(k, 0) + 1
                if len(multi_examples) < 6:
                    multi_examples.append(f"{r.get('name')}  [{', '.join(labels)}]")
        print(f"\n{name}  (of {len(records)})")
        print(f"  no value    {none:>6}")
        print(f"  one value   {one:>6}")
        print(f"  MULTIPLE    {many:>6}   <-- forced to one by `dedupe`")
        if combos:
            print("  most common combinations:")
            for c, n in sorted(combos.items(), key=lambda x: -x[1])[:8]:
                print(f"     {n:>5}  {c}")
        for e in multi_examples: print(f"     e.g. {e}")
        return many

    a = tally(orgs,    ORG_CATEGORY,    org_cat_opts, "ORGANISATION - Business Category")
    b = tally(persons, PERSON_CATEGORY, per_cat_opts, "PERSON - Business Category")
    c = tally(orgs,    ORG_GRADE,       grade_opts,   "ORGANISATION - Grade")

    org_cat = {}
    for o in orgs:
        v = values(o, ORG_CATEGORY)
        if v: org_cat[o["id"]] = pick(sorted(org_cat_opts.get(x, x) for x in v), PRIORITY)
    missing = wrong = no_org = ok = orphan = 0
    for p in persons:
        org = p.get("org_id"); oid = org.get("value") if isinstance(org, dict) else org
        if not oid: no_org += 1; continue
        if oid not in org_cat: orphan += 1; continue
        want = org_cat[oid]
        have = [per_cat_opts.get(x, x) for x in values(p, PERSON_CATEGORY)]
        if not have: missing += 1
        elif have == [want]: ok += 1
        else: wrong += 1

    print(f"\nPERSON category vs their COMPANY  (of {len(persons)})")
    print(f"  no company linked        {no_org:>6}   cannot inherit")
    print(f"  company has no category  {orphan:>6}   fix the company first")
    print(f"  already correct          {ok:>6}")
    print(f"  MISSING - would be set   {missing:>6}   <-- `inherit` fills these")
    print(f"  differs from company     {wrong:>6}   <-- `inherit` overwrites these")
    print("\n" + "="*74)
    print(f"dedupe would touch  {a+b+c} records")
    print(f"inherit would touch {missing+wrong} persons")
    print("\nPriority: " + " > ".join(PRIORITY))
    print("Grade: " + " > ".join(GRADE_PRIORITY) + "\n")

def dedupe(limit=None):
    print(f"\nDEDUPE on {DOMAIN} - forcing one value\n" + "="*74)
    jobs = [("/organizations", ORG_CATEGORY, "/organizationFields", PRIORITY, "org.Business Category"),
            ("/persons", PERSON_CATEGORY, "/personFields", PRIORITY, "person.Business Category"),
            ("/organizations", ORG_GRADE, "/organizationFields", GRADE_PRIORITY, "org.Grade")]
    total = 0
    for path, key, fpath, prio, name in jobs:
        opts = opt_map(fpath, key); rev = {v: k for k, v in opts.items()}
        recs = get_all(path, name)
        todo = [r for r in recs if len(values(r, key)) > 1]
        if limit: todo = todo[:limit]
        print(f"\n{name}: {len(todo)} to fix")
        for r in todo:
            labels = sorted(opts.get(x, x) for x in values(r, key))
            keep = pick(labels, prio)
            res = call("PUT", f"{path}/{r['id']}", {key: rev[keep]})
            ok = res.get("success"); total += 1 if ok else 0
            print(f"  {'OK  ' if ok else 'FAIL'} {str(r.get('name'))[:38]:<40} "
                  f"[{', '.join(labels)}] -> {keep}" + ("" if ok else f"  {res.get('error')}"))
    print(f"\nUpdated {total} records.\n")

def inherit(limit=None):
    print(f"\nINHERIT on {DOMAIN} - person category from company\n" + "="*74)
    org_opts = opt_map("/organizationFields", ORG_CATEGORY)
    per_opts = opt_map("/personFields", PERSON_CATEGORY)
    per_rev  = {v: k for k, v in per_opts.items()}
    orgs = get_all("/organizations", "organizations")
    persons = get_all("/persons", "persons")
    org_cat = {}
    for o in orgs:
        v = values(o, ORG_CATEGORY)
        if v: org_cat[o["id"]] = pick(sorted(org_opts.get(x, x) for x in v), PRIORITY)
    todo, unmapped = [], set()
    for p in persons:
        org = p.get("org_id"); oid = org.get("value") if isinstance(org, dict) else org
        if not oid or oid not in org_cat: continue
        want = org_cat[oid]
        have = [per_opts.get(x, x) for x in values(p, PERSON_CATEGORY)]
        if have == [want]: continue
        if want not in per_rev: unmapped.add(want); continue
        todo.append((p, want, have))
    if unmapped:
        print(f"\n  ! No matching PERSON option for: {', '.join(sorted(unmapped))}")
        print( "    Add them to the person Business Category field first, then re-run.\n")
    if limit: todo = todo[:limit]
    print(f"{len(todo)} persons to update\n")
    done = 0
    for p, want, have in todo:
        res = call("PUT", f"/persons/{p['id']}", {PERSON_CATEGORY: per_rev[want]})
        ok = res.get("success"); done += 1 if ok else 0
        print(f"  {'OK  ' if ok else 'FAIL'} {str(p.get('name'))[:32]:<34} "
              f"{('[' + ', '.join(have) + ']') if have else '(empty)':<28} -> {want}"
              + ("" if ok else f"  {res.get('error')}"))
    print(f"\nUpdated {done} persons.\n")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "report"
    lim = int(sys.argv[sys.argv.index("--limit")+1]) if "--limit" in sys.argv else None
    if   mode == "report":  report()
    elif mode == "dedupe":  dedupe(lim)
    elif mode == "inherit": inherit(lim)
    else: sys.exit("usage: pipedrive_category_tidy.py [report|dedupe|inherit] [--limit N]")
