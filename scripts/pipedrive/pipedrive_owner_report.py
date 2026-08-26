#!/usr/bin/env python3
"""Alpha Surfaces - ownership and coverage report.  gaps | mismatch | sync"""
import os, sys, csv, json, time, urllib.request, urllib.parse, urllib.error
from collections import defaultdict

TOKEN  = os.environ.get("PIPEDRIVE_API_TOKEN") or os.environ.get("ALPHA_PIPEDRIVE_API_TOKEN")
DOMAIN = os.environ.get("PIPEDRIVE_DOMAIN") or os.environ.get("ALPHA_PIPEDRIVE_COMPANY_DOMAIN") or "alphasurfacescomau"
BASE   = f"https://{DOMAIN}.pipedrive.com/api/v1"
if not TOKEN: sys.exit("PIPEDRIVE_API_TOKEN not set. Check: railway status")

ORG_CATEGORY    = "14f7ff9216111e222ce489e888e81ee3f63f35e6"
PERSON_CATEGORY = "da25035c39ec621856e3252165feaf9141423b88"
UNASSIGNED = "- UNASSIGNED / INACTIVE -"

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

def owner_id(rec):
    o = rec.get("owner_id")
    if isinstance(o, dict): return o.get("id") or o.get("value")
    return o

def org_id(rec):
    o = rec.get("org_id")
    if isinstance(o, dict): return o.get("value") or o.get("id")
    return o

def has_value(rec, key):
    return rec.get(key) not in (None, "", [], "0")

def load():
    users = {u["id"]: u for u in (call("GET","/users").get("data") or [])}
    orgs    = get_all("/organizations", "organizations")
    persons = get_all("/persons", "persons")
    return users, orgs, persons

def uname(users, uid):
    u = users.get(uid)
    if not u: return UNASSIGNED
    if not u.get("active_flag"): return f"{u.get('name')} (INACTIVE)"
    return u.get("name") or UNASSIGNED

def gaps():
    print(f"\nCOVERAGE GAPS BY SALESPERSON - {DOMAIN}\n" + "="*96)
    users, orgs, persons = load()
    persons_by_org = defaultdict(list)
    for p in persons:
        oid = org_id(p)
        if oid: persons_by_org[oid].append(p)
    rows = defaultdict(lambda: dict(orgs=0, org_no_cat=0, org_no_contact=0,
                                    people=0, ppl_no_cat=0, ppl_no_org=0))
    worklist = []
    for o in orgs:
        who = uname(users, owner_id(o))
        r = rows[who]; r["orgs"] += 1
        no_cat = not has_value(o, ORG_CATEGORY)
        no_con = len(persons_by_org.get(o["id"], [])) == 0
        if no_cat: r["org_no_cat"] += 1
        if no_con: r["org_no_contact"] += 1
        if no_cat or no_con:
            worklist.append({"owner": who, "organisation": o.get("name"),
                             "missing_category": "YES" if no_cat else "",
                             "no_contacts": "YES" if no_con else "", "org_id": o["id"]})
    for p in persons:
        who = uname(users, owner_id(p))
        r = rows[who]; r["people"] += 1
        if not has_value(p, PERSON_CATEGORY): r["ppl_no_cat"] += 1
        if not org_id(p): r["ppl_no_org"] += 1
    hdr = f"{'Salesperson':<26}{'Orgs':>7}{'no cat':>8}{'no contact':>12}{'People':>8}{'no cat':>8}{'no company':>12}"
    print("\n" + hdr); print("-"*len(hdr))
    order = sorted(rows.items(), key=lambda x: (x[0] == UNASSIGNED, -x[1]["orgs"]))
    tot = defaultdict(int)
    for who, r in order:
        print(f"{who[:25]:<26}{r['orgs']:>7}{r['org_no_cat']:>8}{r['org_no_contact']:>12}"
              f"{r['people']:>8}{r['ppl_no_cat']:>8}{r['ppl_no_org']:>12}")
        for k, v in r.items(): tot[k] += v
    print("-"*len(hdr))
    print(f"{'TOTAL':<26}{tot['orgs']:>7}{tot['org_no_cat']:>8}{tot['org_no_contact']:>12}"
          f"{tot['people']:>8}{tot['ppl_no_cat']:>8}{tot['ppl_no_org']:>12}")
    with open("gaps_by_owner.csv","w",newline="") as f:
        w = csv.writer(f)
        w.writerow(["Salesperson","Organisations","Orgs missing category","Orgs with no contacts",
                    "People","People missing category","People with no company"])
        for who, r in order:
            w.writerow([who, r["orgs"], r["org_no_cat"], r["org_no_contact"],
                        r["people"], r["ppl_no_cat"], r["ppl_no_org"]])
    with open("orgs_missing_category.csv","w",newline="") as f:
        w = csv.DictWriter(f, fieldnames=["owner","organisation","missing_category","no_contacts","org_id"])
        w.writeheader()
        for row in sorted(worklist, key=lambda x: (x["owner"], x["organisation"] or "")):
            w.writerow(row)
    print(f"\nWrote gaps_by_owner.csv  and  orgs_missing_category.csv ({len(worklist)} rows)\n")

def mismatch(apply=False, limit=None):
    print(f"\nCONTACT vs COMPANY OWNER - {DOMAIN}\n" + "="*80)
    users, orgs, persons = load()
    org_owner = {o["id"]: owner_id(o) for o in orgs}
    org_name  = {o["id"]: o.get("name") for o in orgs}
    same = no_org = orphan = 0
    bad, pairs = [], defaultdict(int)
    for p in persons:
        oid = org_id(p)
        if not oid: no_org += 1; continue
        if oid not in org_owner: orphan += 1; continue
        po, oo = owner_id(p), org_owner[oid]
        if po == oo: same += 1; continue
        bad.append((p, oid, po, oo))
        pairs[(uname(users, po), uname(users, oo))] += 1
    print(f"\n  contacts matching their company owner   {same:>6}")
    print(f"  contacts with NO company linked         {no_org:>6}")
    print(f"  company missing from this dataset       {orphan:>6}")
    print(f"  MISMATCHED                              {len(bad):>6}")
    if pairs:
        print(f"\n  {'contact owner':<24} -> {'company owner':<24}{'count':>7}")
        print("  " + "-"*57)
        for (a, b), n in sorted(pairs.items(), key=lambda x: -x[1]):
            print(f"  {a[:23]:<24} -> {b[:23]:<24}{n:>7}")
    with open("owner_mismatch.csv","w",newline="") as f:
        w = csv.writer(f)
        w.writerow(["Contact","Contact owner","Organisation","Company owner","person_id"])
        for p, oid, po, oo in bad:
            w.writerow([p.get("name"), uname(users,po), org_name.get(oid), uname(users,oo), p["id"]])
    print(f"\n  Wrote owner_mismatch.csv ({len(bad)} rows)")
    if not apply:
        print("\n  DRY RUN - nothing written to Pipedrive.")
        print("  Re-run with --apply to set each contact's owner to their company's owner.\n")
        return
    todo = bad[:limit] if limit else bad
    print(f"\n  Applying to {len(todo)} contacts\n")
    done = 0
    for p, oid, po, oo in todo:
        res = call("PUT", f"/persons/{p['id']}", {"owner_id": oo})
        ok = res.get("success"); done += 1 if ok else 0
        print(f"  {'OK  ' if ok else 'FAIL'} {str(p.get('name'))[:28]:<30} "
              f"{uname(users,po)[:18]:<20} -> {uname(users,oo)[:18]}"
              + ("" if ok else f"  {res.get('error')}"))
    print(f"\n  Updated {done} contacts.\n")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "gaps"
    apply = "--apply" in sys.argv
    lim = int(sys.argv[sys.argv.index("--limit")+1]) if "--limit" in sys.argv else None
    if   mode == "gaps":     gaps()
    elif mode == "mismatch": mismatch(apply=False)
    elif mode == "sync":     mismatch(apply=apply, limit=lim)
    else: sys.exit("usage: pipedrive_owner_report.py [gaps|mismatch|sync] [--apply] [--limit N]")
