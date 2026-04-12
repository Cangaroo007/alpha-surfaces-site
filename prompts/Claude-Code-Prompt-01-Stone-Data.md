# Prompt 01: Stone Data & Finishes Update
**Priority:** HIGH — Foundation for everything else
**Run from:** `~/Downloads/alpha-surfaces-site/`
**Verify directory:** `pwd` must show `alpha-surfaces-site` (hyphens, NOT underscores)

---

## Context

The stone finishes spreadsheet has been updated by Belinda (the client) in Google Sheets. It is the **definitive source of truth** for which stones exist, which collection they belong to, and what finish type they have.

The website's stone data lives in `public/data/stones.json` — this file drives all dynamic stone routes and detail pages.

**CRITICAL:** The updated spreadsheet has **47 total stones**. The old site had 52. Several stones have moved between collections, some are brand new, and some have been removed. Every detail below has been verified directly from the PDF export of Belinda's updated Google Sheet dated April 7, 2026.

## What to Do

### Step 1: Read the current stones.json
```bash
cat public/data/stones.json | python3 -c "import sys,json; data=json.load(sys.stdin); [print(f\"{s.get('collection','?')} | {s['name']} | {s.get('finish','?')}\") for s in data['stones']]"
```

### Step 2: Cross-reference against the DEFINITIVE updated spreadsheet data

The spreadsheet contains exactly **47 stones** across 6 groups:

---

**Collection 01 — 6 stones (ALL Polished Finish):**
1. Jewel — Polished Finish
2. Crystal — Polished Finish
3. Fraser — Polished Finish
4. Oyster — Polished Finish
5. Graphite — Polished Finish
6. Brilliance — Polished Finish

> **CHANGES vs old site:** Crystal is CONFIRMED as a C01 stone (it was previously uncertain). Bondi is NOT in the spreadsheet — if it exists on the site, REMOVE it. Oyster is IN the spreadsheet — add it if not present.

---

**Collection 02 — 7 stones:**
1. Shell — Polished Finish
2. Carrara — Polished Finish
3. Oyster Grey — Matte Finish
4. Earthy Concrete — Matte Finish
5. Ash — Polished Finish
6. Arctic — Polished Finish
7. Pearl — Polished Finish

> **No changes** from old data.

---

**Collection 03 — 8 stones:**
1. Salt Stone — Polished Finish
2. Davinci Gris — Polished Finish
3. Desert Dune — Polished Finish
4. Davinci Oro — Polished Finish
5. Whitehaven — Polished Finish — **UV Stable — Indoor/Outdoor**
6. Cabarita — Matte Finish — **UV Stable — Indoor/Outdoor**
7. Torquay — Matte Finish — **UV Stable — Indoor/Outdoor**
8. Broome — Matte Finish — **UV Stable — Indoor/Outdoor**

> **No changes** from old data.

---

**Collection 04 — 8 stones:**
1. Opal Mist — Matte Finish
2. Calacatta Leggera — Polished Finish
3. Metallic Grey — Matte Finish
4. Statuario Gold — Polished Finish
5. Eternity — Polished Finish
6. Glacier — Polished Finish
7. White Cloud — Matte Finish
8. **Arabescato — Polished Finish** ← MOVED here from Collection 05

> **CHANGE:** Arabescato has moved from C05 to C04. Update its `collection` field in stones.json. Old C04 had 7 stones; now has 8.

---

**Collection 05 — 8 stones (ALL Polished Finish):**
1. **Taj Mahal — Polished Finish** ← MOVED here from Original Alpha Zero (was previously discontinued)
2. **Perla Mahal — Polished Finish** ← BRAND NEW stone
3. Calacatta Viola — Polished Finish
4. Autumn Gold — Polished Finish
5. **Emerald Haze — Polished Finish** ← BRAND NEW stone
6. **Viola Ligerra — Polished Finish** ← BRAND NEW stone
7. **Crystal Mahal — Polished Finish** ← BRAND NEW stone
8. **Venato — Polished Finish** ← BRAND NEW stone

> **MAJOR CHANGES:**
> - Arabescato REMOVED from C05 (moved to C04)
> - Taj Mahal MOVED from Alpha Zero to C05 (it is no longer discontinued)
> - 5 brand new stones added: Perla Mahal, Emerald Haze, Viola Ligerra, Crystal Mahal, Venato
> - Old C05 had 3 stones; now has 8
> - For Taj Mahal: if it existed in Alpha Zero on the site, update its collection to C05 and remove `discontinued` flag. It is now a current product.
> - For the 5 new stones: they will need entries created in stones.json. They may not have images yet — create placeholder entries and flag with `"images_pending": true`

---

**Original Alpha Zero — 10 stones (DISCONTINUED):**
1. Silver Travertine — Matt Finish
2. Crystello — Matt Finish
3. Grande Glacier — Matt Finish
4. Basaltina — Matt Finish
5. Carbon — Matt Finish
6. Acropolis — Matt Finish
7. Glacier Grey — Polished Finish
8. Noosa — Matte Finish
9. Calacatta Oro — Polished Finish
10. Serena — Matte Finish

> **CHANGES vs old site (which had 16 Alpha Zero stones):**
> - Taj Mahal MOVED to C05 (no longer discontinued)
> - The following 5 are being REMOVED entirely: Venatino, Patagonia, Calacatta Borghini, Biscotti, Infinity Gris
> - Remove these 5 from stones.json and delete their routes/pages if they have dedicated HTML files

---

### Step 3: Update stones.json

For each stone in the spreadsheet above:
1. Ensure it exists in stones.json with the **correct `collection` value**
2. Set the `finish` field to exactly match the spreadsheet:
   - "Polished Finish" for polished stones
   - "Matte Finish" for matte stones
   - "Matt Finish" for Alpha Zero matt stones (note the spelling difference — single 't' — this matches the spreadsheet exactly)
3. For the 4 UV Stable stones in C03 (Whitehaven, Cabarita, Torquay, Broome), add `"indoor_outdoor": true`
4. For all 10 Alpha Zero stones, add `"discontinued": true`
5. For Taj Mahal: REMOVE `"discontinued": true` if it had it — it is now a current C05 stone
6. For the 5 brand new C05 stones (Perla Mahal, Emerald Haze, Viola Ligerra, Crystal Mahal, Venato):
   - Create new entries with correct collection ("Collection 05") and finish ("Polished Finish")
   - Generate slugs: `perla-mahal`, `emerald-haze`, `viola-ligerra`, `crystal-mahal`, `venato`
   - Set image fields to empty/placeholder — these will be populated when images arrive
   - Add `"images_pending": true` so they can be tracked
7. For Arabescato: change `collection` from "Collection 05" to "Collection 04"
8. REMOVE these stones entirely (they are not in the updated spreadsheet):
   - Bondi (was in C01)
   - Venatino (was in Alpha Zero)
   - Patagonia (was in Alpha Zero)
   - Calacatta Borghini (was in Alpha Zero)
   - Biscotti (was in Alpha Zero)
   - Infinity Gris (was in Alpha Zero)

### Step 4: Update the stone count

Total is now **47 stones** (37 current + 10 discontinued Alpha Zero).

Search the entire codebase for references to "52 stones" or "52 surfaces" or "40 stones" or similar counts and update to 47:

```bash
grep -rn "52\|40" public/ --include="*.html" --include="*.js" --include="*.json" | grep -i "stone\|surface\|colour\|color\|total"
```

### Step 5: Verify

```bash
cat public/data/stones.json | python3 -c "
import sys, json
data = json.load(sys.stdin)
stones = data['stones']
from collections import Counter
colls = Counter(s.get('collection','?') for s in stones)
print(f'Total stones: {len(stones)}')
expected = {'Collection 01': 6, 'Collection 02': 7, 'Collection 03': 8, 'Collection 04': 8, 'Collection 05': 8, 'Original Alpha Zero': 10}
for c in sorted(expected.keys()):
    actual = colls.get(c, 0)
    status = '✅' if actual == expected[c] else f'❌ EXPECTED {expected[c]}'
    print(f'  {c}: {actual} {status}')
total = sum(colls.values())
print(f'\nTotal: {total} {\"✅\" if total == 47 else \"❌ EXPECTED 47\"}\n')
for s in sorted(stones, key=lambda x: (x.get('collection',''), x['name'])):
    flags = []
    if s.get('indoor_outdoor'): flags.append('UV')
    if s.get('discontinued'): flags.append('DISC')
    if s.get('images_pending'): flags.append('NO-IMG')
    flag_str = ' [' + ', '.join(flags) + ']' if flags else ''
    print(f\"  {s.get('collection','?'):20s} | {s['name']:25s} | {s.get('finish','MISSING'):20s}{flag_str}\")
"
```

**EXPECTED OUTPUT:**
```
Total stones: 47
  Collection 01: 6 ✅
  Collection 02: 7 ✅
  Collection 03: 8 ✅
  Collection 04: 8 ✅
  Collection 05: 8 ✅
  Original Alpha Zero: 10 ✅

Total: 47 ✅
```

### Step 6: Commit
```bash
git add public/data/stones.json
git diff --cached --stat
git commit -m "feat: update stones.json — reconcile with Belinda's updated finishes spreadsheet (47 stones, 6 collections)"
```

**DO NOT PUSH YET** — wait until all prompts are done, then push once at the end.
