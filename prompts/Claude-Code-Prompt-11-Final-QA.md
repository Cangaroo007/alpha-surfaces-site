# Prompt 11: Final QA & Verification
**Priority:** CRITICAL — Run LAST after all other prompts
**Run from:** `~/Downloads/alpha-surfaces-site/`

---

## Context

This is the final quality assurance pass before Belinda and Jay review the site. Every change from Prompts 01–10 should be deployed. This prompt verifies everything works.

## Full Verification Checklist

### 1. stones.json Integrity
```bash
python3 -c "
import json
with open('public/data/stones.json') as f:
    data = json.load(f)
stones = data['stones']
print(f'Total stones: {len(stones)}')
print()

from collections import Counter
colls = Counter(s.get('collection','?') for s in stones)
for c, n in sorted(colls.items()):
    print(f'{c}: {n} stones')
print()

# Check every stone has required fields
required = ['name', 'collection', 'finish']
for s in stones:
    missing = [f for f in required if not s.get(f)]
    if missing:
        print(f'WARNING: {s.get(\"name\", \"UNNAMED\")} missing: {missing}')

# Check finishes
finishes = Counter(s.get('finish','?') for s in stones)
print()
print('Finish distribution:')
for f, n in finishes.items():
    print(f'  {f}: {n}')

# Check discontinued flags
disc = [s['name'] for s in stones if s.get('discontinued')]
print(f'\nDiscontinued stones ({len(disc)}): {disc}')

# Check indoor/outdoor flags
io = [s['name'] for s in stones if s.get('indoor_outdoor')]
print(f'Indoor/Outdoor stones ({len(io)}): {io}')
"
```

### 2. Image Integrity
```bash
python3 -c "
import json, os
with open('public/data/stones.json') as f:
    data = json.load(f)

total = 0
missing = 0
for s in data['stones']:
    for img_field in ['hero','thumb','swatch','slab']:
        path = s.get(img_field, s.get(f'{img_field}_image', ''))
        if path:
            total += 1
            # Normalize path
            if path.startswith('/'): full = 'public' + path
            else: full = os.path.join('public/images/stones', path)
            if not os.path.exists(full):
                missing += 1
                print(f'MISSING: {s[\"name\"]} → {img_field} → {full}')

print(f'\nTotal image references: {total}')
print(f'Missing files: {missing}')
if missing == 0:
    print('All images present.')
"
```

### 3. Broken Links Check
```bash
# Check all internal links in HTML files
python3 -c "
import re, os, glob

html_files = glob.glob('public/**/*.html', recursive=True)
broken = []
for f in html_files:
    with open(f) as fh:
        content = fh.read()
    links = re.findall(r'href=[\"'](/[^\"'#]*)[\"']', content)
    for link in links:
        # Check if it's a file or a route
        target = 'public' + link
        if link.endswith('.html') or '.' in link.split('/')[-1]:
            if not os.path.exists(target):
                broken.append(f'{f} → {link}')
        # For routes without extension, check if HTML exists
        elif not os.path.exists(target + '.html') and not os.path.exists(target + '/index.html'):
            # May be a dynamic route — skip
            pass

if broken:
    print(f'{len(broken)} broken links:')
    for b in broken: print(f'  {b}')
else:
    print('No broken file links found.')
"
```

### 4. Content Verification
```bash
echo "=== CRAFTSMANSHIP should be gone ==="
grep -rni "craftsmanship" public/ --include="*.html" --include="*.js" | head -5
echo "(should be empty)"

echo ""
echo "=== SUPERIOR QUALITY AND DURABILITY should exist ==="
grep -rni "superior quality" public/ --include="*.html" | head -5

echo ""
echo "=== Stone. Life. Style. spacing ==="
grep -rn "Stone\." public/index.html | head -5

echo ""
echo "=== Discontinued AlphaZero naming ==="
grep -rni "discontinued.*alpha\|alpha.*zero" public/ --include="*.html" | head -10

echo ""
echo "=== Original AlphaZero should be gone ==="
grep -rni "original.*alpha.*zero" public/ --include="*.html" | head -5
echo "(should be empty)"

echo ""
echo "=== Emerald Haze label (not Carrara) ==="
grep -n "Carrara.*Collection\|Emerald.*Haze" public/about.html | head -5

echo ""
echo "=== Downloads section links ==="
grep -rn "care-and-maintenance\|fabrication-guide\|warranty" public/ --include="*.html" | head -10

echo ""
echo "=== Social links ==="
grep -rn "instagram\|facebook" public/ --include="*.html" | head -10

echo ""
echo "=== Cache bust versions ==="
grep -o "?v=[a-zA-Z0-9]*" public/index.html | sort -u
```

### 5. Certification Logos
```bash
echo "=== Certification logo files ==="
ls -la public/images/certifications/ 2>/dev/null || echo "Directory not found!"

echo ""
echo "=== Logo references in HTML ==="
grep -rn "certifications/" public/ --include="*.html" | head -10
```

### 6. Page-by-Page Visual Check

Start the server and manually verify:
```bash
node server.js &
echo "Server running. Check these URLs in browser:"
echo "  http://localhost:3000/ — Homepage"
echo "  http://localhost:3000/collections — Collections"
echo "  http://localhost:3000/about — About"
echo "  http://localhost:3000/care-and-maintenance — Care & Maintenance"
echo "  http://localhost:3000/warranty — Warranty"
echo "  http://localhost:3000/fabrication-guide — Fabrication Guide"
echo "  http://localhost:3000/privacy-policy — Privacy Policy"
echo "  http://localhost:3000/preview — Preview (no-cache)"
```

#### Homepage checklist:
- [ ] A logo — full shape with rounded bottom
- [ ] A logo — sticks at hero bottom, fades out below
- [ ] Intro paragraph BEFORE quote
- [ ] "SUPERIOR QUALITY AND DURABILITY" (not "CRAFTSMANSHIP")
- [ ] "Stone. Life. Style." — correct spacing
- [ ] No duplicate Autumn Gold label
- [ ] Social icons in footer

#### Collections page checklist:
- [ ] Correct hero image (unchanged)
- [ ] Kitchen image replaced (or TODO comment if Figma export pending)
- [ ] Instagram carousel shell visible
- [ ] Certification logos in quality assurance section
- [ ] Navigation simplified (Collections link goes to page)

#### About page checklist:
- [ ] Hero image swapped to bathroom/lifestyle
- [ ] Module layout: square images, correct grid
- [ ] Alpha Shield: logo only, no doubled text
- [ ] Indoor-Outdoor: large starburst icon
- [ ] Zero Silica: text only
- [ ] "Emerald Haze / Collection 05" (not Carrara)
- [ ] FAQ warranty link works

#### Alpha Zero section:
- [ ] "Discontinued AlphaZero" heading
- [ ] Discount messaging visible
- [ ] Only 10 discontinued stones shown (5 removed entirely, Taj Mahal moved to C05)
- [ ] Swatch clicks open slab image (not detail page)

#### Download pages:
- [ ] Each page loads with correct content
- [ ] PDF download button works on each
- [ ] Footer links work

### 7. Responsive Check
Test at these widths:
- 375px (mobile)
- 768px (tablet)
- 1440px (desktop)

```bash
# Quick check for mobile CSS
grep -n "@media\|min-width\|max-width" public/styles.css | head -20
```

### 8. Final Commit (if fixes needed)
```bash
git add -A
git diff --cached --stat
git commit -m "fix: final QA pass — resolve any remaining issues found during verification"
```

### 9. Push Everything
```bash
git pull --rebase origin main && git push
```

Wait ~60 seconds, then verify on live:
```
https://alpha-surfaces-site-production.up.railway.app/preview
```

### 10. Notify Belinda and Jay
Send them the `/preview` URL for their final review.
