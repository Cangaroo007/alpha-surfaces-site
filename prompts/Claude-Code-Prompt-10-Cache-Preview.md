# Prompt 10: Cache Busting & Preview URL
**Priority:** MEDIUM — Critical for review process
**Run from:** `~/Downloads/alpha-surfaces-site/`

---

## Context

The April 2 meeting revealed that Belinda and Jay were NOT seeing the latest version of the site due to aggressive browser/server caching. This needs to be solved before they can meaningfully review any changes.

Two things are needed:
1. Force cache busting so all users see the latest version
2. A `/preview` URL with hard cache-push headers for shared review

## What to Do

### Step 1: Global Cache-Bust Query Strings

Find all CSS and JS references across all HTML files and increment the `?v=N` version number:

```bash
grep -rn "\.css?v=\|\.js?v=" public/ --include="*.html" | head -30
```

Increment every `?v=N` to `?v=N+1`. If there are no version strings yet, add `?v=1` to every CSS `<link>` and `<script>` tag.

Better yet, use the current git commit hash as the version:
```bash
HASH=$(git rev-parse --short HEAD)
echo "Current hash: $HASH"
```

Then replace all `?v=...` with `?v=$HASH` across all HTML files:
```bash
# This is a bulk find-and-replace — be careful
find public/ -name "*.html" -exec sed -i "s/?v=[a-zA-Z0-9]*/?v=$HASH/g" {} \;
```

### Step 2: Add No-Cache Headers to Server

In `server.js`, add middleware to prevent browser caching during the review period:

```bash
grep -n "express.static\|app.use.*static\|cache" server.js | head -10
```

Add cache-control headers:
```javascript
// Add before the static file middleware
app.use((req, res, next) => {
  // Aggressive no-cache for HTML pages
  if (req.path.endsWith('.html') || req.path === '/' || !req.path.includes('.')) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  // Short cache for assets (CSS, JS, images) — they have ?v= cache busters
  if (req.path.match(/\.(css|js)$/)) {
    res.setHeader('Cache-Control', 'public, max-age=300'); // 5 minutes
  }
  next();
});
```

### Step 3: Set Up /preview Route

Create a `/preview` route that forces a completely fresh load:

```javascript
// Preview route — forces complete cache bypass
app.get('/preview', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Clear-Site-Data', '"cache"');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Preview route for specific pages
app.get('/preview/:page', (req, res) => {
  const page = req.params.page;
  const filePath = path.join(__dirname, 'public', `${page}.html`);
  if (require('fs').existsSync(filePath)) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.sendFile(filePath);
  } else {
    res.status(404).send('Page not found');
  }
});
```

### Step 4: Add a meta refresh tag to all pages (belt and braces)

In the `<head>` of all HTML pages:
```html
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
```

### Step 5: Test
```bash
node server.js &
# Check headers
curl -I http://localhost:3000/ 2>/dev/null | grep -i cache
curl -I http://localhost:3000/preview 2>/dev/null | grep -i cache
kill %1
```

Verify:
- [ ] `/preview` returns the homepage with no-cache headers
- [ ] `/preview/collections` returns the collections page
- [ ] All CSS/JS files have updated `?v=` strings
- [ ] Browser dev tools show no cached assets when loading through `/preview`

### Step 6: Commit
```bash
git add -A
git commit -m "chore: add cache busting, no-cache headers, and /preview URL for review"
```

### Step 7: Push and verify on Railway
```bash
git pull --rebase origin main && git push
```

Wait ~60 seconds, then test:
```
https://alpha-surfaces-site-production.up.railway.app/preview
```

Send this URL to Belinda and Jay for review.
