# Prompt 08: Downloads Section & Document Pages
**Priority:** MEDIUM-HIGH
**Run from:** `~/Downloads/alpha-surfaces-site/`
**Depends on:** Care & Maintenance doc (RECEIVED). Fabrication Guide and Warranty may be pending.

---

## Context

The April 2 meeting agreed: Fabrication Guide, Warranty, and Care & Maintenance should each have their own page, styled the same as the Privacy Policy page, with a PDF download button. The Privacy Policy page should also get a PDF download button added.

All three documents have been copied into `assets/documents/` within this repo:
- `assets/documents/Alpha Surfaces Care and Maintence document - BK.docx` — Care & Maintenance
- `assets/documents/Alpha Surfaces Fabrication and Installation Guide - BK.docx` — Fabrication Guide
- `assets/documents/Alpha Surfaces Warranty Download .docx` — Warranty

## What to Do

### Step 1: Verify the documents
```bash
ls -la assets/documents/
```

### Step 2: Examine the Privacy Policy page for template

The Privacy Policy page is the design template for all document pages.

```bash
ls public/privacy* 2>/dev/null
cat public/privacy-policy.html | head -50
```

Study its structure:
- Header/nav
- Content area with styled text
- Footer
- Fonts (Concrette S headings, Degular body)
- Colour scheme (olive, cream, charcoal)

### Step 3: Create the downloads directory
```bash
mkdir -p public/downloads/
```

### Step 4: Process each document

For each document that's available:

**4a. Convert content to HTML**
If the document is a Word doc (.docx):
```bash
# Use pandoc to convert to HTML
pandoc "assets/documents/Alpha Surfaces Care and Maintence document - BK.docx" -o /tmp/doc-content.html --standalone
```

If it's a PDF, extract the text content for the HTML page.

**4b. Create the styled inline page**

Using the Privacy Policy page as a template, create:
- `public/care-and-maintenance.html` — Care & Maintenance
- `public/warranty.html` — Warranty
- `public/fabrication-guide.html` — Fabrication Guide

Each page should:
- Use identical nav, footer, and styling as the Privacy Policy page
- Render the document content as readable HTML
- Include a prominent "Download PDF" button at the top of the content area

**4c. Create/copy PDFs for download**

If the source document is already a PDF, copy it:
```bash
cp "assets/documents/[document].pdf" public/downloads/care-and-maintenance.pdf
```

If it's a Word doc, convert to PDF:
```bash
libreoffice --headless --convert-to pdf "assets/documents/Alpha Surfaces Care and Maintence document - BK.docx" --outdir public/downloads/
```

### Step 5: Add PDF download button to each page

```html
<div class="document-download">
  <a href="/downloads/care-and-maintenance.pdf" class="btn btn-primary download-btn" download>
    Download PDF
  </a>
</div>
```

Style:
```css
.document-download {
  text-align: center;
  padding: 24px 0;
  margin-bottom: 32px;
}
.download-btn {
  display: inline-block;
  background: var(--olive, #564D22);
  color: white;
  padding: 12px 32px;
  text-decoration: none;
  font-family: 'Degular', sans-serif;
  font-size: 14px;
  letter-spacing: 1px;
  text-transform: uppercase;
  transition: background 0.2s;
}
.download-btn:hover {
  background: #3d3818;
}
```

### Step 6: Add PDF download button to existing Privacy Policy page

Update `public/privacy-policy.html` to include the same download button pattern:
```html
<div class="document-download">
  <a href="/downloads/privacy-policy.pdf" class="btn btn-primary download-btn" download>
    Download PDF
  </a>
</div>
```

Also create `public/downloads/privacy-policy.pdf` from the existing HTML page content.

### Step 7: Add routes in server.js

Check if `server.js` needs explicit routes for the new pages (it may serve them automatically as static files):

```bash
grep -n "privacy\|route\|app.get\|static" server.js | head -20
```

If the server uses Express static file serving for `public/`, the new HTML files should be automatically served. If not, add routes:
```javascript
app.get('/care-and-maintenance', (req, res) => res.sendFile(path.join(__dirname, 'public', 'care-and-maintenance.html')));
app.get('/warranty', (req, res) => res.sendFile(path.join(__dirname, 'public', 'warranty.html')));
app.get('/fabrication-guide', (req, res) => res.sendFile(path.join(__dirname, 'public', 'fabrication-guide.html')));
```

### Step 8: Update FAQ Warranty Link

In the About page FAQ section, find the "What warranty is provided?" answer and add a direct link:

```bash
grep -n -A 5 "warranty\|What warranty" public/about.html | head -20
```

Add: `<a href="/warranty">View our full Warranty</a>`

### Step 9: Update Footer

Replace "Product info" link with "DOWNLOADS" sub-header in the footer:

```bash
grep -n "product.*info\|Product Info\|footer.*link\|resources" public/index.html public/about.html public/collections.html | head -20
```

Add links to all three document pages under the DOWNLOADS header:
```html
<div class="footer-column">
  <h4>DOWNLOADS</h4>
  <ul>
    <li><a href="/fabrication-guide">Fabrication Guide</a></li>
    <li><a href="/warranty">Warranty</a></li>
    <li><a href="/care-and-maintenance">Care & Maintenance</a></li>
    <li><a href="/privacy-policy">Privacy Policy</a></li>
  </ul>
</div>
```

### Step 10: Handle missing documents

If Fabrication Guide or Warranty documents haven't been received yet:
- Create the pages with placeholder content
- Add a TODO comment at the top:
```html
<!-- TODO: Replace placeholder content with actual document from Belinda -->
```
- Still create the route and footer links so the structure is ready

### Step 11: Commit
```bash
git add public/care-and-maintenance.html public/warranty.html public/fabrication-guide.html
git add public/downloads/
git add server.js public/about.html public/index.html public/collections.html
git add -A
git commit -m "feat: add Downloads section — Care & Maintenance, Warranty, Fabrication Guide pages with PDF downloads"
```
