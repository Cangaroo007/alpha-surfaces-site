#!/usr/bin/env node
//
// Minimal smoke server that mounts only the partial-injection middleware
// from server.js (no DB, no admin routes, no integrations). Serves real
// public/ HTML so we can curl pages and confirm the footer partial gets
// injected end-to-end without spinning up Postgres.

'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.SMOKE_PORT || 3940;

const PUBLIC_DIR = path.resolve(path.join(__dirname, '..', 'public'));
const FOOTER_PARTIAL = fs.readFileSync(
  path.join(__dirname, '..', 'views', 'partials', 'footer.html'),
  'utf8'
);
const FOOTER_MARKER = '<!-- FOOTER -->';

function renderHtml(filePath) {
  const html = fs.readFileSync(filePath, 'utf8');
  return html.includes(FOOTER_MARKER)
    ? html.replace(FOOTER_MARKER, FOOTER_PARTIAL)
    : html;
}

function sendHtml(res, filePath) {
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(renderHtml(filePath));
}

app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  let urlPath = req.path;
  if (urlPath === '/') urlPath = '/index.html';
  if (!urlPath.endsWith('.html')) return next();
  const resolved = path.resolve(path.join(PUBLIC_DIR, urlPath));
  if (!resolved.startsWith(PUBLIC_DIR + path.sep)) return next();
  if (!fs.existsSync(resolved)) return next();
  return sendHtml(res, resolved);
});

// Mirror server.js's clean-URL routes for the pages we need to verify
app.get('/', (req, res) => sendHtml(res, path.join(PUBLIC_DIR, 'index.html')));
app.get('/collections', (req, res) => sendHtml(res, path.join(PUBLIC_DIR, 'collections.html')));
app.get('/care-and-maintenance', (req, res) => sendHtml(res, path.join(PUBLIC_DIR, 'care-and-maintenance.html')));
app.get('/warranty', (req, res) => sendHtml(res, path.join(PUBLIC_DIR, 'warranty.html')));
app.get('/surfaces/:slug', (req, res) => {
  const slug = req.params.slug.replace(/[^a-z0-9-]/gi, '');
  const fp = path.join(PUBLIC_DIR, 'surfaces', slug + '.html');
  if (fs.existsSync(fp)) return sendHtml(res, fp);
  res.status(404).send('not found');
});
app.get('/partners/:slug', (req, res) => {
  const slug = req.params.slug.replace(/[^a-z0-9-]/gi, '');
  const fp = path.join(PUBLIC_DIR, 'partners', slug + '.html');
  if (fs.existsSync(fp)) return sendHtml(res, fp);
  res.status(404).send('not found');
});
app.use(express.static(PUBLIC_DIR));

app.listen(PORT, () => console.log(`[smoke] listening on http://localhost:${PORT}`));
