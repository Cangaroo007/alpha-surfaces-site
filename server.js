const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Config ───
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'alpha2025';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CONTENT_FILE = path.join(DATA_DIR, 'content.json');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Active sessions (in-memory, resets on restart)
const sessions = new Map();

// ─── Middleware ───
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Helpers ───
function loadContent() {
  try {
    return JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
  } catch {
    const defaults = require('./data/defaults.json');
    saveContent(defaults);
    return defaults;
  }
}

function saveContent(data) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(CONTENT_FILE, JSON.stringify(data, null, 2));
}

function authMiddleware(req, res, next) {
  const token = req.cookies?.alpha_session;
  if (token && sessions.has(token)) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ─── Auth Routes ───
app.post('/api/login', (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { created: Date.now() });
    res.cookie('alpha_session', token, { httpOnly: true, sameSite: 'lax', maxAge: 86400000 });
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Wrong password' });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies?.alpha_session;
  if (token) sessions.delete(token);
  res.clearCookie('alpha_session');
  res.json({ ok: true });
});

app.get('/api/auth-check', (req, res) => {
  const token = req.cookies?.alpha_session;
  res.json({ authenticated: !!(token && sessions.has(token)) });
});

// ─── Content API (public read, auth write) ───
app.get('/api/content', (req, res) => {
  res.json(loadContent());
});

app.put('/api/content', authMiddleware, (req, res) => {
  try {
    saveContent(req.body);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save' });
  }
});

// Partial update - merge specific section
app.patch('/api/content/:section', authMiddleware, (req, res) => {
  try {
    const content = loadContent();
    content[req.params.section] = req.body;
    saveContent(content);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save' });
  }
});

// ─── Admin route ───
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ─── Catch-all for SPA ───
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Alpha Surfaces CMS running on port ${PORT}`);
});
