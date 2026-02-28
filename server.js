const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Config ───
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'alpha2025';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CONTENT_FILE = path.join(DATA_DIR, 'content.json');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// ─── Cloudinary ───
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ─── Multer (memory storage) ───
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

// Active sessions (in-memory, resets on restart)
const sessions = new Map();

// ─── Middleware ───
app.use(express.json({ limit: '25mb' }));
app.use(cookieParser());
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "https://res.cloudinary.com", "data:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      scriptSrcAttr: ["'unsafe-inline'"],
    },
  })
);
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
});

// ─── Helpers ───
function loadContent() {
  try {
    return JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
  } catch {
    const defaults = JSON.parse(fs.readFileSync(path.join(__dirname, 'config', 'defaults.json'), 'utf8'));
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
// To generate a hash for a new password, run:
// node -e "const b = require('bcryptjs'); b.hash('yourpassword', 12).then(h => console.log(h))"
// Then set ADMIN_PASSWORD in Railway to the hash string
app.post('/api/login', loginLimiter, async (req, res) => {
  const { password } = req.body;
  const storedPassword = ADMIN_PASSWORD;

  let valid = await bcrypt.compare(password, storedPassword);
  if (!valid && !storedPassword.startsWith('$2')) {
    valid = password === storedPassword;
  }

  if (valid) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { created: Date.now() });
    res.cookie('alpha_session', token, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 86400000 });
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

// ─── File type validation (magic bytes) ───
function validateImageType(buffer) {
  if (buffer.length < 12) return false;

  // JPEG: FF D8 FF
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return true;

  // PNG: 89 50 4E 47
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return true;

  // WebP: bytes 8-11 are "WEBP" (57 45 42 50)
  if (buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) return true;

  // GIF87a: 47 49 46 38 37 61
  // GIF89a: 47 49 46 38 39 61
  if (
    buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 &&
    buffer[3] === 0x38 && (buffer[4] === 0x37 || buffer[4] === 0x39) && buffer[5] === 0x61
  ) return true;

  return false;
}

// ─── Upload route ───
app.post('/api/upload', authMiddleware, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file provided.' });
  }

  if (!validateImageType(req.file.buffer)) {
    return res.status(400).json({ error: 'Invalid file type. Only JPEG, PNG, WebP and GIF images are allowed.' });
  }

  const b64 = req.file.buffer.toString('base64');
  const dataUri = `data:${req.file.mimetype};base64,${b64}`;

  cloudinary.uploader.upload(dataUri, { folder: 'alpha-surfaces' }, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Upload failed.' });
    }
    res.json({ url: result.secure_url });
  });
});

// ─── AI CMS Routes ───
const BACKUP_FILE = path.join(DATA_DIR, 'content.backup.json');

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Too many AI requests. Please slow down.' },
});

// POST /api/ai/chat — Core NL CMS endpoint
app.post('/api/ai/chat', authMiddleware, aiLimiter, async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'Anthropic API key not configured.' });
  }

  try {
    const { messages, attachments } = req.body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'Messages array is required.' });
    }

    const currentContent = loadContent();
    const systemPrompt = `You are the AI content manager for Alpha Surfaces, a premium Australian benchtop brand. You have full knowledge of and control over the website content.

CURRENT WEBSITE CONTENT:
${JSON.stringify(currentContent, null, 2)}

YOUR ROLE:
- Help Belinda and Sean manage their website through natural conversation
- Make content changes, improve copy, rewrite sections, add/remove items
- Understand the brand: luxury, premium, mineral stone, zero crystalline silica, AlphaShield™ Lifetime Stain Resistance Guarantee, Australian market
- Keep all copy consistent with the brand voice: confident, premium, editorial

RESPONSE FORMAT:
Always respond in this exact JSON structure:
{
  "reply": "Your conversational response explaining what you did or answering their question",
  "changes": {
    "fieldPath": "newValue"
  }
}

Field paths use dot notation matching the content schema. Examples:
- "hero.heading" → changes the hero heading
- "hero.badge" → changes the badge text
- "about.quote" → changes the MD quote
- "nav.brand" → changes the brand name in the nav
- "collections.items[0].name" → changes the first collection's name
- "footer.copyright" → changes the footer copyright text

If no content changes are needed, set "changes" to null.

IMPORTANT:
- Never invent product specifications — only use what is in the current content
- Preserve all HTML tags (e.g. <em>) in heading fields
- When rewriting copy, match the existing tone and style unless asked to change it
- Always confirm what you changed in your reply so the user can decide whether to apply it`;

    // Build the Anthropic messages array
    const anthropicMessages = messages.map((msg, idx) => {
      const content = [];

      // Attach images to the last user message
      if (msg.role === 'user' && idx === messages.length - 1 && attachments && attachments.length > 0) {
        for (const att of attachments) {
          if (att.type === 'image' && att.base64 && att.mimeType) {
            content.push({
              type: 'image',
              source: { type: 'base64', media_type: att.mimeType, data: att.base64 },
            });
          }
        }
      }

      content.push({ type: 'text', text: msg.content });
      return { role: msg.role, content };
    });

    const client = new Anthropic();
    const response = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4096,
      system: systemPrompt,
      messages: anthropicMessages,
    });

    // Extract text from the response
    const rawText = response.content
      .filter(b => b.type === 'text')
      .map(b => b.text)
      .join('');

    // Parse the JSON response from Claude
    let parsed;
    try {
      // Try to extract JSON from the response (handles markdown code fences)
      const jsonMatch = rawText.match(/\{[\s\S]*\}/);
      parsed = JSON.parse(jsonMatch ? jsonMatch[0] : rawText);
    } catch {
      // If parsing fails, treat the whole response as a plain reply
      return res.json({ reply: rawText, diff: null, proposedContent: null });
    }

    const reply = parsed.reply || rawText;
    const changes = parsed.changes;

    if (!changes || Object.keys(changes).length === 0) {
      return res.json({ reply, diff: null, proposedContent: null });
    }

    // Build diff and proposedContent
    const proposedContent = JSON.parse(JSON.stringify(currentContent));
    const diff = {};

    for (const [fieldPath, newValue] of Object.entries(changes)) {
      // Get current value using bracket and dot notation
      const before = getNestedValue(currentContent, fieldPath);
      setNestedValue(proposedContent, fieldPath, newValue);
      diff[fieldPath] = {
        before: before !== undefined ? String(before) : '',
        after: String(newValue),
      };
    }

    res.json({ reply, diff, proposedContent });
  } catch (err) {
    console.error('AI chat error:', err);
    res.status(500).json({ error: 'AI request failed. Please try again.' });
  }
});

// POST /api/ai/apply — Apply proposed content changes
app.post('/api/ai/apply', authMiddleware, async (req, res) => {
  try {
    const { proposedContent } = req.body;
    if (!proposedContent) {
      return res.status(400).json({ error: 'proposedContent is required.' });
    }
    // Backup current content
    const current = loadContent();
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(BACKUP_FILE, JSON.stringify(current, null, 2));
    // Write new content
    saveContent(proposedContent);
    res.json({ ok: true });
  } catch (err) {
    console.error('AI apply error:', err);
    res.status(500).json({ error: 'Failed to apply changes.' });
  }
});

// POST /api/ai/undo — Revert to backup
app.post('/api/ai/undo', authMiddleware, async (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_FILE)) {
      return res.status(404).json({ error: 'No backup found to revert to.' });
    }
    const backup = JSON.parse(fs.readFileSync(BACKUP_FILE, 'utf8'));
    saveContent(backup);
    res.json({ ok: true, message: 'Reverted to previous version' });
  } catch (err) {
    console.error('AI undo error:', err);
    res.status(500).json({ error: 'Failed to revert.' });
  }
});

// GET /api/ai/status — Check configured AI providers
app.get('/api/ai/status', (req, res) => {
  res.json({
    anthropic: !!process.env.ANTHROPIC_API_KEY,
    openai: !!process.env.OPENAI_API_KEY,
    google: !!process.env.GOOGLE_AI_API_KEY,
    xai: !!process.env.XAI_API_KEY,
  });
});

// Helpers for nested value access with bracket notation support (e.g. "collections.items[0].name")
function getNestedValue(obj, path) {
  const keys = parsePath(path);
  let current = obj;
  for (const key of keys) {
    if (current == null) return undefined;
    current = current[key];
  }
  return current;
}

function setNestedValue(obj, path, value) {
  const keys = parsePath(path);
  let current = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (current[key] == null) {
      current[key] = typeof keys[i + 1] === 'number' ? [] : {};
    }
    current = current[key];
  }
  current[keys[keys.length - 1]] = value;
}

function parsePath(path) {
  const keys = [];
  const parts = path.split('.');
  for (const part of parts) {
    const match = part.match(/^([^[]+)(?:\[(\d+)\])?$/);
    if (match) {
      keys.push(match[1]);
      if (match[2] !== undefined) keys.push(parseInt(match[2], 10));
    } else {
      keys.push(part);
    }
  }
  return keys;
}

// ─── Admin route ───
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ─── Kitchen Connection landing page ───
app.get('/kc', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'kc.html'));
});

// ─── Catch-all for SPA ───
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Alpha Surfaces CMS running on port ${PORT}`);
});
