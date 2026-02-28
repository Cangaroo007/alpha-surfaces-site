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
const OpenAI = require('openai');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const versions = require('./lib/versions');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Config ───
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'alpha2025';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CONTENT_FILE = path.join(DATA_DIR, 'content.json');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// ─── API Keys Management ───
const KEY_NAMES = [
  'anthropic', 'openai', 'google', 'xai', 'runway',
  'cloudinary_cloud_name', 'cloudinary_api_key', 'cloudinary_api_secret'
];

const ENV_MAP = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
  google: 'GOOGLE_AI_API_KEY',
  xai: 'XAI_API_KEY',
  runway: 'RUNWAY_API_KEY',
  cloudinary_cloud_name: 'CLOUDINARY_CLOUD_NAME',
  cloudinary_api_key: 'CLOUDINARY_API_KEY',
  cloudinary_api_secret: 'CLOUDINARY_API_SECRET',
};

let KEYS = {};
let keysFromFile = {};

function loadKeys() {
  // Start with empty keys
  const merged = {};
  for (const k of KEY_NAMES) merged[k] = '';

  // Load from keys.json if it exists
  try {
    if (fs.existsSync(KEYS_FILE)) {
      keysFromFile = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
      for (const k of KEY_NAMES) {
        if (keysFromFile[k]) merged[k] = keysFromFile[k];
      }
    }
  } catch (err) {
    console.error('Failed to load keys.json:', err.message);
  }

  // Env vars take priority
  for (const k of KEY_NAMES) {
    const envName = ENV_MAP[k];
    if (process.env[envName]) merged[k] = process.env[envName];
  }

  KEYS = merged;
}

function saveKeys() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keysFromFile, null, 2));
}

function getKeySource(keyName) {
  const envName = ENV_MAP[keyName];
  if (process.env[envName] && process.env[envName] === KEYS[keyName]) return 'env';
  if (keysFromFile[keyName] && keysFromFile[keyName] === KEYS[keyName]) return 'admin';
  return null;
}

function maskKey(value) {
  if (!value) return null;
  if (value.length < 12) return '••••••••';
  return value.substring(0, 6) + '••••••••' + value.substring(value.length - 4);
}

// Load keys on startup
loadKeys();

// ─── Cloudinary ───
function configureCloudinary() {
  cloudinary.config({
    cloud_name: KEYS.cloudinary_cloud_name,
    api_key: KEYS.cloudinary_api_key,
    api_secret: KEYS.cloudinary_api_secret,
  });
}
configureCloudinary();

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
    // Auto-snapshot current content before writing
    const current = loadContent();
    versions.createVersion('content', current, {
      source: 'cms-save',
      autoLabel: 'Manual save',
      changeCount: 0,
    });
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

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Too many AI requests. Please slow down.' },
});

// Video generation jobs (in-memory)
const videoJobs = new Map();

// Build the system prompt used by all LLM providers
function buildSystemPrompt(currentContent) {
  return `You are the AI content editor for Alpha Surfaces, a premium Australian benchtop brand. You have full knowledge of and control over the website's content via a JSON content store.

Alpha Surfaces brand context:
- Premium mineral stone benchtops with zero crystalline silica (silicosis-safe)
- AlphaShield™ Lifetime Stain Resistance Guarantee
- 30+ surfaces across 5 collections (01–05) plus Original Alpha Zero
- Jumbo slabs: 3200 × 1600mm, 20mm thickness
- Target markets: fabricators, architects, designers, builders, homeowners
- Managing Director: Belinda Kelaher
- Tone: Luxury editorial — confident, precise, premium without being cold

Brand voice guidelines:
- Avoid generic superlatives ("world-class", "leading", "best-in-class")
- Prefer sensory and material language ("tactile", "weight", "grain", "depth")
- Short declarative sentences work better than long compound ones for headlines
- Australian English spelling throughout (e.g. "colour" not "color")
- HTML <em> tags may be used in headings for italic emphasis — preserve this pattern

The current website content.json is below. This is the live content of the site:

<content>
${JSON.stringify(currentContent, null, 2)}
</content>

When the user asks you to make changes to the site:
1. Make the changes thoughtfully, in the brand voice described above
2. Return your conversational reply AND the proposed content changes in this exact format at the end of your response:

<proposed_changes>
{ ...only the changed fields as a deep partial object... }
</proposed_changes>

The proposed_changes object must use the exact same key structure as content.json. Only include keys that have actually changed — do not return the entire content object in proposed_changes, only the changed portions.

Examples:
- If you changed hero.heading: { "hero": { "heading": "new value" } }
- If you changed two collections: { "collections": { "items": [null, { "name": "new name" }, null] } } — use null for unchanged array items
- If you changed a colour: { "styles": { "olive": "#6B6820" } }

If the user is asking a question and no changes are needed, reply helpfully and omit the <proposed_changes> block entirely.

If the user asks you to do something outside your capabilities (e.g. upload images, change passwords, deploy code), explain what you can and can't do, and suggest alternatives where possible.`;
}

// ─── Deep Merge & Diff Utilities ───

// Deep merge a partial object into the original, producing a full updated object.
// For arrays, null entries in partial mean "keep the original item at this index".
function deepMergeContent(original, partial) {
  const result = JSON.parse(JSON.stringify(original));

  function mergeInto(target, source) {
    if (Array.isArray(source)) {
      if (!Array.isArray(target)) return source;
      for (let i = 0; i < source.length; i++) {
        if (source[i] === null) continue;
        if (i >= target.length) {
          target[i] = source[i];
        } else if (typeof source[i] === 'object' && source[i] !== null && typeof target[i] === 'object' && target[i] !== null) {
          target[i] = mergeInto(target[i], source[i]);
        } else {
          target[i] = source[i];
        }
      }
      return target;
    }

    if (typeof source === 'object' && source !== null) {
      if (typeof target !== 'object' || target === null || Array.isArray(target)) {
        return source;
      }
      for (const key of Object.keys(source)) {
        if (typeof source[key] === 'object' && source[key] !== null && typeof target[key] === 'object' && target[key] !== null) {
          target[key] = mergeInto(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
      return target;
    }

    return source;
  }

  mergeInto(result, partial);
  return result;
}

// Recursively compare two objects, returning an array of {path, before, after} for changed leaf values.
// Skips image objects (those containing url/publicId/thumb/medium/large keys).
function computeDiff(original, proposed) {
  const diffs = [];

  function isImageObj(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
    const keys = Object.keys(obj);
    return keys.some(k => ['url', 'publicId', 'thumb', 'medium', 'large'].includes(k));
  }

  function walk(a, b, currentPath) {
    if (a === b) return;

    const aIsObj = a !== null && a !== undefined && typeof a === 'object';
    const bIsObj = b !== null && b !== undefined && typeof b === 'object';

    if (aIsObj && bIsObj && !Array.isArray(a) && !Array.isArray(b)) {
      if (isImageObj(a) || isImageObj(b)) return;
      const allKeys = new Set([...Object.keys(a), ...Object.keys(b)]);
      for (const key of allKeys) {
        walk(a[key], b[key], currentPath ? `${currentPath}.${key}` : key);
      }
      return;
    }

    if (Array.isArray(a) && Array.isArray(b)) {
      const maxLen = Math.max(a.length, b.length);
      for (let i = 0; i < maxLen; i++) {
        walk(a[i], b[i], `${currentPath}[${i}]`);
      }
      return;
    }

    // Leaf comparison
    const aStr = a != null ? String(a) : '';
    const bStr = b != null ? String(b) : '';
    if (aStr !== bStr) {
      diffs.push({ path: currentPath, before: aStr, after: bStr });
    }
  }

  walk(original, proposed, '');
  return diffs;
}

// ─── LLM Provider Functions ───

async function callAnthropic(model, messages, attachments, systemPrompt) {
  const client = new Anthropic({ apiKey: KEYS.anthropic });
  const anthropicMessages = messages.map((msg, idx) => {
    const content = [];
    if (msg.role === 'user' && idx === messages.length - 1 && attachments && attachments.length > 0) {
      for (const att of attachments) {
        if (att.type === 'image' && att.base64 && att.mimeType) {
          content.push({
            type: 'image',
            source: { type: 'base64', media_type: att.mimeType, data: att.base64 },
          });
        } else if (att.type === 'document' && att.base64 && att.mimeType) {
          content.push({
            type: 'document',
            source: { type: 'base64', media_type: att.mimeType, data: att.base64 },
          });
        }
      }
    }
    content.push({ type: 'text', text: msg.content });
    return { role: msg.role, content };
  });

  const response = await client.messages.create({
    model: model || 'claude-sonnet-4-20250514',
    max_tokens: 4096,
    system: systemPrompt,
    messages: anthropicMessages,
  });

  const rawText = response.content.filter(b => b.type === 'text').map(b => b.text).join('');
  const usage = response.usage;
  const tokens = (usage?.input_tokens || 0) + (usage?.output_tokens || 0);
  return { rawText, tokens };
}

async function callOpenAI(model, messages, attachments, systemPrompt, baseURL, apiKey) {
  const client = new OpenAI({
    apiKey: apiKey || KEYS.openai,
    ...(baseURL ? { baseURL } : {}),
  });

  const openaiMessages = [{ role: 'system', content: systemPrompt }];
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role === 'user' && i === messages.length - 1 && attachments && attachments.length > 0) {
      const contentParts = [];
      for (const att of attachments) {
        if (att.type === 'image' && att.base64 && att.mimeType) {
          contentParts.push({
            type: 'image_url',
            image_url: { url: `data:${att.mimeType};base64,${att.base64}` },
          });
        }
      }
      contentParts.push({ type: 'text', text: msg.content });
      openaiMessages.push({ role: 'user', content: contentParts });
    } else {
      openaiMessages.push({ role: msg.role, content: msg.content });
    }
  }

  const response = await client.chat.completions.create({
    model: model,
    max_tokens: 4096,
    messages: openaiMessages,
  });

  const rawText = response.choices[0]?.message?.content || '';
  const usage = response.usage;
  const tokens = (usage?.prompt_tokens || 0) + (usage?.completion_tokens || 0);
  return { rawText, tokens };
}

async function callGemini(model, messages, attachments, systemPrompt) {
  const genAI = new GoogleGenerativeAI(KEYS.google);
  const geminiModel = genAI.getGenerativeModel({ model: model || 'gemini-1.5-pro' });

  const history = [];
  for (let i = 0; i < messages.length - 1; i++) {
    const msg = messages[i];
    history.push({
      role: msg.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: msg.content }],
    });
  }

  const chat = geminiModel.startChat({
    history,
    systemInstruction: { parts: [{ text: systemPrompt }] },
  });

  const lastMsg = messages[messages.length - 1];
  const parts = [];

  if (lastMsg.role === 'user' && attachments && attachments.length > 0) {
    for (const att of attachments) {
      if (att.type === 'image' && att.base64 && att.mimeType) {
        parts.push({ inlineData: { mimeType: att.mimeType, data: att.base64 } });
      }
    }
  }
  parts.push({ text: lastMsg.content });

  const result = await chat.sendMessage(parts);
  const response = result.response;
  const rawText = response.text();
  const usage = response.usageMetadata;
  const tokens = (usage?.promptTokenCount || 0) + (usage?.candidatesTokenCount || 0);
  return { rawText, tokens };
}

async function callGrok(model, messages, attachments, systemPrompt) {
  return callOpenAI(
    model || 'grok-2',
    messages,
    attachments,
    systemPrompt,
    'https://api.x.ai/v1',
    KEYS.xai
  );
}

async function routeToLLM(model, messages, attachments, currentContent) {
  const systemPrompt = buildSystemPrompt(currentContent);
  if (model.startsWith('claude')) return callAnthropic(model, messages, attachments, systemPrompt);
  if (model.startsWith('gpt'))    return callOpenAI(model, messages, attachments, systemPrompt);
  if (model.startsWith('gemini')) return callGemini(model, messages, attachments, systemPrompt);
  if (model.startsWith('grok'))   return callGrok(model, messages, attachments, systemPrompt);
  throw new Error(`Unknown model: ${model}`);
}

// POST /api/ai/chat — Core NL CMS endpoint (multi-LLM)
app.post('/api/ai/chat', authMiddleware, aiLimiter, async (req, res) => {
  try {
    const { messages, attachments, model: requestedModel } = req.body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ ok: false, message: 'Messages array is required.' });
    }

    const model = requestedModel || 'claude-sonnet-4-20250514';

    // Validate the provider has an API key
    if (model.startsWith('claude') && !KEYS.anthropic) {
      return res.status(503).json({ ok: false, message: 'Claude API key not configured. Add it in API Keys → Claude.' });
    }
    if (model.startsWith('gpt') && !KEYS.openai) {
      return res.status(503).json({ ok: false, message: 'OpenAI API key not configured. Add it in API Keys → GPT-4o.' });
    }
    if (model.startsWith('gemini') && !KEYS.google) {
      return res.status(503).json({ ok: false, message: 'Google AI API key not configured. Add it in API Keys → Gemini.' });
    }
    if (model.startsWith('grok') && !KEYS.xai) {
      return res.status(503).json({ ok: false, message: 'xAI API key not configured. Add it in API Keys → Grok.' });
    }

    // Always read fresh content from disk
    const currentContent = loadContent();
    const { rawText, tokens } = await routeToLLM(model, messages, attachments, currentContent);

    // Parse response: extract reply text and <proposed_changes> block
    const changesMatch = rawText.match(/<proposed_changes>\s*([\s\S]*?)\s*<\/proposed_changes>/);

    let reply = rawText;
    let proposedChanges = null;

    if (changesMatch) {
      reply = rawText.substring(0, rawText.indexOf('<proposed_changes>')).trim();
      try {
        proposedChanges = JSON.parse(changesMatch[1]);
      } catch (e) {
        // JSON parsing failed — treat as no changes
        proposedChanges = null;
      }
    }

    if (!proposedChanges) {
      return res.json({
        ok: true,
        reply,
        diff: [],
        proposedContent: null,
        hasChanges: false,
        model,
        tokens
      });
    }

    // Deep merge proposed changes with current content
    const proposedContent = deepMergeContent(currentContent, proposedChanges);

    // Compute diff array
    const diff = computeDiff(currentContent, proposedContent);

    res.json({
      ok: true,
      reply,
      diff,
      proposedContent,
      hasChanges: diff.length > 0,
      model,
      tokens
    });
  } catch (err) {
    console.error('AI chat error:', err);
    const message = err?.status === 401
      ? 'Invalid API key. Check your key in API Keys settings.'
      : err?.status === 429
      ? 'Rate limit exceeded. Please wait a moment and try again.'
      : err?.message || 'AI request failed. Please try again.';
    res.status(500).json({ ok: false, message });
  }
});

// POST /api/ai/apply — Apply proposed content changes
app.post('/api/ai/apply', authMiddleware, async (req, res) => {
  try {
    const { proposedContent } = req.body;
    if (!proposedContent) {
      return res.status(400).json({ error: 'proposedContent is required.' });
    }
    // Snapshot current content via version history
    const current = loadContent();
    const diff = computeDiff(current, proposedContent);
    versions.createVersion('content', current, {
      source: 'nl-cms',
      autoLabel: versions.generateAutoLabel(diff),
      changeCount: diff.length,
    });
    // Write new content
    saveContent(proposedContent);
    res.json({ ok: true, message: 'Changes applied. Version saved.' });
  } catch (err) {
    console.error('AI apply error:', err);
    res.status(500).json({ error: 'Failed to apply changes.' });
  }
});

// /api/ai/undo removed — replaced by multi-level version history (see /api/versions/*)

// GET /api/ai/status — Provider availability & model capability data
app.get('/api/ai/status', (req, res) => {
  res.json({
    anthropic: !!KEYS.anthropic,
    openai: !!KEYS.openai,
    google: !!KEYS.google,
    xai: !!KEYS.xai,
    runway: !!KEYS.runway,
    models: {
      'claude-sonnet-4-20250514': {
        available: !!KEYS.anthropic,
        label: 'Claude Sonnet',
        capabilities: ['text', 'vision', 'content-edit'],
      },
      'gpt-4o': {
        available: !!KEYS.openai,
        label: 'GPT-4o',
        capabilities: ['text', 'vision', 'content-edit', 'image-gen'],
      },
      'gemini-1.5-pro': {
        available: !!KEYS.google,
        label: 'Gemini 1.5 Pro',
        capabilities: ['text', 'vision', 'content-edit', 'large-context'],
      },
      'grok-2': {
        available: !!KEYS.xai,
        label: 'Grok',
        capabilities: ['text', 'content-edit', 'image-gen', 'web-search'],
      },
    },
  });
});

// ─── Image Generation ───

// Helper: upload a buffer to Cloudinary
function uploadBufferToCloudinary(buffer, options = {}) {
  return new Promise((resolve, reject) => {
    const uploadOptions = {
      folder: 'alpha-surfaces',
      ...options,
    };
    const stream = cloudinary.uploader.upload_stream(uploadOptions, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
    stream.end(buffer);
  });
}

// POST /api/ai/generate-image
app.post('/api/ai/generate-image', authMiddleware, aiLimiter, async (req, res) => {
  const { prompt, provider, size, targetField } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt is required.' });

  const selectedProvider = provider || 'dalle3';

  try {
    let imageBuffer;

    if (selectedProvider === 'dalle3') {
      if (!KEYS.openai) {
        return res.status(503).json({ error: 'OpenAI API key not configured.' });
      }
      const client = new OpenAI({ apiKey: KEYS.openai });
      const imageSize = size || '1792x1024';
      const response = await client.images.generate({
        model: 'dall-e-3',
        prompt,
        n: 1,
        size: imageSize,
        response_format: 'b64_json',
      });
      const b64 = response.data[0].b64_json;
      imageBuffer = Buffer.from(b64, 'base64');

    } else if (selectedProvider === 'imagen3') {
      if (!KEYS.google) {
        return res.status(503).json({ error: 'Google AI API key not configured.' });
      }
      const genAI = new GoogleGenerativeAI(KEYS.google);
      const model = genAI.getGenerativeModel({ model: 'imagen-3.0-generate-002' });
      const result = await model.generateImages({
        prompt,
        config: { numberOfImages: 1 },
      });
      const imgBytes = result.images[0].imageBytes;
      imageBuffer = Buffer.from(imgBytes, 'base64');

    } else if (selectedProvider === 'grok-aurora') {
      if (!KEYS.xai) {
        return res.status(503).json({ error: 'xAI API key not configured.' });
      }
      const client = new OpenAI({
        apiKey: KEYS.xai,
        baseURL: 'https://api.x.ai/v1',
      });
      const response = await client.images.generate({
        model: 'grok-2-image',
        prompt,
        n: 1,
        response_format: 'b64_json',
      });
      const b64 = response.data[0].b64_json;
      imageBuffer = Buffer.from(b64, 'base64');

    } else {
      return res.status(400).json({ error: `Unknown image provider: ${selectedProvider}` });
    }

    // Upload to Cloudinary
    const result = await uploadBufferToCloudinary(imageBuffer, {
      public_id: `ai-gen-${Date.now()}`,
      resource_type: 'image',
    });

    res.json({
      ok: true,
      url: result.secure_url,
      publicId: result.public_id,
      thumb: cloudinary.url(result.public_id, { width: 200, crop: 'fill', fetch_format: 'auto' }),
      medium: cloudinary.url(result.public_id, { width: 800, crop: 'limit', fetch_format: 'auto' }),
      large: cloudinary.url(result.public_id, { width: 1920, crop: 'limit', fetch_format: 'auto' }),
      targetField: targetField || null,
      prompt,
    });
  } catch (err) {
    console.error('Image generation error:', err);
    const message = err?.message || 'Image generation failed.';
    res.status(500).json({ error: message });
  }
});

// ─── Video Generation ───

// POST /api/ai/generate-video — Start async video job
app.post('/api/ai/generate-video', authMiddleware, async (req, res) => {
  const { prompt, provider, duration, targetField } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt is required.' });

  if ((provider || 'runway') !== 'runway') {
    return res.status(400).json({ error: `Unsupported video provider: ${provider}` });
  }
  if (!KEYS.runway) {
    return res.status(503).json({ error: 'Runway API key not configured.' });
  }

  const jobId = 'vid-' + crypto.randomBytes(8).toString('hex');
  videoJobs.set(jobId, { status: 'processing', prompt, targetField, provider: 'runway', createdAt: Date.now() });

  // Run async
  (async () => {
    try {
      // Start generation
      const startRes = await fetch('https://api.dev.runwayml.com/v1/text_to_video', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${KEYS.runway}`,
          'Content-Type': 'application/json',
          'X-Runway-Version': '2024-11-06',
        },
        body: JSON.stringify({
          model: 'gen4_turbo',
          text_prompt: prompt,
          duration: duration || 5,
          ratio: '1280:720',
        }),
      });

      if (!startRes.ok) {
        const errBody = await startRes.text();
        throw new Error(`Runway API error: ${startRes.status} — ${errBody}`);
      }

      const startData = await startRes.json();
      const taskId = startData.id;

      // Poll for completion
      let attempts = 0;
      const maxAttempts = 60; // 5 minutes max (5s intervals)
      while (attempts < maxAttempts) {
        await new Promise(r => setTimeout(r, 5000));
        attempts++;

        const pollRes = await fetch(`https://api.dev.runwayml.com/v1/tasks/${taskId}`, {
          headers: {
            'Authorization': `Bearer ${KEYS.runway}`,
            'X-Runway-Version': '2024-11-06',
          },
        });

        if (!pollRes.ok) continue;
        const pollData = await pollRes.json();

        if (pollData.status === 'SUCCEEDED') {
          const videoUrl = pollData.output?.[0];
          if (!videoUrl) throw new Error('No video URL in Runway response');

          // Download the video
          const videoRes = await fetch(videoUrl);
          const videoBuffer = Buffer.from(await videoRes.arrayBuffer());

          // Upload to Cloudinary as video
          const cloudResult = await uploadBufferToCloudinary(videoBuffer, {
            public_id: `ai-video-${Date.now()}`,
            resource_type: 'video',
          });

          videoJobs.set(jobId, {
            status: 'complete',
            prompt,
            targetField,
            provider: 'runway',
            result: {
              url: cloudResult.secure_url,
              publicId: cloudResult.public_id,
              thumb: cloudResult.secure_url.replace(/\.[^.]+$/, '.jpg'),
              targetField,
              prompt,
            },
          });
          return;
        } else if (pollData.status === 'FAILED') {
          throw new Error(pollData.error || 'Runway generation failed');
        }
        // else still processing, continue polling
      }
      throw new Error('Video generation timed out');
    } catch (err) {
      console.error('Video generation error:', err);
      videoJobs.set(jobId, { status: 'failed', error: err.message, prompt, targetField, provider: 'runway' });
    }
  })();

  res.json({ jobId });
});

// GET /api/ai/video-status/:jobId — Poll video job status
app.get('/api/ai/video-status/:jobId', authMiddleware, (req, res) => {
  const job = videoJobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found.' });
  res.json(job);
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

// ─── API Keys Management Routes ───

// GET /api/keys — Return key status (masked values only)
app.get('/api/keys', authMiddleware, (req, res) => {
  const result = {};
  for (const k of KEY_NAMES) {
    const value = KEYS[k];
    result[k] = {
      set: !!value,
      masked: maskKey(value),
      source: value ? getKeySource(k) : null,
    };
  }
  res.json(result);
});

// PUT /api/keys — Save one or more keys
app.put('/api/keys', authMiddleware, (req, res) => {
  const updated = [];
  const cloudinaryChanged = false;
  let reloadCloudinary = false;

  for (const [key, value] of Object.entries(req.body)) {
    if (!KEY_NAMES.includes(key)) continue;

    const trimmed = String(value).trim();

    // Skip if value is only bullet characters (masked value submitted accidentally)
    if (/^[•]+$/.test(trimmed)) continue;

    // Update keys.json data
    keysFromFile[key] = trimmed;
    updated.push(key);

    if (key.startsWith('cloudinary_')) reloadCloudinary = true;
  }

  if (updated.length > 0) {
    saveKeys();
    loadKeys();
    if (reloadCloudinary) configureCloudinary();
  }

  res.json({ ok: true, updated });
});

// POST /api/keys/test/:provider — Test a provider connection
app.post('/api/keys/test/:provider', authMiddleware, async (req, res) => {
  const { provider } = req.params;
  const start = Date.now();

  try {
    if (provider === 'anthropic') {
      if (!KEYS.anthropic) return res.json({ ok: false, provider, message: 'No API key configured' });
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': KEYS.anthropic,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 1,
          messages: [{ role: 'user', content: 'hi' }],
        }),
      });
      if (!resp.ok) {
        const body = await resp.text();
        throw new Error(resp.status === 401 ? 'Invalid API key — check and try again' : `API error ${resp.status}`);
      }
      return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });

    } else if (provider === 'openai') {
      if (!KEYS.openai) return res.json({ ok: false, provider, message: 'No API key configured' });
      const resp = await fetch('https://api.openai.com/v1/models', {
        headers: { 'Authorization': `Bearer ${KEYS.openai}` },
      });
      if (!resp.ok) throw new Error(resp.status === 401 ? 'Invalid API key — check and try again' : `API error ${resp.status}`);
      return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });

    } else if (provider === 'google') {
      if (!KEYS.google) return res.json({ ok: false, provider, message: 'No API key configured' });
      const resp = await fetch(`https://generativelanguage.googleapis.com/v1/models?key=${encodeURIComponent(KEYS.google)}`);
      if (!resp.ok) throw new Error(resp.status === 400 || resp.status === 403 ? 'Invalid API key — check and try again' : `API error ${resp.status}`);
      return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });

    } else if (provider === 'xai') {
      if (!KEYS.xai) return res.json({ ok: false, provider, message: 'No API key configured' });
      const resp = await fetch('https://api.x.ai/v1/models', {
        headers: { 'Authorization': `Bearer ${KEYS.xai}` },
      });
      if (!resp.ok) throw new Error(resp.status === 401 ? 'Invalid API key — check and try again' : `API error ${resp.status}`);
      return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });

    } else if (provider === 'runway') {
      if (!KEYS.runway) return res.json({ ok: false, provider, message: 'No API key configured' });
      const resp = await fetch('https://api.dev.runwayml.com/v1/organizations', {
        headers: {
          'Authorization': `Bearer ${KEYS.runway}`,
          'X-Runway-Version': '2024-11-06',
        },
      });
      // 200 or 401 both count as reachable
      if (resp.status === 200 || resp.status === 401) {
        return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });
      }
      throw new Error(`API error ${resp.status}`);

    } else if (provider === 'cloudinary') {
      if (!KEYS.cloudinary_cloud_name || !KEYS.cloudinary_api_key || !KEYS.cloudinary_api_secret) {
        return res.json({ ok: false, provider, message: 'Cloudinary credentials not fully configured' });
      }
      await cloudinary.api.ping();
      return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });

    } else {
      return res.status(400).json({ ok: false, provider, message: `Unknown provider: ${provider}` });
    }
  } catch (err) {
    return res.json({ ok: false, provider, message: err.message || 'Connection failed' });
  }
});

// DELETE /api/keys/:keyName — Clear a single key
app.delete('/api/keys/:keyName', authMiddleware, (req, res) => {
  const { keyName } = req.params;
  if (!KEY_NAMES.includes(keyName)) {
    return res.status(400).json({ error: `Unknown key: ${keyName}` });
  }
  keysFromFile[keyName] = '';
  saveKeys();
  loadKeys();
  if (keyName.startsWith('cloudinary_')) configureCloudinary();
  res.json({ ok: true, cleared: keyName });
});

// ─── Version History API Routes ───

// GET /api/versions/:page — List versions
app.get('/api/versions/:page', authMiddleware, (req, res) => {
  try {
    const pageKey = req.params.page;
    const versionList = versions.getIndex(pageKey);
    res.json({ ok: true, page: pageKey, versions: versionList.slice(0, MAX_VERSIONS) });
  } catch (err) {
    console.error('Version list error:', err);
    res.status(500).json({ ok: false, message: 'Failed to load versions.' });
  }
});

// GET /api/versions/:page/:id/snapshot — Get full snapshot
app.get('/api/versions/:page/:id/snapshot', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    const snapshot = versions.getSnapshot(page, id);
    if (snapshot === null) {
      return res.status(404).json({ ok: false, message: 'Snapshot not found.' });
    }
    if (page === 'content') {
      res.json(snapshot);
    } else {
      res.type('text/html').send(snapshot);
    }
  } catch (err) {
    console.error('Snapshot error:', err);
    res.status(500).json({ ok: false, message: 'Failed to load snapshot.' });
  }
});

// GET /api/versions/:page/:id/diff — Diff vs current live
app.get('/api/versions/:page/:id/diff', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    let currentLive;
    if (page === 'content') {
      currentLive = loadContent();
    } else {
      const htmlPath = path.join(__dirname, 'public', page + '.html');
      if (!fs.existsSync(htmlPath)) {
        return res.status(404).json({ ok: false, message: 'Live page not found.' });
      }
      currentLive = fs.readFileSync(htmlPath, 'utf8');
    }
    const result = versions.getDiff(page, id, currentLive);
    if (!result) {
      return res.status(404).json({ ok: false, message: 'Snapshot not found.' });
    }
    res.json(result);
  } catch (err) {
    console.error('Diff error:', err);
    res.status(500).json({ ok: false, message: 'Failed to compute diff.' });
  }
});

// POST /api/versions/:page/checkpoint — Create manual checkpoint
app.post('/api/versions/:page/checkpoint', authMiddleware, (req, res) => {
  try {
    const pageKey = req.params.page;
    const label = req.body.label || null;
    let currentLive;
    if (pageKey === 'content') {
      currentLive = loadContent();
    } else {
      const htmlPath = path.join(__dirname, 'public', pageKey + '.html');
      if (!fs.existsSync(htmlPath)) {
        return res.status(404).json({ ok: false, message: 'Page not found.' });
      }
      currentLive = fs.readFileSync(htmlPath, 'utf8');
    }
    const version = versions.createCheckpoint(pageKey, currentLive, label);
    res.json({ ok: true, version });
  } catch (err) {
    console.error('Checkpoint error:', err);
    res.status(500).json({ ok: false, message: 'Failed to create checkpoint.' });
  }
});

// PUT /api/versions/:page/:id/label — Rename a version
app.put('/api/versions/:page/:id/label', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    let label = req.body.label;
    if (label !== null && label !== undefined) {
      label = String(label).trim();
      if (label === '') label = null;
    }
    const updated = versions.renameVersion(page, id, label);
    if (!updated) {
      return res.status(404).json({ ok: false, message: 'Version not found.' });
    }
    res.json({ ok: true, version: updated });
  } catch (err) {
    console.error('Label error:', err);
    res.status(500).json({ ok: false, message: 'Failed to update label.' });
  }
});

// DELETE /api/versions/:page/:id — Delete a version
app.delete('/api/versions/:page/:id', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    const result = versions.deleteVersion(page, id);
    res.json(result);
  } catch (err) {
    console.error('Delete version error:', err);
    res.status(500).json({ ok: false, message: 'Failed to delete version.' });
  }
});

// PUT /api/versions/:page/:id/protect — Toggle protected status
app.put('/api/versions/:page/:id/protect', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    const protectedVal = !!req.body.protected;
    const updated = versions.toggleProtect(page, id, protectedVal);
    if (!updated) {
      return res.status(404).json({ ok: false, message: 'Version not found.' });
    }
    res.json({ ok: true, version: updated });
  } catch (err) {
    console.error('Protect error:', err);
    res.status(500).json({ ok: false, message: 'Failed to update protection.' });
  }
});

// POST /api/versions/:page/:id/restore — Restore a version
app.post('/api/versions/:page/:id/restore', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    let currentLive;
    let writeLiveFile;

    if (page === 'content') {
      currentLive = loadContent();
      writeLiveFile = (snapshot) => {
        saveContent(snapshot);
      };
    } else {
      const htmlPath = path.join(__dirname, 'public', page + '.html');
      if (!fs.existsSync(htmlPath)) {
        return res.status(404).json({ ok: false, message: 'Page not found.' });
      }
      currentLive = fs.readFileSync(htmlPath, 'utf8');
      writeLiveFile = (snapshot) => {
        fs.writeFileSync(htmlPath, snapshot);
      };
    }

    const result = versions.restoreVersion(page, id, currentLive, writeLiveFile);

    // If restoring content, reload in-memory DATA
    if (page === 'content' && result.ok) {
      // Content is already written to disk by writeLiveFile
    }

    res.json(result);
  } catch (err) {
    console.error('Restore error:', err);
    res.status(500).json({ ok: false, message: 'Failed to restore version.' });
  }
});

// Expose MAX_VERSIONS for the version list route
const MAX_VERSIONS = 50;

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

// ─── Version History Startup ───
versions.ensureDirectories();
versions.snapshotContentOnStartup(loadContent());
versions.detectAndSnapshotPages();

app.listen(PORT, () => {
  console.log(`Alpha Surfaces CMS running on port ${PORT}`);
});
