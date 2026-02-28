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

// Video generation jobs (in-memory)
const videoJobs = new Map();

// Build the system prompt used by all LLM providers
function buildSystemPrompt(currentContent) {
  return `You are the AI content manager for Alpha Surfaces, a premium Australian benchtop brand. You have full knowledge of and control over the website content.

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
  },
  "action": null
}

Field paths use dot notation matching the content schema. Examples:
- "hero.heading" → changes the hero heading
- "hero.badge" → changes the badge text
- "about.quote" → changes the MD quote
- "nav.brand" → changes the brand name in the nav
- "collections.items[0].name" → changes the first collection's name
- "footer.copyright" → changes the footer copyright text

If no content changes are needed, set "changes" to null.

IMAGE GENERATION:
If the user asks you to generate, create, or make an image (e.g. "generate a hero background image of ..."), respond with an action instead of changes:
{
  "reply": "I'll generate that image for you...",
  "changes": null,
  "action": {
    "type": "generate-image",
    "prompt": "Detailed image generation prompt based on their request...",
    "targetField": "hero.backgroundImage",
    "provider": "dalle3"
  }
}
Choose the targetField based on context (hero.backgroundImage, about.visualImage, collections.items[N].slabImage, etc.).

IMPORTANT:
- Never invent product specifications — only use what is in the current content
- Preserve all HTML tags (e.g. <em>) in heading fields
- When rewriting copy, match the existing tone and style unless asked to change it
- Always confirm what you changed in your reply so the user can decide whether to apply it`;
}

// ─── LLM Provider Functions ───

async function callAnthropic(model, messages, attachments, systemPrompt) {
  const client = new Anthropic();
  const anthropicMessages = messages.map((msg, idx) => {
    const content = [];
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
    apiKey: apiKey || process.env.OPENAI_API_KEY,
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
  const genAI = new GoogleGenerativeAI(process.env.GOOGLE_AI_API_KEY);
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
    process.env.XAI_API_KEY
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
      return res.status(400).json({ error: 'Messages array is required.' });
    }

    const model = requestedModel || 'claude-sonnet-4-20250514';

    // Validate the provider has an API key
    if (model.startsWith('claude') && !process.env.ANTHROPIC_API_KEY) {
      return res.status(503).json({ error: 'Anthropic API key not configured.' });
    }
    if (model.startsWith('gpt') && !process.env.OPENAI_API_KEY) {
      return res.status(503).json({ error: 'OpenAI API key not configured.' });
    }
    if (model.startsWith('gemini') && !process.env.GOOGLE_AI_API_KEY) {
      return res.status(503).json({ error: 'Google AI API key not configured.' });
    }
    if (model.startsWith('grok') && !process.env.XAI_API_KEY) {
      return res.status(503).json({ error: 'xAI API key not configured.' });
    }

    const currentContent = loadContent();
    const { rawText, tokens } = await routeToLLM(model, messages, attachments, currentContent);

    // Parse the JSON response
    let parsed;
    try {
      const jsonMatch = rawText.match(/\{[\s\S]*\}/);
      parsed = JSON.parse(jsonMatch ? jsonMatch[0] : rawText);
    } catch {
      return res.json({ reply: rawText, diff: null, proposedContent: null, action: null, model, tokens });
    }

    const reply = parsed.reply || rawText;
    const changes = parsed.changes;
    const action = parsed.action || null;

    if (action) {
      return res.json({ reply, diff: null, proposedContent: null, action, model, tokens });
    }

    if (!changes || Object.keys(changes).length === 0) {
      return res.json({ reply, diff: null, proposedContent: null, action: null, model, tokens });
    }

    // Build diff and proposedContent
    const proposedContent = JSON.parse(JSON.stringify(currentContent));
    const diff = {};

    for (const [fieldPath, newValue] of Object.entries(changes)) {
      const before = getNestedValue(currentContent, fieldPath);
      setNestedValue(proposedContent, fieldPath, newValue);
      diff[fieldPath] = {
        before: before !== undefined ? String(before) : '',
        after: String(newValue),
      };
    }

    res.json({ reply, diff, proposedContent, action: null, model, tokens });
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

// GET /api/ai/status — Full model capability data
app.get('/api/ai/status', (req, res) => {
  res.json({
    models: {
      'claude-sonnet-4-20250514': {
        available: !!process.env.ANTHROPIC_API_KEY,
        label: 'Claude Sonnet',
        capabilities: ['text', 'vision', 'content-edit'],
      },
      'gpt-4o': {
        available: !!process.env.OPENAI_API_KEY,
        label: 'GPT-4o',
        capabilities: ['text', 'vision', 'content-edit', 'image-gen'],
      },
      'gemini-1.5-pro': {
        available: !!process.env.GOOGLE_AI_API_KEY,
        label: 'Gemini 1.5 Pro',
        capabilities: ['text', 'vision', 'content-edit', 'large-context'],
      },
      'grok-2': {
        available: !!process.env.XAI_API_KEY,
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
      if (!process.env.OPENAI_API_KEY) {
        return res.status(503).json({ error: 'OpenAI API key not configured.' });
      }
      const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
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
      if (!process.env.GOOGLE_AI_API_KEY) {
        return res.status(503).json({ error: 'Google AI API key not configured.' });
      }
      const genAI = new GoogleGenerativeAI(process.env.GOOGLE_AI_API_KEY);
      const model = genAI.getGenerativeModel({ model: 'imagen-3.0-generate-002' });
      const result = await model.generateImages({
        prompt,
        config: { numberOfImages: 1 },
      });
      const imgBytes = result.images[0].imageBytes;
      imageBuffer = Buffer.from(imgBytes, 'base64');

    } else if (selectedProvider === 'grok-aurora') {
      if (!process.env.XAI_API_KEY) {
        return res.status(503).json({ error: 'xAI API key not configured.' });
      }
      const client = new OpenAI({
        apiKey: process.env.XAI_API_KEY,
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
  if (!process.env.RUNWAY_API_KEY) {
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
          'Authorization': `Bearer ${process.env.RUNWAY_API_KEY}`,
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
            'Authorization': `Bearer ${process.env.RUNWAY_API_KEY}`,
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
