'use strict';

const fs = require('fs');
const path = require('path');
const multer = require('multer');

const PUBLIC_DIR = path.join(__dirname, 'public');
const STONES_JSON = path.join(PUBLIC_DIR, 'data', 'stones.json');
const DOWNLOADS_DIR = path.join(PUBLIC_DIR, 'downloads');

function slugify(value) {
  return String(value || '')
    .toLowerCase()
    .trim()
    .replace(/&/g, 'and')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function cleanPath(value) {
  if (!value) return '';
  return String(value).replace(/^public\//, '').replace(/^\/+/, '/');
}

function safeJson(value, fallback) {
  if (value == null) return fallback;
  if (typeof value === 'object') return value;
  try { return JSON.parse(value); } catch { return fallback; }
}

function rowToStone(row) {
  const specs = safeJson(row.specs, {});
  const gallery = safeJson(row.gallery, []);
  return {
    slug: row.slug,
    name: row.name,
    tagline: row.tagline || '',
    description: row.description || '',
    finish: row.finish || '',
    image: row.image_url || '',
    thumbnail: row.thumbnail_url || '',
    swatch: row.swatch_url || '',
    slab: row.slab_url || '',
    gallery,
    slab_width: specs.slab_width || 3200,
    slab_height: specs.slab_height || 1600,
    thickness: specs.thickness || 20,
    weight: specs.weight || 236,
    warranty: specs.warranty || '15-Year Limited Warranty',
    uv_stable: !!row.uv_stable,
    indoor_outdoor: !!row.indoor_outdoor,
    discontinued: !!row.discontinued,
    images_pending: !!row.images_pending,
    seo_title: row.seo_title || '',
    seo_description: row.seo_description || ''
  };
}

function rowToCollection(row, stones) {
  return {
    id: row.collection_id,
    name: row.name,
    subtitle: row.subtitle || '',
    description: row.description || '',
    hero_image: row.hero_image_url || '',
    swatch_image: row.swatch_image_url || '',
    visible: row.visible !== false,
    sort_order: row.sort_order || 0,
    stones: stones || []
  };
}

async function initCms({ pool }) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cms_collections (
      id               SERIAL PRIMARY KEY,
      collection_id    VARCHAR(80) UNIQUE NOT NULL,
      name             VARCHAR(255) NOT NULL,
      subtitle         TEXT,
      description      TEXT,
      hero_image_url   TEXT,
      swatch_image_url TEXT,
      sort_order       INTEGER DEFAULT 0,
      visible          BOOLEAN DEFAULT TRUE,
      created_at       TIMESTAMPTZ DEFAULT NOW(),
      updated_at       TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cms_stones (
      id               SERIAL PRIMARY KEY,
      slug             VARCHAR(120) UNIQUE NOT NULL,
      name             VARCHAR(255) NOT NULL,
      collection_id    VARCHAR(80) REFERENCES cms_collections(collection_id) ON DELETE SET NULL,
      tagline          TEXT,
      description      TEXT,
      finish           VARCHAR(100),
      image_url        TEXT,
      thumbnail_url    TEXT,
      swatch_url       TEXT,
      slab_url         TEXT,
      gallery          JSONB DEFAULT '[]'::jsonb,
      specs            JSONB DEFAULT '{}'::jsonb,
      uv_stable        BOOLEAN DEFAULT FALSE,
      indoor_outdoor   BOOLEAN DEFAULT FALSE,
      discontinued     BOOLEAN DEFAULT FALSE,
      images_pending   BOOLEAN DEFAULT FALSE,
      visible          BOOLEAN DEFAULT TRUE,
      sort_order       INTEGER DEFAULT 0,
      seo_title        TEXT,
      seo_description  TEXT,
      created_at       TIMESTAMPTZ DEFAULT NOW(),
      updated_at       TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cms_documents (
      id               SERIAL PRIMARY KEY,
      slug             VARCHAR(120) UNIQUE NOT NULL,
      title            VARCHAR(255) NOT NULL,
      description      TEXT,
      file_url         TEXT NOT NULL,
      source_url       TEXT,
      category         VARCHAR(80) DEFAULT 'resource',
      sort_order       INTEGER DEFAULT 0,
      visible          BOOLEAN DEFAULT TRUE,
      created_at       TIMESTAMPTZ DEFAULT NOW(),
      updated_at       TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cms_media (
      id               SERIAL PRIMARY KEY,
      url              TEXT NOT NULL,
      title            VARCHAR(255),
      alt_text         TEXT,
      media_type       VARCHAR(80),
      tags             TEXT[] DEFAULT '{}',
      created_at       TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await seedCollectionsAndStones(pool);
  await seedDocuments(pool);
}

async function seedCollectionsAndStones(pool) {
  const { rows } = await pool.query('SELECT COUNT(*)::int AS c FROM cms_collections');
  if (rows[0].c > 0 || !fs.existsSync(STONES_JSON)) return;

  const data = JSON.parse(fs.readFileSync(STONES_JSON, 'utf8'));
  let collectionOrder = 0;
  for (const collection of data.collections || []) {
    await pool.query(
      `INSERT INTO cms_collections
        (collection_id, name, subtitle, description, sort_order, visible)
       VALUES ($1,$2,$3,$4,$5,TRUE)
       ON CONFLICT (collection_id) DO NOTHING`,
      [
        collection.id || slugify(collection.name),
        collection.name,
        collection.subtitle || '',
        collection.description || collection.subtitle || '',
        collectionOrder++
      ]
    );

    let stoneOrder = 0;
    for (const stone of collection.stones || []) {
      const specs = {
        slab_width: stone.slab_width || 3200,
        slab_height: stone.slab_height || 1600,
        thickness: stone.thickness || 20,
        weight: stone.weight || 236,
        warranty: stone.warranty || '15-Year Limited Warranty'
      };
      await pool.query(
        `INSERT INTO cms_stones
          (slug, name, collection_id, tagline, description, finish, image_url,
           thumbnail_url, swatch_url, slab_url, gallery, specs, uv_stable,
           indoor_outdoor, discontinued, images_pending, visible, sort_order)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14,$15,$16,TRUE,$17)
         ON CONFLICT (slug) DO NOTHING`,
        [
          stone.slug || slugify(stone.name),
          stone.name,
          collection.id || slugify(collection.name),
          stone.tagline || '',
          stone.description || '',
          stone.finish || '',
          stone.image || '',
          stone.thumbnail || '',
          stone.swatch || '',
          stone.slab || '',
          JSON.stringify(stone.gallery || []),
          JSON.stringify(specs),
          !!stone.uv_stable,
          !!stone.indoor_outdoor,
          !!stone.discontinued || collection.id === 'alpha-zero',
          !!stone.images_pending,
          stoneOrder++
        ]
      );
    }
  }
  console.log('[cms] seeded collections and stones from public/data/stones.json');
}

async function seedDocuments(pool) {
  const { rows } = await pool.query('SELECT COUNT(*)::int AS c FROM cms_documents');
  if (rows[0].c > 0) return;

  const docs = [
    {
      slug: 'brochure',
      title: 'Alpha Surfaces Brochure',
      description: 'Product brochure and brand overview.',
      file: 'brochure.pdf',
      category: 'brochure',
      sort: 10
    },
    {
      slug: 'care-maintenance',
      title: 'Care & Maintenance',
      description: 'Care instructions for Alpha Surfaces products.',
      file: 'care-maintenance.pdf',
      source: 'alpha-surfaces-care-and-maintenance.docx',
      category: 'technical',
      sort: 20
    },
    {
      slug: 'fabrication-guide',
      title: 'Fabrication Guide',
      description: 'Fabrication and installation guide for stone masons and installers.',
      file: 'fabrication-guide.pdf',
      source: 'alpha-surfaces-fabrication-guide.docx',
      category: 'technical',
      sort: 30
    },
    {
      slug: 'warranty',
      title: 'Warranty Terms',
      description: 'Warranty terms and product guarantee information.',
      file: 'warranty.pdf',
      source: 'alpha-surfaces-warranty.docx',
      category: 'warranty',
      sort: 40
    },
    {
      slug: 'sds',
      title: 'Safety Data Sheet',
      description: 'Safety Data Sheet for Alpha Surfaces materials.',
      file: 'sds.pdf',
      category: 'technical',
      sort: 50
    }
  ];

  for (const doc of docs) {
    if (!fs.existsSync(path.join(DOWNLOADS_DIR, doc.file))) continue;
    await pool.query(
      `INSERT INTO cms_documents
        (slug, title, description, file_url, source_url, category, sort_order, visible)
       VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE)
       ON CONFLICT (slug) DO NOTHING`,
      [
        doc.slug,
        doc.title,
        doc.description,
        `/downloads/${doc.file}`,
        doc.source ? `/downloads/${doc.source}` : null,
        doc.category,
        doc.sort
      ]
    );
  }
  console.log('[cms] seeded document library from public/downloads');
}

async function getManagedStones(pool, includeHidden = false) {
  const colRes = await pool.query(
    `SELECT * FROM cms_collections
     ${includeHidden ? '' : 'WHERE visible = TRUE'}
     ORDER BY sort_order ASC, id ASC`
  );
  const stoneRes = await pool.query(
    `SELECT * FROM cms_stones
     ${includeHidden ? '' : 'WHERE visible = TRUE'}
     ORDER BY collection_id ASC, sort_order ASC, name ASC`
  );
  const stonesByCollection = new Map();
  for (const row of stoneRes.rows) {
    const key = row.collection_id || '_uncategorised';
    if (!stonesByCollection.has(key)) stonesByCollection.set(key, []);
    stonesByCollection.get(key).push(rowToStone(row));
  }
  return {
    collections: colRes.rows.map(row => rowToCollection(row, stonesByCollection.get(row.collection_id) || []))
  };
}

function mountCms(app, { pool, authMiddleware, dataDir }) {
  const uploadsDir = path.join(dataDir || path.join(__dirname, 'data'), 'cms-uploads');
  fs.mkdirSync(uploadsDir, { recursive: true });
  app.use('/cms-uploads', require('express').static(uploadsDir));

  const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadsDir),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || '').toLowerCase();
      cb(null, `${Date.now()}-${slugify(path.basename(file.originalname, ext))}${ext}`);
    }
  });
  const upload = multer({ storage, limits: { fileSize: 25 * 1024 * 1024 } });

  app.get('/api/public/stones', async (_req, res) => {
    try {
      res.json(await getManagedStones(pool, false));
    } catch (err) {
      console.error('[cms/public/stones] DB query failed, falling back to static stones.json:', err.message);
      try {
        if (fs.existsSync(STONES_JSON)) {
          const staticData = JSON.parse(fs.readFileSync(STONES_JSON, 'utf8'));
          return res.json(staticData);
        }
      } catch (readErr) {
        console.error('[cms/public/stones] Static fallback also failed:', readErr.message);
      }
      res.status(500).json({ error: 'Failed to load stones' });
    }
  });

  app.get('/api/public/collections', async (_req, res) => {
    try {
      const data = await getManagedStones(pool, false);
      res.json({
        collections: data.collections.map(c => ({
          id: c.id,
          name: c.name,
          subtitle: c.subtitle,
          description: c.description,
          hero_image: c.hero_image,
          swatch_image: c.swatch_image,
          stones: c.stones.map(s => ({ slug: s.slug, name: s.name, discontinued: s.discontinued }))
        }))
      });
    } catch (err) {
      console.error('[cms/public/collections]', err.message);
      res.status(500).json({ error: 'Failed to load collections' });
    }
  });

  app.get('/api/public/documents', async (_req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT slug, title, description, file_url, source_url, category, sort_order
         FROM cms_documents WHERE visible = TRUE ORDER BY sort_order ASC, title ASC`
      );
      res.json({ documents: rows });
    } catch (err) {
      console.error('[cms/public/documents]', err.message);
      res.status(500).json({ error: 'Failed to load documents' });
    }
  });

  app.get('/api/admin/cms/stones', authMiddleware, async (_req, res) => {
    try { res.json(await getManagedStones(pool, true)); }
    catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.put('/api/admin/cms/collections/:id', authMiddleware, async (req, res) => {
    try {
      const id = req.params.id;
      const b = req.body || {};
      const { rows } = await pool.query(
        `UPDATE cms_collections
         SET name=$2, subtitle=$3, description=$4, hero_image_url=$5,
             swatch_image_url=$6, sort_order=$7, visible=$8, updated_at=NOW()
         WHERE collection_id=$1 RETURNING *`,
        [id, b.name, b.subtitle || '', b.description || '', b.hero_image_url || b.hero_image || '',
         b.swatch_image_url || b.swatch_image || '', Number(b.sort_order || 0), b.visible !== false]
      );
      res.json({ ok: true, collection: rows[0] });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.put('/api/admin/cms/stones/:slug', authMiddleware, async (req, res) => {
    try {
      const slug = req.params.slug;
      const b = req.body || {};
      const specs = b.specs || {
        slab_width: Number(b.slab_width || 3200),
        slab_height: Number(b.slab_height || 1600),
        thickness: Number(b.thickness || 20),
        weight: Number(b.weight || 236),
        warranty: b.warranty || '15-Year Limited Warranty'
      };
      const { rows } = await pool.query(
        `UPDATE cms_stones
         SET name=$2, collection_id=$3, tagline=$4, description=$5, finish=$6,
             image_url=$7, thumbnail_url=$8, swatch_url=$9, slab_url=$10,
             gallery=$11::jsonb, specs=$12::jsonb, uv_stable=$13,
             indoor_outdoor=$14, discontinued=$15, images_pending=$16,
             visible=$17, sort_order=$18, seo_title=$19, seo_description=$20,
             updated_at=NOW()
         WHERE slug=$1 RETURNING *`,
        [slug, b.name, b.collection_id, b.tagline || '', b.description || '', b.finish || '',
         b.image_url || b.image || '', b.thumbnail_url || b.thumbnail || '',
         b.swatch_url || b.swatch || '', b.slab_url || b.slab || '',
         JSON.stringify(b.gallery || []), JSON.stringify(specs), !!b.uv_stable,
         !!b.indoor_outdoor, !!b.discontinued, !!b.images_pending,
         b.visible !== false, Number(b.sort_order || 0), b.seo_title || '', b.seo_description || '']
      );
      res.json({ ok: true, stone: rowToStone(rows[0]) });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/api/admin/cms/stones', authMiddleware, async (req, res) => {
    try {
      const b = req.body || {};
      const slug = slugify(b.slug || b.name);
      const { rows } = await pool.query(
        `INSERT INTO cms_stones
          (slug, name, collection_id, finish, description, image_url, swatch_url,
           slab_url, visible, sort_order, specs)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
         RETURNING *`,
        [slug, b.name, b.collection_id, b.finish || 'Polished Finish', b.description || '',
         b.image_url || '', b.swatch_url || '', b.slab_url || '', b.visible !== false,
         Number(b.sort_order || 999), JSON.stringify(b.specs || {})]
      );
      res.json({ ok: true, stone: rowToStone(rows[0]) });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.get('/api/admin/cms/documents', authMiddleware, async (_req, res) => {
    try {
      const { rows } = await pool.query('SELECT * FROM cms_documents ORDER BY sort_order ASC, title ASC');
      res.json({ documents: rows });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.put('/api/admin/cms/documents/:slug', authMiddleware, async (req, res) => {
    try {
      const b = req.body || {};
      const { rows } = await pool.query(
        `UPDATE cms_documents
         SET title=$2, description=$3, file_url=$4, source_url=$5,
             category=$6, sort_order=$7, visible=$8, updated_at=NOW()
         WHERE slug=$1 RETURNING *`,
        [req.params.slug, b.title, b.description || '', b.file_url, b.source_url || null,
         b.category || 'resource', Number(b.sort_order || 0), b.visible !== false]
      );
      res.json({ ok: true, document: rows[0] });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/api/admin/cms/documents/:slug/upload', authMiddleware, upload.single('file'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
      const fileUrl = `/cms-uploads/${req.file.filename}`;
      const { rows } = await pool.query(
        `UPDATE cms_documents SET file_url=$2, updated_at=NOW() WHERE slug=$1 RETURNING *`,
        [req.params.slug, fileUrl]
      );
      res.json({ ok: true, document: rows[0], file_url: fileUrl });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });
}

module.exports = { initCms, mountCms, getManagedStones };
