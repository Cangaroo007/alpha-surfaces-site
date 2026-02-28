// lib/versions.js — Multi-level version history for Alpha Surfaces CMS
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const VERSIONS_DIR = path.join(DATA_DIR, 'versions');
const MAX_VERSIONS = 50;

// ─── Directory helpers ───

function contentDir() {
  return path.join(VERSIONS_DIR, 'content');
}

function contentSnapshotsDir() {
  return path.join(contentDir(), 'snapshots');
}

function pageDir(pageKey) {
  return path.join(VERSIONS_DIR, 'pages', pageKey);
}

function pageSnapshotsDir(pageKey) {
  return path.join(pageDir(pageKey), 'snapshots');
}

function indexPath(pageKey) {
  if (pageKey === 'content') return path.join(contentDir(), 'index.json');
  return path.join(pageDir(pageKey), 'index.json');
}

function snapshotPath(pageKey, id) {
  const ext = pageKey === 'content' ? '.json' : '.html';
  if (pageKey === 'content') return path.join(contentSnapshotsDir(), id + ext);
  return path.join(pageSnapshotsDir(pageKey), id + ext);
}

// ─── Ensure directories exist on startup ───

function ensureDirectories() {
  fs.mkdirSync(contentSnapshotsDir(), { recursive: true });
  // Page directories are created on demand when pages are detected
}

// ─── Index read/write ───

function readIndex(pageKey) {
  const p = indexPath(pageKey);
  try {
    if (fs.existsSync(p)) {
      return JSON.parse(fs.readFileSync(p, 'utf8'));
    }
  } catch (err) {
    console.error(`Failed to read version index for ${pageKey}:`, err.message);
  }
  return [];
}

function writeIndex(pageKey, index) {
  const p = indexPath(pageKey);
  fs.writeFileSync(p, JSON.stringify(index, null, 2));
}

// ─── Auto-label generation ───

function generateAutoLabel(diff) {
  if (!diff || diff.length === 0) return 'AI edit';

  // Group changed paths by their top-level section
  const sections = {};
  for (const { path: fieldPath } of diff) {
    const section = fieldPath.split('.')[0].split('[')[0];
    sections[section] = (sections[section] || 0) + 1;
  }

  const parts = Object.entries(sections).map(([s, n]) =>
    n === 1 ? diff.find(d => d.path.split('.')[0].split('[')[0] === s).path : `${n} fields in ${s}`
  );

  const label = 'AI: ' + parts.slice(0, 3).join(', ');
  return parts.length > 3 ? label + ` (+${parts.length - 3} more)` : label;
}

// ─── Hash for change detection (page versions) ───

function hashContents(contents) {
  return Buffer.from(contents).toString('base64').slice(0, 16);
}

// ─── Pruning ───

function pruneOldVersions(pageKey) {
  const index = readIndex(pageKey);
  if (index.length <= MAX_VERSIONS) return;

  // Find unprotected versions to prune (oldest first — index is newest-first)
  const unprotected = [];
  for (let i = index.length - 1; i >= 0; i--) {
    if (!index[i].protected) {
      unprotected.push(i);
    }
  }

  const toRemove = index.length - MAX_VERSIONS;
  if (unprotected.length < toRemove) {
    console.warn(`[versions] Warning: ${pageKey} has ${index.length} versions and only ${unprotected.length} are unprotected. Cannot prune to ${MAX_VERSIONS}.`);
  }

  // Remove oldest unprotected versions
  const indicesToRemove = unprotected.slice(0, toRemove);
  // Sort descending so splice indices remain valid
  indicesToRemove.sort((a, b) => b - a);

  for (const idx of indicesToRemove) {
    const version = index[idx];
    // Delete snapshot file
    const snapPath = snapshotPath(pageKey, version.id);
    try {
      if (fs.existsSync(snapPath)) fs.unlinkSync(snapPath);
    } catch (err) {
      console.error(`Failed to delete snapshot ${snapPath}:`, err.message);
    }
    // Remove from index
    index.splice(idx, 1);
  }

  writeIndex(pageKey, index);
}

// ─── Core: createVersion ───

function createVersion(pageKey, content, metadata) {
  const id = 'v_' + Date.now();
  const timestamp = new Date().toISOString();

  // Ensure directories for page versions
  if (pageKey !== 'content') {
    fs.mkdirSync(pageSnapshotsDir(pageKey), { recursive: true });
  }

  // Write snapshot
  const snapPath = snapshotPath(pageKey, id);
  const snapshotContent = pageKey === 'content'
    ? JSON.stringify(content, null, 2)
    : String(content);
  fs.writeFileSync(snapPath, snapshotContent);

  const sizeBytes = fs.statSync(snapPath).size;

  // Build metadata entry
  const entry = {
    id,
    timestamp,
    label: metadata.label || null,
    autoLabel: metadata.autoLabel || 'Snapshot',
    source: metadata.source || 'unknown',
    changeCount: metadata.changeCount || 0,
    sizeBytes,
    protected: metadata.protected || false,
  };

  // Add hash for page versions
  if (pageKey !== 'content') {
    entry.hash = hashContents(snapshotContent);
  }

  // Prepend to index
  const index = readIndex(pageKey);
  index.unshift(entry);
  writeIndex(pageKey, index);

  // Prune
  pruneOldVersions(pageKey);

  return entry;
}

// ─── getIndex ───

function getIndex(pageKey) {
  return readIndex(pageKey);
}

// ─── getSnapshot ───

function getSnapshot(pageKey, id) {
  const snapPath = snapshotPath(pageKey, id);
  if (!fs.existsSync(snapPath)) return null;

  const raw = fs.readFileSync(snapPath, 'utf8');
  if (pageKey === 'content') {
    try { return JSON.parse(raw); } catch { return raw; }
  }
  return raw;
}

// ─── getDiff ───

function getDiff(pageKey, id, currentLiveContent) {
  const snapshot = getSnapshot(pageKey, id);
  if (snapshot === null) return null;

  // Find the version entry to determine timestamp
  const index = readIndex(pageKey);
  const versionEntry = index.find(v => v.id === id);
  const snapshotTime = versionEntry ? new Date(versionEntry.timestamp) : new Date(0);
  const snapshotIsOlder = true; // Snapshots should always be older than current

  if (pageKey === 'content') {
    // Deep diff between snapshot and current live content
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

      const aStr = a != null ? String(a) : '';
      const bStr = b != null ? String(b) : '';
      if (aStr !== bStr) {
        diffs.push({ path: currentPath, snapshot: aStr, current: bStr });
      }
    }

    walk(snapshot, currentLiveContent, '');

    return {
      ok: true,
      diff: diffs,
      snapshotIsOlder,
    };
  } else {
    // HTML page diff — character count only
    const snapshotBytes = Buffer.byteLength(snapshot, 'utf8');
    const currentStr = String(currentLiveContent);
    const currentBytes = Buffer.byteLength(currentStr, 'utf8');
    return {
      ok: true,
      diff: [],
      snapshotIsOlder,
      htmlDiff: {
        snapshotBytes,
        currentBytes,
        deltaBytes: currentBytes - snapshotBytes,
      },
    };
  }
}

// ─── renameVersion ───

function renameVersion(pageKey, id, label) {
  const index = readIndex(pageKey);
  const entry = index.find(v => v.id === id);
  if (!entry) return null;

  entry.label = label;
  writeIndex(pageKey, index);
  return entry;
}

// ─── deleteVersion ───

function deleteVersion(pageKey, id) {
  const index = readIndex(pageKey);
  const idx = index.findIndex(v => v.id === id);
  if (idx === -1) return { ok: false, message: 'Version not found.' };

  const entry = index[idx];
  if (entry.protected) {
    return { ok: false, message: 'Checkpoint versions cannot be deleted. Rename it or use the star button to unprotect it first.' };
  }

  // Delete snapshot file
  const snapPath = snapshotPath(pageKey, id);
  try {
    if (fs.existsSync(snapPath)) fs.unlinkSync(snapPath);
  } catch (err) {
    console.error(`Failed to delete snapshot ${snapPath}:`, err.message);
  }

  // Remove from index
  index.splice(idx, 1);
  writeIndex(pageKey, index);
  return { ok: true };
}

// ─── restoreVersion ───

function restoreVersion(pageKey, id, currentLiveContent, writeLiveFile) {
  const snapshot = getSnapshot(pageKey, id);
  if (snapshot === null) return { ok: false, message: 'Snapshot not found.' };

  // Find the version's timestamp for the auto-label
  const index = readIndex(pageKey);
  const versionEntry = index.find(v => v.id === id);
  const targetTime = versionEntry
    ? new Date(versionEntry.timestamp).toLocaleString('en-AU', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
    : 'unknown time';

  // Auto-snapshot current live content before restoring
  createVersion(pageKey, currentLiveContent, {
    source: 'restore',
    autoLabel: `Before restore to ${targetTime}`,
    changeCount: 0,
    protected: false,
  });

  // Write the snapshot as the new live content
  writeLiveFile(snapshot);

  return { ok: true, message: 'Restored. Current version saved as a new snapshot.' };
}

// ─── createCheckpoint ───

function createCheckpoint(pageKey, currentLiveContent, label) {
  return createVersion(pageKey, currentLiveContent, {
    source: 'checkpoint',
    autoLabel: 'Checkpoint',
    label: label || null,
    changeCount: 0,
    protected: true,
  });
}

// ─── toggleProtect ───

function toggleProtect(pageKey, id, protectedVal) {
  const index = readIndex(pageKey);
  const entry = index.find(v => v.id === id);
  if (!entry) return null;

  entry.protected = protectedVal;
  writeIndex(pageKey, index);
  return entry;
}

// ─── detectAndSnapshotPages ───

function detectAndSnapshotPages() {
  const publicDir = path.join(__dirname, '..', 'public');
  const excludeFiles = ['index.html', 'admin.html'];

  let htmlFiles;
  try {
    htmlFiles = fs.readdirSync(publicDir).filter(f =>
      f.endsWith('.html') && !excludeFiles.includes(f)
    );
  } catch (err) {
    console.error('Failed to read public/ for landing page detection:', err.message);
    return;
  }

  for (const file of htmlFiles) {
    const pageKey = path.basename(file, '.html');
    const filePath = path.join(publicDir, file);

    // Ensure page version directories
    fs.mkdirSync(pageSnapshotsDir(pageKey), { recursive: true });

    // Read file contents
    let contents;
    try {
      contents = fs.readFileSync(filePath, 'utf8');
    } catch (err) {
      console.error(`Failed to read ${filePath}:`, err.message);
      continue;
    }

    const hash = hashContents(contents);

    // Read existing index
    const index = readIndex(pageKey);

    // Check if changed vs most recent version
    if (index.length > 0 && index[0].hash === hash) {
      console.log(`[versions] ${pageKey}.html unchanged — skipping startup snapshot`);
      continue;
    }

    // Create startup snapshot
    console.log(`[versions] ${pageKey}.html ${index.length === 0 ? 'first snapshot' : 'changed'} — creating startup snapshot`);
    createVersion(pageKey, contents, {
      source: 'startup',
      autoLabel: 'Server startup snapshot',
      changeCount: 0,
      protected: false,
    });
  }
}

// ─── Startup snapshot for content.json ───

function snapshotContentOnStartup(currentContent) {
  const index = readIndex('content');
  // Always create a startup snapshot if no versions exist
  if (index.length === 0) {
    console.log('[versions] No content versions found — creating startup snapshot');
    createVersion('content', currentContent, {
      source: 'startup',
      autoLabel: 'Server startup snapshot',
      changeCount: 0,
      protected: false,
    });
  }
}

// ─── Exports ───

module.exports = {
  ensureDirectories,
  createVersion,
  getIndex,
  getSnapshot,
  getDiff,
  renameVersion,
  deleteVersion,
  restoreVersion,
  createCheckpoint,
  pruneOldVersions,
  detectAndSnapshotPages,
  snapshotContentOnStartup,
  generateAutoLabel,
  toggleProtect,
  DATA_DIR,
  VERSIONS_DIR,
  MAX_VERSIONS,
};
