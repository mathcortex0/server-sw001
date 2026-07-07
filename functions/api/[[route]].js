// ========== CRYPTO HELPERS ==========
async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getSecretKey() {
  const encoder = new TextEncoder();
  const secret = 'sw001-jwt-secret-2024-production-key';
  return await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign', 'verify']
  );
}

async function signToken(payload) {
  const key = await getSecretKey();
  const encoder = new TextEncoder();
  const header = { alg: 'HS256', typ: 'JWT' };
  const hb = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const pb = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const sigInput = encoder.encode(`${hb}.${pb}`);
  const sigBuf = await crypto.subtle.sign('HMAC', key, sigInput);
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${hb}.${pb}.${sig}`;
}

async function verifyToken(token) {
  try {
    const key = await getSecretKey();
    const encoder = new TextEncoder();
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [hb, pb, sig] = parts;
    const sigInput = encoder.encode(`${hb}.${pb}`);
    const sigBuf = Uint8Array.from(
      atob(sig.replace(/-/g, '+').replace(/_/g, '/')),
      c => c.charCodeAt(0)
    );
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, sigInput);
    if (!valid) return null;
    const payload = JSON.parse(atob(pb.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ========== RESPONSE HELPERS ==========
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

function j(data, s = 200) {
  return new Response(JSON.stringify(data), {
    status: s,
    headers: { 'Content-Type': 'application/json', ...CORS }
  });
}

function e(msg, s = 400) {
  return j({ error: msg }, s);
}

async function getUser(request) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return await verifyToken(auth.slice(7));
}

// ========== DATABASE SETUP ==========
async function ensureTables(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS auth_salt (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    salt TEXT NOT NULL
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER DEFAULT NULL,
    name_enc TEXT NOT NULL,
    iv TEXT NOT NULL,
    color TEXT DEFAULT '#444444',
    created_at TEXT DEFAULT (datetime('now'))
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    folder_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    title_enc TEXT NOT NULL,
    data_enc TEXT NOT NULL,
    iv TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    imgbb_key_enc TEXT DEFAULT NULL,
    iv TEXT DEFAULT NULL
  )`).run();

  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_items_folder ON items(folder_id)`).run();

  // Seed admin: mdalamin.cnct@gmail.com / mdalaminzxcvgfdsQ
  const h = await sha256('mdalaminzxcvgfdsQ');
  await db.prepare(
    `INSERT OR IGNORE INTO users (id, email, password_hash) VALUES (1, 'mdalamin.cnct@gmail.com', ?)`
  ).bind(h).run();

  // Seed salt
  const s = await db.prepare(`SELECT id FROM auth_salt LIMIT 1`).first();
  if (!s) {
    await db.prepare(`INSERT INTO auth_salt (salt) VALUES (?)`)
      .bind(crypto.randomUUID() + crypto.randomUUID()).run();
  }

  // Seed settings row
  const st = await db.prepare(`SELECT id FROM settings LIMIT 1`).first();
  if (!st) {
    await db.prepare(`INSERT INTO settings (imgbb_key_enc, iv) VALUES (NULL, NULL)`).run();
  }
}

const migrations = [];
async function runMigrations(db) {
  for (const sql of migrations) {
    try { await db.prepare(sql).run(); } catch {}
  }
}

// ========== AUTH HANDLER ==========
async function handleAuth(method, path, body, db) {
  // POST /api/auth/login
  if (method === 'POST' && path === '/auth/login') {
    const { email, password } = body || {};
    if (!email || !password) return e('Email and password required');
    const user = await db.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
    if (!user) return e('Invalid credentials', 401);
    const hash = await sha256(password);
    if (hash !== user.password_hash) return e('Invalid credentials', 401);
    const token = await signToken({
      id: user.id,
      email: user.email,
      exp: Date.now() + 30 * 24 * 60 * 60 * 1000
    });
    return j({ token, user: { id: user.id, email: user.email } });
  }

  // GET /api/auth/salt — returns PBKDF2 salt
  if (method === 'GET' && path === '/auth/salt') {
    const row = await db.prepare(`SELECT salt FROM auth_salt LIMIT 1`).first();
    return j({ salt: row?.salt || '' });
  }

  // POST /api/auth/change-password
  if (method === 'POST' && path === '/auth/change-password') {
    const authHeader = body?.token ? `Bearer ${body.token}` : '';
    const user = authHeader ? await getUser(new Request('http://x', { headers: { Authorization: authHeader } })) : null;
    if (!user) return e('Authentication required', 401);
    const { currentPassword, newPassword } = body || {};
    if (!currentPassword || !newPassword) return e('Missing fields');
    const dbUser = await db.prepare(`SELECT * FROM users WHERE id = ?`).bind(user.id).first();
    if ((await sha256(currentPassword)) !== dbUser.password_hash) return e('Current password incorrect', 401);
    await db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`)
      .bind(await sha256(newPassword), user.id).run();
    return j({ success: true });
  }

  return null;
}

// ========== FOLDERS HANDLER ==========
async function handleFolders(method, path, body, db) {
  // GET /api/folders
  if (method === 'GET' && path === '/folders') {
    const rows = await db.prepare(
      `SELECT * FROM folders WHERE parent_id IS NULL ORDER BY created_at ASC`
    ).all();
    return j(rows.results);
  }

  // GET /api/folders/:id
  const fMatch = path.match(/^\/folders\/(\d+)$/);
  if (method === 'GET' && fMatch) {
    const id = fMatch[1];
    const folder = await db.prepare(`SELECT * FROM folders WHERE id = ?`).bind(id).first();
    if (!folder) return e('Folder not found', 404);
    const subs = await db.prepare(
      `SELECT * FROM folders WHERE parent_id = ? ORDER BY created_at ASC`
    ).bind(id).all();
    const items = await db.prepare(
      `SELECT * FROM items WHERE folder_id = ? ORDER BY created_at DESC`
    ).bind(id).all();
    return j({ folder, subfolders: subs.results, items: items.results });
  }

  // POST /api/folders
  if (method === 'POST' && path === '/folders') {
    const { name_enc, iv, parent_id, color } = body || {};
    if (!name_enc || !iv) return e('Missing encrypted data');
    const r = await db.prepare(
      `INSERT INTO folders (parent_id, name_enc, iv, color) VALUES (?, ?, ?, ?)`
    ).bind(parent_id || null, name_enc, iv, color || '#444444').run();
    return j({ id: r.meta?.last_row_id || 0 }, 201);
  }

  // PUT /api/folders/:id
  const fPut = path.match(/^\/folders\/(\d+)$/);
  if (method === 'PUT' && fPut) {
    const { name_enc, iv, color } = body || {};
    await db.prepare(`UPDATE folders SET name_enc = ?, iv = ?, color = ? WHERE id = ?`)
      .bind(name_enc, iv, color || '#444444', fPut[1]).run();
    return j({ success: true });
  }

  // DELETE /api/folders/:id
  const fDel = path.match(/^\/folders\/(\d+)$/);
  if (method === 'DELETE' && fDel) {
    const id = fDel[1];
    // Cascade delete
    await db.prepare(`DELETE FROM items WHERE folder_id = ?`).bind(id).run();
    await db.prepare(`DELETE FROM folders WHERE parent_id = ?`).bind(id).run();
    await db.prepare(`DELETE FROM folders WHERE id = ?`).bind(id).run();
    return j({ success: true });
  }

  return null;
}

// ========== ITEMS HANDLER ==========
async function handleItems(method, path, body, db) {
  // POST /api/items
  if (method === 'POST' && path === '/items') {
    const { folder_id, type, title_enc, data_enc, iv } = body || {};
    if (!folder_id || !type || !title_enc || !data_enc || !iv) return e('Missing fields');
    const r = await db.prepare(
      `INSERT INTO items (folder_id, type, title_enc, data_enc, iv) VALUES (?, ?, ?, ?, ?)`
    ).bind(folder_id, type, title_enc, data_enc, iv).run();
    return j({ id: r.meta?.last_row_id || 0 }, 201);
  }

  // PUT /api/items/:id
  const iPut = path.match(/^\/items\/(\d+)$/);
  if (method === 'PUT' && iPut) {
    const { title_enc, data_enc, iv } = body || {};
    await db.prepare(
      `UPDATE items SET title_enc = ?, data_enc = ?, iv = ?, updated_at = datetime('now') WHERE id = ?`
    ).bind(title_enc, data_enc, iv, iPut[1]).run();
    return j({ success: true });
  }

  // DELETE /api/items/:id
  const iDel = path.match(/^\/items\/(\d+)$/);
  if (method === 'DELETE' && iDel) {
    await db.prepare(`DELETE FROM items WHERE id = ?`).bind(iDel[1]).run();
    return j({ success: true });
  }

  return null;
}

// ========== SETTINGS HANDLER ==========
async function handleSettings(method, path, body, db) {
  // GET /api/settings
  if (method === 'GET' && path === '/settings') {
    const row = await db.prepare(`SELECT * FROM settings LIMIT 1`).first();
    return j(row || {});
  }

  // PUT /api/settings/imgbb
  if (method === 'PUT' && path === '/settings/imgbb') {
    const { imgbb_key_enc, iv } = body || {};
    await db.prepare(`UPDATE settings SET imgbb_key_enc = ?, iv = ? WHERE id = 1`)
      .bind(imgbb_key_enc || null, iv || null).run();
    return j({ success: true });
  }

  return null;
}

// ========== MAIN EXPORT ==========
async function onRequest(context) {
  const { request, env } = context;
  const db = env.SW_DB;

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  // Init tables once
  if (!globalThis.__tablesReady) {
    await ensureTables(db);
    await runMigrations(db);
    globalThis.__tablesReady = true;
  }

  const url = new URL(request.url);
  const path = url.pathname.replace('/api', '');
  const method = request.method;
  let body = null;
  if (method !== 'GET' && method !== 'OPTIONS') {
    try { body = await request.json(); } catch {}
  }

  // Public: auth routes
  const authResult = await handleAuth(method, path, body, db);
  if (authResult) return authResult;

  // Everything else requires authentication
  const user = await getUser(request);
  if (!user) return e('Not found', 404); // Disguise: return 404, not 401

  // Protected routes
  const folderResult = await handleFolders(method, path, body, db);
  if (folderResult) return folderResult;

  const itemResult = await handleItems(method, path, body, db);
  if (itemResult) return itemResult;

  const settingsResult = await handleSettings(method, path, body, db);
  if (settingsResult) return settingsResult;

  return e('Not found', 404);
}

export { onRequest };
