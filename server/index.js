/**
 * FlashNPrint API — SQLite + JWT + rate limits + support chat
 */
import express from 'express';
import cors from 'cors';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import fs from 'fs';
import rateLimit from 'express-rate-limit';
import { catalog3d, MODEL_CATEGORIES } from './catalog3d.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.join(__dirname, '..');

dotenv.config({ path: path.join(rootDir, '.env') });

const PORT = Number(process.env.PORT) || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-insecure-change-me';
const DB_PATH = process.env.SQLITE_PATH || path.join(rootDir, 'data', 'fnp.sqlite');

const MAX_CHAT_BODY = 2000;
const MAX_ORDER_ITEMS = 50;
const MAX_SUPPORT_POLL = 200;

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '512kb' }));

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_GLOBAL_PER_MIN) || 100,
  standardHeaders: true,
  legacyHeaders: false,
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_AUTH_PER_15M) || 25,
  standardHeaders: true,
  legacyHeaders: false,
});
const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_WRITE_PER_MIN) || 40,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', globalLimiter);

function initDb() {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE COLLATE NOCASE,
      phone TEXT UNIQUE,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      student_id TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
      points INTEGER NOT NULL DEFAULT 0,
      rank TEXT NOT NULL DEFAULT 'bronze' CHECK (rank IN ('bronze', 'silver', 'gold', 'platinum')),
      reset_token TEXT,
      reset_expires TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_login_at TEXT
    );

    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      name_en TEXT,
      description TEXT,
      description_en TEXT,
      price INTEGER NOT NULL,
      category TEXT NOT NULL,
      image TEXT,
      unit TEXT,
      min_quantity INTEGER DEFAULT 1,
      pickup_only INTEGER DEFAULT 0,
      variants_json TEXT,
      is_promotion INTEGER DEFAULT 0,
      stock_limit INTEGER DEFAULT -1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','ready','completed','cancelled')),
      total INTEGER NOT NULL,
      delivery_address TEXT,
      pickup_location TEXT,
      payment_method TEXT,
      payment_status TEXT NOT NULL DEFAULT 'unpaid' CHECK (payment_status IN ('unpaid','pending_verification','paid')),
      items_json TEXT NOT NULL,
      estimated_time TEXT,
      delivery_date TEXT,
      delivery_time TEXT,
      received_points INTEGER DEFAULT 0,
      guest_name TEXT,
      guest_phone TEXT,
      cancel_reason TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS order_notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
      comment TEXT,
      points_awarded INTEGER DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS coupons (
      code TEXT PRIMARY KEY COLLATE NOCASE,
      discount_percent INTEGER NOT NULL,
      max_uses INTEGER DEFAULT -1,
      used_count INTEGER DEFAULT 0,
      expires_at TEXT,
      min_spent INTEGER DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS support_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      order_id TEXT,
      from_admin INTEGER NOT NULL CHECK (from_admin IN (0, 1)),
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Column Migrations for existing tables (in case table already existed)
  const uCols = db.prepare(`PRAGMA table_info(users)`).all().map(c => c.name);
  if (!uCols.includes('phone')) db.exec(`ALTER TABLE users ADD COLUMN phone TEXT`);
  if (!uCols.includes('points')) db.exec(`ALTER TABLE users ADD COLUMN points INTEGER DEFAULT 0`);
  if (!uCols.includes('rank')) db.exec(`ALTER TABLE users ADD COLUMN rank TEXT DEFAULT 'bronze'`);
  if (!uCols.includes('reset_token')) db.exec(`ALTER TABLE users ADD COLUMN reset_token TEXT`);
  if (!uCols.includes('reset_expires')) db.exec(`ALTER TABLE users ADD COLUMN reset_expires TEXT`);

  // Migration: Make email nullable
  const uInfo = db.prepare(`PRAGMA table_info(users)`).all();
  const emailColInfo = uInfo.find(c => c.name === 'email');
  if (emailColInfo && emailColInfo.notnull === 1) {
    console.log('[fnp-api] Migration: Making email nullable in users table...');
    db.exec(`
      CREATE TABLE users_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE COLLATE NOCASE,
        phone TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        student_id TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
        points INTEGER NOT NULL DEFAULT 0,
        rank TEXT NOT NULL DEFAULT 'bronze' CHECK (rank IN ('bronze', 'silver', 'gold', 'platinum')),
        reset_token TEXT,
        reset_expires TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_login_at TEXT
      );
      INSERT INTO users_new (id, email, phone, password_hash, name, student_id, role, points, rank, reset_token, reset_expires, created_at, last_login_at)
      SELECT id, email, phone, password_hash, name, student_id, role, points, rank, reset_token, reset_expires, created_at, last_login_at FROM users;
      DROP TABLE users;
      ALTER TABLE users_new RENAME TO users;
    `);
  }

  const oCols = db.prepare(`PRAGMA table_info(orders)`).all().map(c => c.name);
  if (!oCols.includes('delivery_date')) db.exec(`ALTER TABLE orders ADD COLUMN delivery_date TEXT`);
  if (!oCols.includes('delivery_time')) db.exec(`ALTER TABLE orders ADD COLUMN delivery_time TEXT`);
  if (!oCols.includes('received_points')) db.exec(`ALTER TABLE orders ADD COLUMN received_points INTEGER DEFAULT 0`);
  if (!oCols.includes('payment_status')) db.exec(`ALTER TABLE orders ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'unpaid' CHECK (payment_status IN ('unpaid','pending_verification','paid'))`);
  if (!oCols.includes('guest_email')) db.exec(`ALTER TABLE orders ADD COLUMN guest_email TEXT`);

  // Product 3D metadata migrations (columns added over time)
  const pCols = db.prepare(`PRAGMA table_info(products)`).all().map(c => c.name);
  const addProdCol = (col, type) => { if (!pCols.includes(col)) db.exec(`ALTER TABLE products ADD COLUMN ${col} ${type}`); };
  addProdCol('model_viewer_url', 'TEXT');
  addProdCol('sub_name', 'TEXT');
  addProdCol('rating', 'REAL');
  addProdCol('review_count', 'INTEGER');
  addProdCol('poly_count', 'TEXT');
  addProdCol('vertex_count', 'TEXT');
  addProdCol('textures', 'TEXT');
  addProdCol('rigged', 'INTEGER DEFAULT 0');
  addProdCol('animated', 'INTEGER DEFAULT 0');
  addProdCol('formats_json', 'TEXT');
  addProdCol('accent_color', 'TEXT');
  addProdCol('tags_json', 'TEXT');

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
    CREATE INDEX IF NOT EXISTS idx_products_cat ON products(category);
    CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);
    CREATE INDEX IF NOT EXISTS idx_reviews_order ON reviews(order_id);
    CREATE INDEX IF NOT EXISTS idx_reviews_user ON reviews(user_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_order ON order_notifications(order_id);
    CREATE INDEX IF NOT EXISTS idx_support_user ON support_messages(user_id);
  `);


  // Purge legacy printing-service products (anything outside 3D-model categories)
  // and keep the products table in sync with the canonical 3D catalog.
  {
    const modelCats = MODEL_CATEGORIES.map(() => '?').join(',');
    const legacy = db
      .prepare(`SELECT COUNT(*) AS c FROM products WHERE category NOT IN (${modelCats})`)
      .get(...MODEL_CATEGORIES).c;
    if (legacy > 0) {
      db.prepare(`DELETE FROM products WHERE category NOT IN (${modelCats})`).run(...MODEL_CATEGORIES);
      console.log(`[polystore-api] Removed ${legacy} legacy printing-service products.`);
    }

    const upsert = db.prepare(`
      INSERT INTO products (
        id, name, name_en, description, description_en, price, category, image, unit,
        min_quantity, pickup_only, is_promotion, stock_limit, model_viewer_url, sub_name,
        rating, review_count, poly_count, vertex_count, textures, rigged, animated,
        formats_json, accent_color, tags_json
      ) VALUES (
        @id, @name, @name_en, @description, @description_en, @price, @category, @image, @unit,
        @min_quantity, @pickup_only, @is_promotion, @stock_limit, @model_viewer_url, @sub_name,
        @rating, @review_count, @poly_count, @vertex_count, @textures, @rigged, @animated,
        @formats_json, @accent_color, @tags_json
      )
      ON CONFLICT(id) DO UPDATE SET
        name=excluded.name, name_en=excluded.name_en, description=excluded.description,
        description_en=excluded.description_en, price=excluded.price, category=excluded.category,
        image=excluded.image, unit=excluded.unit, min_quantity=excluded.min_quantity,
        pickup_only=excluded.pickup_only, is_promotion=excluded.is_promotion,
        stock_limit=excluded.stock_limit, model_viewer_url=excluded.model_viewer_url,
        sub_name=excluded.sub_name, rating=excluded.rating, review_count=excluded.review_count,
        poly_count=excluded.poly_count, vertex_count=excluded.vertex_count, textures=excluded.textures,
        rigged=excluded.rigged, animated=excluded.animated, formats_json=excluded.formats_json,
        accent_color=excluded.accent_color, tags_json=excluded.tags_json
    `);
    const syncAll = db.transaction((items) => {
      for (const p of items) {
        upsert.run({
          id: p.id,
          name: p.name,
          name_en: p.nameEn ?? null,
          description: p.description ?? '',
          description_en: p.descriptionEn ?? null,
          price: p.price,
          category: p.category,
          image: p.image ?? '',
          unit: p.unit ?? '',
          min_quantity: p.minQuantity ?? 1,
          pickup_only: p.pickupOnly ? 1 : 0,
          is_promotion: p.isPromotion ? 1 : 0,
          stock_limit: p.stockLimit ?? -1,
          model_viewer_url: p.modelViewerUrl ?? null,
          sub_name: p.subName ?? null,
          rating: p.rating ?? null,
          review_count: p.reviewCount ?? null,
          poly_count: p.polyCount ?? null,
          vertex_count: p.vertexCount ?? null,
          textures: p.textures ?? null,
          rigged: p.rigged ? 1 : 0,
          animated: p.animated ? 1 : 0,
          formats_json: p.formats ? JSON.stringify(p.formats) : null,
          accent_color: p.accentColor ?? null,
          tags_json: p.tags ? JSON.stringify(p.tags) : null,
        });
      }
    });
    syncAll(catalog3d);
    console.log(`[polystore-api] Synced ${catalog3d.length} 3D products from canonical catalog.`);
  }

  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@polystore.com').trim().toLowerCase();
  const adminPass = process.env.ADMIN_PASSWORD || 'admin';
  const hash = bcrypt.hashSync(adminPass, 10);
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
  if (!exists) {
    db.prepare(
      `INSERT INTO users (email, password_hash, name, student_id, role) VALUES (?,?,?,?, 'admin')`,
    ).run(adminEmail, hash, 'PolyStore Admin', '000000');
    console.log(`[polystore-api] Seeded PolyStore admin user: ${adminEmail} / password: ${adminPass}`);
  } else {
    db.prepare(`UPDATE users SET password_hash = ?, role = 'admin' WHERE email = ?`).run(hash, adminEmail);
    console.log(`[polystore-api] Enforced password and admin role for: ${adminEmail}`);
  }

  // Seed a demo customer so the "customer" role login always exists after a
  // redeploy (Render's SQLite is ephemeral). Credentials are overridable via env.
  const customerEmail = (process.env.CUSTOMER_EMAIL || 'customer@polystore.com').trim().toLowerCase();
  const customerPass = process.env.CUSTOMER_PASSWORD || 'customer123';
  const customerHash = bcrypt.hashSync(customerPass, 10);
  const customerExists = db.prepare('SELECT id FROM users WHERE email = ?').get(customerEmail);
  if (!customerExists) {
    db.prepare(
      `INSERT INTO users (email, password_hash, name, student_id, role) VALUES (?,?,?,?, 'user')`,
    ).run(customerEmail, customerHash, 'Demo Customer', '000001');
    console.log(`[polystore-api] Seeded demo customer: ${customerEmail} / password: ${customerPass}`);
  } else {
    db.prepare(`UPDATE users SET password_hash = ?, role = 'user' WHERE email = ?`).run(customerHash, customerEmail);
    console.log(`[polystore-api] Enforced password and user role for: ${customerEmail}`);
  }

  // Seed initial coupons if empty or missing POLY100
  const poly100Exists = db.prepare(`SELECT code FROM coupons WHERE code = 'POLY100'`).get();
  if (!poly100Exists) {
    db.prepare(`INSERT INTO coupons (code, discount_percent, max_uses, min_spent) VALUES (?,?,?,?)`)
      .run('POLY100', 100, -1, 0);
    console.log(`[polystore-api] Seeded POLY100 coupon (100% discount)`);
  }

  // Migration: vip -> platinum
  db.prepare(`UPDATE users SET rank = 'platinum' WHERE rank = 'vip'`).run();

  try {
    db.prepare(`UPDATE users SET role = 'user' WHERE email = 'huythepro2121@gmail.com'`).run();
    db.prepare(`UPDATE users SET role = 'user' WHERE email = 'basicallybao1401@vanlanguni.vn'`).run();
    console.log(`[fnp-api] Cleaned up admin roles for test accounts.`);
  } catch (e) {}

  return db;
}

const db = initDb();

const VANLANG = '@vanlanguni.vn';

function isValidEmail(email) {
  return typeof email === 'string' && email.includes('@') && email.length > 5;
}

function isDigitsOnly(s) {
  return typeof s === 'string' && /^\d+$/.test(s.trim());
}

function signToken(user) {
  return jwt.sign({ sub: user.id, role: user.role, email: user.email }, JWT_SECRET, {
    expiresIn: '7d',
  });
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  const token = h?.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) {
    req.user = null;
    return next();
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = {
      id: payload.sub,
      role: payload.role,
      email: payload.email,
    };
  } catch {
    req.user = null;
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user?.id) return res.status(401).json({ error: 'unauthorized' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user?.id || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

function userDto(row, stats) {
  return {
    id: row.id,
    name: row.name,
    schoolEmail: row.email,
    phone: row.phone || null,
    role: row.role,
    lastLoginAt: row.last_login_at || null,
    createdAt: row.created_at || null,
    orderCount: stats?.orderCount ?? 0,
    totalSpent: stats?.totalSpent ?? 0,
  };
}

function statsForUser(userId) {
  const s = db
    .prepare(
      `SELECT COUNT(*) as c, COALESCE(SUM(CASE WHEN status = 'completed' THEN total ELSE 0 END), 0) as spent
       FROM orders WHERE user_id = ?`,
    )
    .get(userId);
  return { orderCount: s.c, totalSpent: s.spent };
}

app.use(authMiddleware);

app.post('/api/auth/register', authLimiter, (req, res) => {
  const { name, schoolEmail, phone, password } = req.body || {};
  if (!name?.trim() || !schoolEmail?.trim() || !password) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  const email = schoolEmail.trim().toLowerCase();
  if (!isValidEmail(email)) return res.status(400).json({ error: 'invalid_email' });
  if (password.length < 4) return res.status(400).json({ error: 'weak_password' });

  const phoneNum = phone ? String(phone).trim() : null;

  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db
      .prepare(
        `INSERT INTO users (email, phone, password_hash, name, student_id, role) VALUES (?,?,?,?,?, 'user')`,
      )
      .run(email, phoneNum, hash, name.trim(), '');
    const user = db
      .prepare(`SELECT * FROM users WHERE id = ?`)
      .get(info.lastInsertRowid);
    db.prepare(`UPDATE users SET last_login_at = datetime('now') WHERE id = ?`).run(user.id);
    const refreshed = db
      .prepare(`SELECT * FROM users WHERE id = ?`)
      .get(user.id);
    const token = signToken(refreshed);
    const st = statsForUser(refreshed.id);
    return res.status(201).json({ token, user: userDto(refreshed, st) });
  } catch (e) {
    if (String(e).includes('UNIQUE')) {
      if (String(e).includes('phone')) return res.status(409).json({ error: 'phone_taken' });
      return res.status(409).json({ error: 'email_taken' });
    }
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/auth/login', authLimiter, (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });
  
  const identifier = email.trim().toLowerCase();
  const row = db
    .prepare(
      `SELECT id, email, phone, name, student_id, role, password_hash, last_login_at, created_at FROM users WHERE email = ? OR phone = ?`,
    )
    .get(identifier, identifier);
    
  if (!row || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  db.prepare(`UPDATE users SET last_login_at = datetime('now') WHERE id = ?`).run(row.id);
  const user = db
    .prepare(`SELECT id, email, phone, name, student_id, role, last_login_at, created_at FROM users WHERE id = ?`)
    .get(row.id);
  const token = signToken(user);
  const st = statsForUser(user.id);
  res.json({ token, user: userDto(user, st) });
});

app.post('/api/auth/forgot-password', authLimiter, (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'missing_email' });
  const user = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email.trim().toLowerCase());
  
  // We always return 200 for security, but actually process if user exists
  if (user) {
    const token = crypto.randomBytes(20).toString('hex');
    const expires = new Date(Date.now() + 3600000).toISOString(); // 1 hour
    db.prepare(`UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?`).run(token, expires, user.id);
    console.log(`[fnp-api] Password reset for ${email}: ${token}`);
    // In a real app, send email here
    return res.json({ ok: true, debug_token: token }); // debug_token for dev ease
  }
  res.json({ ok: true });
});

app.post('/api/auth/reset-password', authLimiter, (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword || newPassword.length < 4) return res.status(400).json({ error: 'invalid_request' });
  
  const user = db.prepare(`SELECT id, reset_expires FROM users WHERE reset_token = ?`).get(token);
  if (!user || new Date(user.reset_expires) < new Date()) {
    return res.status(400).json({ error: 'invalid_or_expired_token' });
  }

  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare(`UPDATE users SET password_hash = ?, reset_token = null, reset_expires = null WHERE id = ?`).run(hash, user.id);
  res.json({ ok: true });
});

app.post('/api/auth/change-password', requireAuth, writeLimiter, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword || newPassword.length < 4) return res.status(400).json({ error: 'invalid_request' });

  const user = db.prepare(`SELECT password_hash FROM users WHERE id = ?`).get(req.user.id);
  if (!bcrypt.compareSync(oldPassword, user.password_hash)) {
    return res.status(401).json({ error: 'invalid_old_password' });
  }

  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).run(hash, req.user.id);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const row = db
    .prepare(`SELECT id, email, phone, name, role, last_login_at, created_at FROM users WHERE id = ?`)
    .get(req.user.id);
  if (!row) return res.status(401).json({ error: 'unauthorized' });
  const st = statsForUser(row.id);
  res.json(userDto(row, st));
});

app.patch('/api/auth/me', requireAuth, writeLimiter, (req, res) => {
  const { name, phone } = req.body || {};
  const row = db.prepare(`SELECT id FROM users WHERE id = ?`).get(req.user.id);
  if (!row) return res.status(401).json({ error: 'unauthorized' });

  const updates = [];
  const vals = [];
  if (name !== undefined) {
    if (!String(name).trim()) return res.status(400).json({ error: 'invalid_name' });
    updates.push('name = ?');
    vals.push(String(name).trim());
  }
  if (phone !== undefined) {
    updates.push('phone = ?');
    vals.push(phone ? String(phone).trim() : null);
  }
  if (!updates.length) return res.status(400).json({ error: 'nothing_to_update' });
  vals.push(req.user.id);
  try {
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...vals);
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'phone_taken' });
    throw e;
  }
  const u = db
    .prepare(`SELECT id, email, phone, name, role, last_login_at, created_at FROM users WHERE id = ?`)
    .get(req.user.id);
  const st = statsForUser(u.id);
  res.json(userDto(u, st));
});

app.post('/api/redeem-points', requireAuth, writeLimiter, (req, res) => {
  // Loyalty program removed — endpoint retired.
  return res.status(410).json({ error: 'feature_removed' });
});

/** Products */
function safeParseJson(str, fallback) {
  if (!str) return fallback;
  try { return JSON.parse(str); } catch { return fallback; }
}

function serializeProduct(r) {
  return {
    id: r.id,
    name: r.name,
    nameEn: r.name_en || undefined,
    description: r.description || '',
    descriptionEn: r.description_en || undefined,
    price: r.price,
    category: r.category,
    image: r.image || '',
    unit: r.unit || '',
    minQuantity: r.min_quantity ?? 1,
    pickupOnly: !!r.pickup_only,
    variants: r.variants_json ? safeParseJson(r.variants_json, undefined) : undefined,
    isPromotion: !!r.is_promotion,
    stockLimit: r.stock_limit ?? -1,
    modelViewerUrl: r.model_viewer_url || undefined,
    subName: r.sub_name || undefined,
    rating: r.rating ?? undefined,
    reviewCount: r.review_count ?? undefined,
    polyCount: r.poly_count || undefined,
    vertexCount: r.vertex_count || undefined,
    textures: r.textures || undefined,
    rigged: r.rigged == null ? undefined : !!r.rigged,
    animated: r.animated == null ? undefined : !!r.animated,
    formats: r.formats_json ? safeParseJson(r.formats_json, undefined) : undefined,
    accentColor: r.accent_color || undefined,
    tags: r.tags_json ? safeParseJson(r.tags_json, undefined) : undefined,
  };
}

app.get('/api/products', (req, res) => {
  const rows = db.prepare(`SELECT * FROM products ORDER BY category, created_at DESC`).all();
  res.json(rows.map(serializeProduct));
});

/** Coupons */
app.post('/api/coupons/validate', writeLimiter, (req, res) => {
  const { code, totalSpent } = req.body || {};
  if (!code) return res.status(400).json({ error: 'missing_code' });
  
  const coupon = db.prepare(`SELECT * FROM coupons WHERE code = ?`).get(code.trim());
  if (!coupon) return res.status(404).json({ error: 'invalid_coupon' });
  
  if (coupon.expires_at && new Date(coupon.expires_at) < new Date()) {
    return res.status(400).json({ error: 'expired_coupon' });
  }
  
  if (coupon.max_uses !== -1 && coupon.used_count >= coupon.max_uses) {
    return res.status(400).json({ error: 'coupon_usage_limit_reached' });
  }
  
  if (totalSpent < coupon.min_spent) {
    return res.status(400).json({ error: 'min_spent_not_reached', minSpent: coupon.min_spent });
  }
  
  res.json({
    code: coupon.code,
    discountPercent: coupon.discount_percent
  });
});

/** Customer: lightweight fingerprint for UI sounds (poll every ~20s) */
app.get('/api/customer/alerts', requireAuth, (req, res) => {
  const uid = req.user.id;
  const n = db
    .prepare(
      `SELECT MAX(n.id) as m FROM order_notifications n
       JOIN orders o ON o.id = n.order_id WHERE o.user_id = ?`,
    )
    .get(uid);
  const s = db
    .prepare(`SELECT MAX(id) as m FROM support_messages WHERE user_id = ? AND from_admin = 1`)
    .get(uid);
  res.json({
    maxNotificationId: n?.m ?? 0,
    maxAdminSupportId: s?.m ?? 0,
  });
});

/** Admin: new orders / new user chat messages */
app.get('/api/admin/alerts', requireAuth, requireAdmin, (req, res) => {
  const o = db.prepare(`SELECT COUNT(*) as c, MAX(created_at) as t FROM orders`).get();
  const m = db.prepare(`SELECT MAX(id) as mid FROM support_messages WHERE from_admin = 0`).get();
  res.json({
    orderCount: o?.c ?? 0,
    latestOrderCreatedAt: o?.t ?? null,
    maxUserSupportId: m?.mid ?? 0,
  });
});

function parseOrderRow(row, notifications = []) {
  let items = [];
  try {
    items = JSON.parse(row.items_json || '[]');
  } catch {
    items = [];
  }
  return {
    id: row.id,
    userId: row.user_id,
    items,
    total: row.total,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    estimatedTime: row.estimated_time || undefined,
    deliveryAddress: row.delivery_address || undefined,
    pickupLocation: row.pickup_location || undefined,
    paymentMethod: row.payment_method || undefined,
    paymentStatus: row.payment_status || 'unpaid',
    cancelReason: row.cancel_reason || undefined,
    guestName: row.guest_name || undefined,
    guestPhone: row.guest_phone || undefined,
    guestEmail: row.guest_email || undefined,
    notifications,
  };
}

function awardOrderPointsOnce(orderId) {
  // Loyalty points removed — this is now a no-op kept for call-site compatibility.
  return 0;
}

function vietQrPayload(order) {
  const bank = encodeURIComponent(process.env.VIETQR_BANK_ID || 'VCB');
  const accountNo = encodeURIComponent(process.env.VIETQR_ACCOUNT_NO || '0123456789');
  const template = encodeURIComponent(process.env.VIETQR_TEMPLATE || 'compact2');
  const accountName = encodeURIComponent(process.env.VIETQR_ACCOUNT_NAME || 'FLASH N PRINT');
  const amount = Math.max(0, Math.round(Number(order.total) || 0));
  const addInfo = encodeURIComponent(order.id);
  return {
    bank,
    accountNo,
    accountName: process.env.VIETQR_ACCOUNT_NAME || 'FLASH N PRINT',
    amount,
    addInfo: order.id,
    qrUrl: `https://img.vietqr.io/image/${bank}-${accountNo}-${template}.png?amount=${amount}&addInfo=${addInfo}&accountName=${accountName}`,
  };
}

app.get('/api/orders/:id/vietqr', requireAuth, (req, res) => {
  const row = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  if (req.user.role !== 'admin' && row.user_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  res.json(vietQrPayload(row));
});

app.post('/api/orders', requireAuth, writeLimiter, (req, res) => {
  const { items, total, deliveryAddress, pickupLocation, paymentMethod, estimatedTime } =
    req.body || {};
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'empty_cart' });
  }
  if (items.length > MAX_ORDER_ITEMS) {
    return res.status(400).json({ error: 'too_many_items' });
  }
  const t = Number(total);
  if (!Number.isFinite(t) || t < 0) return res.status(400).json({ error: 'invalid_total' });

  const id = `ORD-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const itemsJson = JSON.stringify(items);
  const normalizedPaymentMethod = String(paymentMethod || '').trim() || 'cash';
  const paymentStatus = normalizedPaymentMethod === 'card' ? 'unpaid' : 'paid';

  db.prepare(
    `INSERT INTO orders (id, user_id, status, total, delivery_address, pickup_location, payment_method, payment_status, items_json, estimated_time)
     VALUES (?,?, 'pending',?,?,?,?,?,?,?)`,
  ).run(
    id,
    req.user.id,
    Math.round(t),
    deliveryAddress || null,
    pickupLocation || null,
    normalizedPaymentMethod,
    paymentStatus,
    itemsJson,
    estimatedTime || '15-30 mins',
  );

  const row = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(id);
  res.status(201).json(parseOrderRow(row, []));
});

app.post('/api/orders/guest', writeLimiter, (req, res) => {
  const { guestName, guestPhone, guestEmail, items, total, deliveryAddress, pickupLocation, paymentMethod, estimatedTime } =
    req.body || {};
  const email = String(guestEmail || '').trim().toLowerCase();
  if (!email || !isValidEmail(email)) return res.status(400).json({ error: 'guest_email_required' });
  // Name/phone are optional; fall back to the email local-part for display.
  const name = String(guestName || '').trim() || email.split('@')[0];
  const phone = String(guestPhone || '').trim();
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'empty_cart' });
  }
  if (items.length > MAX_ORDER_ITEMS) {
    return res.status(400).json({ error: 'too_many_items' });
  }
  const t = Number(total);
  if (!Number.isFinite(t) || t < 0) return res.status(400).json({ error: 'invalid_total' });

  const id = `ORD-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const itemsJson = JSON.stringify(items);
  const normalizedPaymentMethod = String(paymentMethod || '').trim() || 'cash';
  const paymentStatus = normalizedPaymentMethod === 'card' ? 'unpaid' : 'paid';

  // Upsert a shared guest system user to satisfy the FK constraint
  let guestUser = db.prepare(`SELECT id FROM users WHERE email = 'guest@system.internal'`).get();
  if (!guestUser) {
    db.prepare(`INSERT INTO users (email, password_hash, name, student_id, role) VALUES ('guest@system.internal', 'x', 'Guest', '0', 'user')`).run();
    guestUser = db.prepare(`SELECT id FROM users WHERE email = 'guest@system.internal'`).get();
  }

  db.prepare(
    `INSERT INTO orders (id, user_id, status, total, delivery_address, pickup_location, payment_method, payment_status, items_json, estimated_time, guest_name, guest_phone, guest_email)
     VALUES (?,?, 'pending',?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    id,
    guestUser.id,
    Math.round(t),
    deliveryAddress || null,
    pickupLocation || null,
    normalizedPaymentMethod,
    paymentStatus,
    itemsJson,
    estimatedTime || '15-30 mins',
    name,
    phone,
    email,
  );

  const row = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(id);
  res.status(201).json(parseOrderRow(row, []));
});

app.get('/api/orders/guest/:id', (req, res) => {
  const row = db.prepare(`SELECT * FROM orders WHERE id = ? AND guest_name IS NOT NULL`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const notes = db
    .prepare(
      `SELECT id, message, created_at AS createdAt FROM order_notifications WHERE order_id = ? ORDER BY id ASC`,
    )
    .all(row.id);
  res.json(parseOrderRow(row, notes));
});

app.get('/api/orders', requireAuth, (req, res) => {
  const rows = db
    .prepare(`SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC`)
    .all(req.user.id);
  res.json(rows.map((r) => parseOrderRow(r, [])));
});

app.get('/api/orders/:id', requireAuth, (req, res) => {
  const row = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  if (req.user.role !== 'admin' && row.user_id !== req.user.id) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const notes = db
    .prepare(
      `SELECT id, message, created_at AS createdAt FROM order_notifications WHERE order_id = ? ORDER BY id ASC`,
    )
    .all(row.id);
  res.json(parseOrderRow(row, notes));
});

app.post('/api/orders/:id/cancel', requireAuth, writeLimiter, (req, res) => {
  const row = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  if (row.user_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  if (!['pending', 'processing'].includes(row.status)) {
    return res.status(400).json({ error: 'cannot_cancel' });
  }
  const reason = String(req.body?.reason || '').trim().slice(0, 500);
  db.prepare(
    `UPDATE orders SET status = 'cancelled', cancel_reason = ?, updated_at = datetime('now') WHERE id = ?`,
  ).run(reason || null, req.params.id);
  const updated = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  const notes = db
    .prepare(
      `SELECT id, message, created_at AS createdAt FROM order_notifications WHERE order_id = ? ORDER BY id ASC`,
    )
    .all(updated.id);
  res.json(parseOrderRow(updated, notes));
});

app.post('/api/orders/:id/payment-submitted', requireAuth, writeLimiter, (req, res) => {
  const row = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  if (row.user_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  if (row.payment_method !== 'card') return res.status(400).json({ error: 'not_qr_payment' });
  if (row.status === 'cancelled') return res.status(400).json({ error: 'order_cancelled' });
  db.prepare(`UPDATE orders SET payment_status = 'pending_verification', updated_at = datetime('now') WHERE id = ?`).run(req.params.id);
  const updated = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  res.json(parseOrderRow(updated, []));
});

app.post('/api/orders/guest/:id/payment-submitted', writeLimiter, (req, res) => {
  const row = db.prepare(`SELECT * FROM orders WHERE id = ? AND guest_name IS NOT NULL`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  if (row.payment_method !== 'card') return res.status(400).json({ error: 'not_qr_payment' });
  if (row.status === 'cancelled') return res.status(400).json({ error: 'order_cancelled' });
  db.prepare(`UPDATE orders SET payment_status = 'pending_verification', updated_at = datetime('now') WHERE id = ?`).run(req.params.id);
  const updated = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  res.json(parseOrderRow(updated, []));
});

app.post('/api/orders/:id/received', requireAuth, writeLimiter, (req, res) => {
  const row = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  if (row.user_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  if (row.status !== 'ready') return res.status(400).json({ error: 'not_ready' });
  if (row.payment_status !== 'paid') return res.status(400).json({ error: 'payment_not_paid' });
  db.prepare(`UPDATE orders SET status = 'completed', updated_at = datetime('now') WHERE id = ?`).run(req.params.id);
  awardOrderPointsOnce(req.params.id);
  const updated = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  const notes = db
    .prepare(`SELECT id, message, created_at AS createdAt FROM order_notifications WHERE order_id = ? ORDER BY id ASC`)
    .all(updated.id);
  res.json(parseOrderRow(updated, notes));
});

/** Customer support chat */
app.get('/api/support/messages', requireAuth, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 100, MAX_SUPPORT_POLL);
  const rows = db
    .prepare(
      `SELECT id, order_id AS orderId, from_admin AS fromAdmin, body, created_at AS createdAt
       FROM support_messages WHERE user_id = ? ORDER BY id DESC LIMIT ?`,
    )
    .all(req.user.id, limit);
  res.json(rows.reverse());
});

app.post('/api/support/messages', requireAuth, writeLimiter, (req, res) => {
  let body = String(req.body?.body || '').trim();
  if (!body) return res.status(400).json({ error: 'empty_message' });
  if (body.length > MAX_CHAT_BODY) body = body.slice(0, MAX_CHAT_BODY);
  const orderId = req.body?.orderId ? String(req.body.orderId).slice(0, 80) : null;
  if (orderId) {
    const ord = db.prepare(`SELECT id FROM orders WHERE id = ? AND user_id = ?`).get(orderId, req.user.id);
    if (!ord) return res.status(400).json({ error: 'invalid_order' });
  }
  const info = db
    .prepare(
      `INSERT INTO support_messages (user_id, order_id, from_admin, body) VALUES (?,?,0,?)`,
    )
    .run(req.user.id, orderId, body);
  const msg = db
    .prepare(
      `SELECT id, order_id AS orderId, from_admin AS fromAdmin, body, created_at AS createdAt FROM support_messages WHERE id = ?`,
    )
    .get(info.lastInsertRowid);
  res.status(201).json(msg);
});

/** Admin orders */
app.get('/api/admin/orders', requireAuth, requireAdmin, (req, res) => {
  const rows = db
    .prepare(
      `SELECT o.*, u.email AS user_email, u.name AS user_name FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.created_at DESC`,
    )
    .all();
  res.json(
    rows.map((r) => {
      const { user_email, user_name, ...order } = r;
      const notes = db
        .prepare(
          `SELECT id, message, created_at AS createdAt FROM order_notifications WHERE order_id = ? ORDER BY id DESC`,
        )
        .all(order.id);
      return {
        ...parseOrderRow(order, notes),
        userEmail: user_email,
        userName: user_name,
      };
    }),
  );
});

app.patch('/api/admin/orders/:id', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const { status, estimatedTime, deliveryAddress, pickupLocation, paymentMethod, paymentStatus } = req.body || {};
  const row = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });

  const allowed = ['pending', 'processing', 'ready', 'completed', 'cancelled'];
  const updates = [];
  const vals = [];
  if (status !== undefined) {
    if (!allowed.includes(status)) return res.status(400).json({ error: 'invalid_status' });
    updates.push('status = ?');
    vals.push(status);
    if (status === 'cancelled' && req.body?.cancelReason !== undefined) {
      updates.push('cancel_reason = ?');
      vals.push(String(req.body.cancelReason).slice(0, 500));
    }
  }
  if (estimatedTime !== undefined) {
    updates.push('estimated_time = ?');
    vals.push(String(estimatedTime).slice(0, 120));
  }
  if (deliveryAddress !== undefined) {
    updates.push('delivery_address = ?');
    const v = String(deliveryAddress).trim();
    vals.push(v ? v.slice(0, 500) : null);
  }
  if (pickupLocation !== undefined) {
    updates.push('pickup_location = ?');
    const v = String(pickupLocation).trim();
    vals.push(v ? v.slice(0, 200) : null);
  }
  if (paymentMethod !== undefined) {
    updates.push('payment_method = ?');
    const v = String(paymentMethod).trim();
    vals.push(v ? v.slice(0, 80) : null);
  }
  if (paymentStatus !== undefined) {
    const paymentAllowed = ['unpaid', 'pending_verification', 'paid'];
    if (!paymentAllowed.includes(paymentStatus)) return res.status(400).json({ error: 'invalid_payment_status' });
    updates.push('payment_status = ?');
    vals.push(paymentStatus);
  }
  if (!updates.length) return res.status(400).json({ error: 'nothing_to_update' });
  updates.push(`updated_at = datetime('now')`);
  vals.push(req.params.id);
  
  db.prepare(`UPDATE orders SET ${updates.join(', ')} WHERE id = ?`).run(...vals);

  // Award points if status changed to 'completed'
  if (status === 'completed' && row.status !== 'completed' && row.user_id) {
    awardOrderPointsOnce(req.params.id);
  }
  const updated = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  const notes = db
    .prepare(
      `SELECT id, message, created_at AS createdAt FROM order_notifications WHERE order_id = ? ORDER BY id ASC`,
    )
    .all(updated.id);
  res.json(parseOrderRow(updated, notes));
});

app.post('/api/admin/orders/:id/confirm-payment', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const row = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  db.prepare(`UPDATE orders SET payment_status = 'paid', updated_at = datetime('now') WHERE id = ?`).run(req.params.id);
  const updated = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  res.json(parseOrderRow(updated, []));
});

app.post('/api/admin/orders/:id/reject-payment', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const row = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  db.prepare(`UPDATE orders SET payment_status = 'unpaid', updated_at = datetime('now') WHERE id = ?`).run(req.params.id);
  const updated = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id);
  res.json(parseOrderRow(updated, []));
});

app.delete('/api/admin/orders/:id', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const r = db.prepare(`DELETE FROM orders WHERE id = ?`).run(req.params.id);
  if (r.changes === 0) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

app.post('/api/admin/orders/:id/notifications', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const { message } = req.body || {};
  if (!message || !String(message).trim()) return res.status(400).json({ error: 'empty_message' });
  const row = db.prepare(`SELECT id FROM orders WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const text = String(message).trim().slice(0, 2000);
  const info = db
    .prepare(`INSERT INTO order_notifications (order_id, message) VALUES (?,?)`)
    .run(req.params.id, text);
  const note = db
    .prepare(`SELECT id, message, created_at AS createdAt FROM order_notifications WHERE id = ?`)
    .get(info.lastInsertRowid);
  res.status(201).json(note);
});

app.delete(
  '/api/admin/orders/:orderId/notifications/:noteId',
  requireAuth,
  requireAdmin,
  writeLimiter,
  (req, res) => {
    const { orderId, noteId } = req.params;
    const nid = Number(noteId);
    if (!Number.isFinite(nid) || nid <= 0) return res.status(400).json({ error: 'invalid_id' });
    const row = db
      .prepare(`SELECT id FROM order_notifications WHERE id = ? AND order_id = ?`)
      .get(nid, orderId);
    if (!row) return res.status(404).json({ error: 'not_found' });
    db.prepare(`DELETE FROM order_notifications WHERE id = ?`).run(nid);
    res.json({ ok: true });
  },
);

/** Admin support threads */
app.get('/api/admin/support/threads', requireAuth, requireAdmin, (req, res) => {
  const rows = db
    .prepare(
      `SELECT sm.user_id AS userId, MAX(sm.id) AS lastId
       FROM support_messages sm
       GROUP BY sm.user_id
       ORDER BY lastId DESC
       LIMIT 80`,
    )
    .all();
  const out = [];
  for (const r of rows) {
    const u = db.prepare(`SELECT id, email, name FROM users WHERE id = ?`).get(r.userId);
    const last = db
      .prepare(
        `SELECT id, body, from_admin AS fromAdmin, created_at AS createdAt FROM support_messages WHERE id = ?`,
      )
      .get(r.lastId);
    out.push({
      userId: r.userId,
      userEmail: u?.email,
      userName: u?.name,
      lastMessage: last,
    });
  }
  res.json(out);
});

app.get('/api/admin/support/messages', requireAuth, requireAdmin, (req, res) => {
  const userId = Number(req.query.userId);
  if (!userId) return res.status(400).json({ error: 'missing_userId' });
  const limit = Math.min(Number(req.query.limit) || 200, MAX_SUPPORT_POLL);
  const rows = db
    .prepare(
      `SELECT id, order_id AS orderId, from_admin AS fromAdmin, body, created_at AS createdAt
       FROM support_messages WHERE user_id = ? ORDER BY id DESC LIMIT ?`,
    )
    .all(userId, limit);
  res.json(rows.reverse());
});

app.post('/api/admin/support/messages', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const userId = Number(req.body?.userId);
  let body = String(req.body?.body || '').trim();
  if (!userId || !body) return res.status(400).json({ error: 'missing_fields' });
  if (body.length > MAX_CHAT_BODY) body = body.slice(0, MAX_CHAT_BODY);
  const u = db.prepare(`SELECT id FROM users WHERE id = ?`).get(userId);
  if (!u) return res.status(404).json({ error: 'user_not_found' });
  const orderId = req.body?.orderId ? String(req.body.orderId).slice(0, 80) : null;
  if (orderId) {
    const ord = db.prepare(`SELECT id FROM orders WHERE id = ? AND user_id = ?`).get(orderId, userId);
    if (!ord) return res.status(400).json({ error: 'invalid_order' });
  }
  const info = db
    .prepare(`INSERT INTO support_messages (user_id, order_id, from_admin, body) VALUES (?,?,1,?)`)
    .run(userId, orderId, body);
  const msg = db
    .prepare(
      `SELECT id, order_id AS orderId, from_admin AS fromAdmin, body, created_at AS createdAt FROM support_messages WHERE id = ?`,
    )
    .get(info.lastInsertRowid);
  res.status(201).json(msg);
});

/** Admin user management */
function serializeAdminUser(r) {
  return {
    id: r.id,
    schoolEmail: r.email,
    phone: r.phone || null,
    name: r.name,
    role: r.role,
    createdAt: r.created_at,
    lastLoginAt: r.last_login_at,
    orderCount: r.order_count ?? 0,
    totalSpent: r.total_spent ?? 0,
  };
}

const ADMIN_USER_SELECT = `SELECT u.id, u.email, u.phone, u.name, u.role, u.created_at, u.last_login_at,
        (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id) AS order_count,
        (SELECT COALESCE(SUM(o.total), 0) FROM orders o WHERE o.user_id = u.id AND o.status != 'cancelled') AS total_spent
       FROM users u`;

app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`${ADMIN_USER_SELECT} ORDER BY u.id`).all();
  res.json(rows.map(serializeAdminUser));
});

app.patch('/api/admin/users/:id', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const targetId = Number(req.params.id);
  const { name, role } = req.body || {};
  const target = db.prepare(`SELECT id, role FROM users WHERE id = ?`).get(targetId);
  if (!target) return res.status(404).json({ error: 'not_found' });

  const updates = [];
  const vals = [];
  if (name !== undefined) {
    if (!String(name).trim()) return res.status(400).json({ error: 'invalid_name' });
    updates.push('name = ?');
    vals.push(String(name).trim());
  }
  if (role !== undefined) {
    if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'invalid_role' });
    // Prevent demoting the last remaining admin (including self).
    if (target.role === 'admin' && role !== 'admin') {
      const ac = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role = 'admin'`).get().c;
      if (ac <= 1) return res.status(400).json({ error: 'last_admin' });
    }
    updates.push('role = ?');
    vals.push(role);
  }

  if (!updates.length) return res.status(400).json({ error: 'nothing_to_update' });
  vals.push(targetId);
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...vals);
  const row = db.prepare(`${ADMIN_USER_SELECT} WHERE u.id = ?`).get(targetId);
  res.json(serializeAdminUser(row));
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const targetId = Number(req.params.id);
  if (targetId === req.user.id) return res.status(400).json({ error: 'cannot_delete_self' });
  const target = db.prepare(`SELECT role FROM users WHERE id = ?`).get(targetId);
  if (!target) return res.status(404).json({ error: 'not_found' });
  if (target.role === 'admin') {
    const ac = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role = 'admin'`).get().c;
    if (ac <= 1) return res.status(400).json({ error: 'last_admin' });
  }
  db.prepare(`DELETE FROM users WHERE id = ?`).run(targetId);
  res.json({ ok: true });
});

/** Admin: Product CRUD */
const PRODUCT_FIELD_MAP = {
  name: 'name', nameEn: 'name_en', description: 'description', descriptionEn: 'description_en',
  price: 'price', category: 'category', image: 'image', unit: 'unit',
  minQuantity: 'min_quantity', pickupOnly: 'pickup_only', variants: 'variants_json',
  isPromotion: 'is_promotion', stockLimit: 'stock_limit',
  modelViewerUrl: 'model_viewer_url', subName: 'sub_name', rating: 'rating',
  reviewCount: 'review_count', polyCount: 'poly_count', vertexCount: 'vertex_count',
  textures: 'textures', rigged: 'rigged', animated: 'animated', formats: 'formats_json',
  accentColor: 'accent_color', tags: 'tags_json',
};
const PRODUCT_BOOL_KEYS = new Set(['pickupOnly', 'isPromotion', 'rigged', 'animated']);
const PRODUCT_JSON_KEYS = new Set(['variants', 'formats', 'tags']);

function coerceProductValue(key, val) {
  if (PRODUCT_BOOL_KEYS.has(key)) return val ? 1 : 0;
  if (PRODUCT_JSON_KEYS.has(key)) return val ? JSON.stringify(val) : null;
  return val;
}

function slugify(str) {
  return String(str || '')
    .toLowerCase()
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60);
}

app.post('/api/admin/products', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const p = req.body || {};
  if (!p.name || String(p.name).trim() === '') return res.status(400).json({ error: 'invalid_name' });
  if (p.price === undefined || p.price === null || Number.isNaN(Number(p.price))) return res.status(400).json({ error: 'invalid_price' });
  if (!p.category || String(p.category).trim() === '') return res.status(400).json({ error: 'invalid_category' });

  let id = p.id && String(p.id).trim() ? slugify(p.id) : slugify(p.name);
  if (!id) id = `prod_${Date.now()}`;
  if (db.prepare(`SELECT id FROM products WHERE id = ?`).get(id)) {
    id = `${id}_${Date.now().toString(36)}`;
  }

  const cols = ['id'];
  const placeholders = ['?'];
  const vals = [id];
  for (const [key, col] of Object.entries(PRODUCT_FIELD_MAP)) {
    if (p[key] !== undefined) {
      cols.push(col);
      placeholders.push('?');
      vals.push(coerceProductValue(key, p[key]));
    }
  }
  try {
    db.prepare(`INSERT INTO products (${cols.join(', ')}) VALUES (${placeholders.join(', ')})`).run(...vals);
    const row = db.prepare(`SELECT * FROM products WHERE id = ?`).get(id);
    res.status(201).json(serializeProduct(row));
  } catch (e) {
    res.status(400).json({ error: 'failed_to_create_product' });
  }
});

app.patch('/api/admin/products/:id', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const p = req.body || {};
  const existing = db.prepare(`SELECT id FROM products WHERE id = ?`).get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'not_found' });

  const updates = [];
  const vals = [];
  for (const [key, col] of Object.entries(PRODUCT_FIELD_MAP)) {
    if (p[key] !== undefined) {
      updates.push(`${col} = ?`);
      vals.push(coerceProductValue(key, p[key]));
    }
  }
  if (!updates.length) return res.status(400).json({ error: 'nothing_to_update' });
  vals.push(req.params.id);
  db.prepare(`UPDATE products SET ${updates.join(', ')} WHERE id = ?`).run(...vals);
  const row = db.prepare(`SELECT * FROM products WHERE id = ?`).get(req.params.id);
  res.json(serializeProduct(row));
});

app.delete('/api/admin/products/:id', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const existing = db.prepare(`SELECT id FROM products WHERE id = ?`).get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'not_found' });
  db.prepare(`DELETE FROM products WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

/** Admin: Coupon CRUD */
app.post('/api/admin/coupons', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const { code, discountPercent, maxUses, expiresAt, minSpent } = req.body || {};
  const cleanCode = String(code || '').trim();
  if (!cleanCode) return res.status(400).json({ error: 'missing_code' });
  const pct = Number(discountPercent);
  if (!Number.isFinite(pct) || pct < 0 || pct > 100) return res.status(400).json({ error: 'invalid_discount' });
  if (db.prepare(`SELECT code FROM coupons WHERE code = ?`).get(cleanCode)) {
    return res.status(409).json({ error: 'coupon_exists' });
  }
  try {
    db.prepare(`
      INSERT INTO coupons (code, discount_percent, max_uses, expires_at, min_spent)
      VALUES (?,?,?,?,?)
    `).run(cleanCode, Math.floor(pct), maxUses ?? -1, expiresAt || null, minSpent ?? 0);
    const row = db.prepare(`SELECT * FROM coupons WHERE code = ?`).get(cleanCode);
    res.status(201).json(row);
  } catch (e) {
    res.status(400).json({ error: 'failed_to_create_coupon' });
  }
});

app.patch('/api/admin/coupons/:code', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const coupon = db.prepare(`SELECT * FROM coupons WHERE code = ?`).get(req.params.code);
  if (!coupon) return res.status(404).json({ error: 'not_found' });
  const { discountPercent, maxUses, expiresAt, minSpent } = req.body || {};
  const updates = [];
  const vals = [];
  if (discountPercent !== undefined) {
    const pct = Number(discountPercent);
    if (!Number.isFinite(pct) || pct < 0 || pct > 100) return res.status(400).json({ error: 'invalid_discount' });
    updates.push('discount_percent = ?');
    vals.push(Math.floor(pct));
  }
  if (maxUses !== undefined) {
    const n = Number(maxUses);
    if (!Number.isFinite(n)) return res.status(400).json({ error: 'invalid_max_uses' });
    updates.push('max_uses = ?');
    vals.push(Math.floor(n));
  }
  if (expiresAt !== undefined) {
    updates.push('expires_at = ?');
    vals.push(expiresAt || null);
  }
  if (minSpent !== undefined) {
    const n = Number(minSpent);
    if (!Number.isFinite(n) || n < 0) return res.status(400).json({ error: 'invalid_min_spent' });
    updates.push('min_spent = ?');
    vals.push(Math.floor(n));
  }
  if (!updates.length) return res.status(400).json({ error: 'nothing_to_update' });
  vals.push(req.params.code);
  db.prepare(`UPDATE coupons SET ${updates.join(', ')} WHERE code = ?`).run(...vals);
  const row = db.prepare(`SELECT * FROM coupons WHERE code = ?`).get(req.params.code);
  res.json(row);
});

app.delete('/api/admin/coupons/:code', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  db.prepare(`DELETE FROM coupons WHERE code = ?`).run(req.params.code);
  res.json({ ok: true });
});

app.get('/api/admin/coupons', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT * FROM coupons ORDER BY created_at DESC`).all();
  res.json(rows);
});

/** Admin: Dashboard stats */
app.get('/api/admin/stats', requireAuth, requireAdmin, (req, res) => {
  // Revenue counts paid, non-cancelled orders.
  const REV_WHERE = `payment_status = 'paid' AND status != 'cancelled'`;
  const revenueTotal = db.prepare(`SELECT COALESCE(SUM(total),0) AS v FROM orders WHERE ${REV_WHERE}`).get().v;
  const revenue30 = db.prepare(
    `SELECT COALESCE(SUM(total),0) AS v FROM orders WHERE ${REV_WHERE} AND date(created_at) >= date('now','-29 days')`,
  ).get().v;
  const revenueToday = db.prepare(
    `SELECT COALESCE(SUM(total),0) AS v FROM orders WHERE ${REV_WHERE} AND date(created_at) = date('now')`,
  ).get().v;

  const totalOrders = db.prepare(`SELECT COUNT(*) AS c FROM orders`).get().c;
  const orders30 = db.prepare(
    `SELECT COUNT(*) AS c FROM orders WHERE date(created_at) >= date('now','-29 days')`,
  ).get().c;
  const statusRows = db.prepare(`SELECT status, COUNT(*) AS c FROM orders GROUP BY status`).all();
  const byStatus = {};
  for (const s of statusRows) byStatus[s.status] = s.c;
  const pendingPayments = db.prepare(
    `SELECT COUNT(*) AS c FROM orders WHERE payment_status = 'pending_verification'`,
  ).get().c;
  const avgRow = db.prepare(
    `SELECT COALESCE(AVG(total),0) AS v FROM orders WHERE status != 'cancelled'`,
  ).get();

  const userCount = db.prepare(`SELECT COUNT(*) AS c FROM users`).get().c;
  const adminCount = db.prepare(`SELECT COUNT(*) AS c FROM users WHERE role = 'admin'`).get().c;
  const newUsers30 = db.prepare(
    `SELECT COUNT(*) AS c FROM users WHERE date(created_at) >= date('now','-29 days')`,
  ).get().c;
  const productCount = db.prepare(`SELECT COUNT(*) AS c FROM products`).get().c;
  const couponCount = db.prepare(`SELECT COUNT(*) AS c FROM coupons`).get().c;

  // Revenue for the last 14 days (paid, non-cancelled), grouped by date.
  const revenueSeries = db.prepare(
    `SELECT date(created_at) AS date, COALESCE(SUM(total),0) AS revenue, COUNT(*) AS orders
     FROM orders
     WHERE ${REV_WHERE} AND date(created_at) >= date('now','-13 days')
     GROUP BY date(created_at) ORDER BY date ASC`,
  ).all();

  // Top products by quantity sold, derived from order items JSON.
  const allOrders = db.prepare(`SELECT items_json FROM orders WHERE status != 'cancelled'`).all();
  const productTally = new Map();
  for (const o of allOrders) {
    let items = [];
    try { items = JSON.parse(o.items_json || '[]'); } catch { items = []; }
    for (const it of items) {
      if (!it || !it.name) continue;
      const key = it.name;
      const prev = productTally.get(key) || { name: key, quantity: 0, revenue: 0 };
      const qty = Number(it.quantity) || 0;
      const price = Number(it.price) || 0;
      prev.quantity += qty;
      prev.revenue += qty * price;
      productTally.set(key, prev);
    }
  }
  const topProducts = [...productTally.values()]
    .sort((a, b) => b.quantity - a.quantity)
    .slice(0, 5);

  const recentOrders = db.prepare(
    `SELECT o.id, o.total, o.status, o.payment_status AS paymentStatus, o.created_at AS createdAt,
            o.guest_name AS guestName, u.name AS userName
     FROM orders o LEFT JOIN users u ON u.id = o.user_id
     ORDER BY o.created_at DESC LIMIT 8`,
  ).all();

  res.json({
    revenue: { total: revenueTotal, last30Days: revenue30, today: revenueToday },
    orders: {
      total: totalOrders,
      byStatus,
      pendingPayments,
      last30Days: orders30,
      averageValue: Math.round(avgRow.v),
    },
    users: { total: userCount, admins: adminCount, newLast30Days: newUsers30 },
    products: { total: productCount },
    coupons: { total: couponCount },
    recentOrders,
    topProducts,
    revenueSeries,
  });
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Serve the built frontend whenever `dist` exists. This makes `npm run build`
// followed by `npm start` work even when NODE_ENV is not explicitly set.
const distPath = path.join(rootDir, 'dist');
if (fs.existsSync(path.join(distPath, 'index.html'))) {
  app.use(express.static(distPath));
  app.use((_req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
  });
} else {
  app.get('/', (_req, res) => {
    res
      .status(200)
      .type('text')
      .send('FlashNPrint API is running. For the website, run `npm run dev` and open http://localhost:5000, or run `npm run build` then `npm start`.');
  });
}

// In production, bind the port the host injects (Render/Heroku/etc. set PORT).
// Fall back to 5000 locally. Always listen on 0.0.0.0 so the platform can route to it.
const listenPort = Number(process.env.PORT) || (process.env.NODE_ENV === 'production' ? 5000 : PORT);
app.listen(listenPort, '0.0.0.0', () => {
  console.log('[fnp-api] listening on 0.0.0.0:' + listenPort + '  DB: ' + DB_PATH);
});