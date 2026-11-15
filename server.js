import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { sql, initDb } from './src/db.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'fkc_phantom_x_key_center_super_secret_2026';

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Anti-Frame Clickjacking & Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

let _dbInitPromise = null;
export async function ensureDb() {
  if (!_dbInitPromise) {
    _dbInitPromise = initDb().catch(err => {
      console.error('[DB Init Error]', err);
      _dbInitPromise = null;
      throw err;
    });
  }
  return _dbInitPromise;
}

// Middleware to ensure DB schema is ready before API or Loader requests
app.use(async (req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/c/')) {
    try {
      await ensureDb();
    } catch (e) {
      return res.status(500).json({ error: 'Database connection failed: ' + e.message });
    }
  }
  next();
});

// ============================================================
// ZERO-SERVER-LOAD IN-MEMORY CACHE ENGINE (SUB-2MS LATENCY)
// ============================================================
const _loaderCache = new Map(); // slug -> loader object
const _keyCache = new Map();    // `${slug}:${user_key}` -> validation result
const _rateLimitMap = new Map(); // ip -> { count, firstTs }

function invalidateCache(slug = null, key = null) {
  if (slug && key) {
    _keyCache.delete(`${slug}:${key}`);
  } else if (slug) {
    _loaderCache.delete(slug);
    for (const k of _keyCache.keys()) {
      if (k.startsWith(`${slug}:`)) _keyCache.delete(k);
    }
  } else {
    _loaderCache.clear();
    _keyCache.clear();
  }
}

// Fast JWT Helper
function createToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 3600 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(`${parts[0]}.${parts[1]}`).digest('base64url');
  if (expectedSig !== parts[2]) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// Authentication Middleware with Impersonation & Fresh DB State
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing token' });
  }
  const token = authHeader.split(' ')[1];
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
  }

  try {
    // Handle SuperAdmin Impersonation Mode
    const impersonateUserId = req.headers['x-impersonate-user-id'];
    if (payload.role === 'superadmin' && impersonateUserId) {
      const impUser = (await sql`SELECT * FROM fkc.users WHERE id = ${parseInt(impersonateUserId)}`)[0];
      if (impUser) {
        req.user = impUser;
        req.isImpersonating = true;
        req.realSuperAdmin = payload;
        return next();
      }
    }

    const freshUser = (await sql`SELECT * FROM fkc.users WHERE id = ${payload.id}`)[0];
    if (!freshUser || freshUser.status === 'blocked') {
      return res.status(403).json({ error: 'User is blocked or deleted' });
    }

    req.user = freshUser;
    next();
  } catch (err) {
    return res.status(500).json({ error: 'Auth Verification Error' });
  }
}

// ============================================================
// 1. PUBLIC CONNECT ROUTER (/c/:slug and /c/:slug/connect)
// ============================================================
async function handleConnect(req, res) {
  const { slug } = req.params;
  const key = req.body?.key || req.query?.key || req.body?.user_key || req.query?.user_key;
  const hwid = req.body?.hwid || req.query?.hwid || req.body?.serial || req.query?.serial;
  const model = req.body?.model || req.query?.model;
  const android_version = req.body?.android_version || req.query?.android_version;

  if (!key || !slug) {
    return res.status(400).json({ status: false, message: 'Missing Key or Loader Slug' });
  }

  const cleanKey = String(key).trim();
  const cleanHwid = String(hwid || '').trim();
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

  // 1. Sliding Window Anti-Brute Force (5 bad attempts = 15m block)
  const ipKey = `${clientIp}`;
  const now = Date.now();
  const rateData = _rateLimitMap.get(ipKey) || { count: 0, firstTs: now, blockedUntil: 0 };
  if (rateData.blockedUntil > now) {
    return res.status(429).json({ status: false, message: 'Too many attempts. Blocked for 15 minutes.' });
  }

  try {
    // 2. Fetch Loader by Slug (In-Memory Cache)
    let loader = _loaderCache.get(slug);
    if (!loader) {
      const dbLoader = (await sql`SELECT * FROM fkc.loaders WHERE slug = ${slug}`)[0];
      if (!dbLoader) {
        return res.status(404).json({ status: false, message: 'Invalid Loader Endpoint Slug!' });
      }
      loader = dbLoader;
      _loaderCache.set(slug, loader);
    }

    // Check Maintenance Switch
    if (loader.maintenance) {
      return res.json({
        status: false,
        maintenance: true,
        message: loader.maintenance_msg || 'Loader currently in maintenance.'
      });
    }

    // 3. Fast In-Memory Key Lookup
    const cacheLookupKey = `${slug}:${cleanKey}:${cleanHwid}`;
    const cachedResult = _keyCache.get(cacheLookupKey);
    if (cachedResult && cachedResult.exp > now) {
      return res.json(cachedResult.data);
    }

    // 4. Database Validation
    const keyRecord = (await sql`
      SELECT k.*, u.username as creator_name
      FROM fkc.license_keys k
      JOIN fkc.users u ON k.creator_id = u.id
      WHERE k.user_key = ${cleanKey} AND k.loader_id = ${loader.id}
    `)[0];

    if (!keyRecord) {
      rateData.count++;
      if (rateData.count >= 5) {
        rateData.blockedUntil = now + 15 * 60 * 1000;
      }
      _rateLimitMap.set(ipKey, rateData);
      return res.status(403).json({ status: false, message: 'Invalid Key for this specific Loader!' });
    }

    if (keyRecord.status === 'banned') {
      return res.status(403).json({ status: false, message: 'License key is BANNED by Admin!' });
    }

    // Check Expiry & First Login Activation
    let firstUsed = keyRecord.first_used_at;
    let expiresAt = keyRecord.expires_at;

    if (!firstUsed) {
      firstUsed = new Date();
      expiresAt = new Date(firstUsed.getTime() + keyRecord.duration_days * 24 * 3600 * 1000);
      await sql`
        UPDATE fkc.license_keys 
        SET first_used_at = ${firstUsed}, expires_at = ${expiresAt} 
        WHERE id = ${keyRecord.id}
      `;
    } else if (new Date(expiresAt).getTime() < now) {
      await sql`UPDATE fkc.license_keys SET status = 'expired' WHERE id = ${keyRecord.id}`;
      return res.status(403).json({ status: false, message: 'License key has EXPIRED!' });
    }

    // 5. HWID / Multi-Device Validation
    if (cleanHwid) {
      const boundDevices = await sql`SELECT * FROM fkc.bound_devices WHERE key_id = ${keyRecord.id}`;
      const isAlreadyBound = boundDevices.some(d => d.device_id === cleanHwid);

      if (!isAlreadyBound) {
        if (boundDevices.length >= keyRecord.max_devices) {
          return res.status(403).json({
            status: false,
            message: `Max device limit reached (${boundDevices.length}/${keyRecord.max_devices}). Contact Admin to reset HWID.`
          });
        }

        await sql`
          INSERT INTO fkc.bound_devices (key_id, device_id, model, android_version, ip_address)
          VALUES (${keyRecord.id}, ${cleanHwid}, ${model || 'Unknown'}, ${android_version || 'Unknown'}, ${clientIp})
          ON CONFLICT (key_id, device_id) DO UPDATE SET last_seen = CURRENT_TIMESTAMP
        `;
      } else {
        await sql`
          UPDATE fkc.bound_devices 
          SET last_seen = CURRENT_TIMESTAMP, ip_address = ${clientIp}
          WHERE key_id = ${keyRecord.id} AND device_id = ${cleanHwid}
        `;
      }
    }

    const expIso = new Date(expiresAt).toISOString();
    const responsePayload = {
      status: true,
      data: {
        token: `FKC_${cleanKey}_${now}`,
        exp: expIso,
        EXP: expIso,
        expiry: expIso,
        loader_name: loader.loader_name,
        package_name: req.body?.package_name || req.query?.package_name || loader.package_name || '*',
        version: loader.app_version,
        max_devices: keyRecord.max_devices,
        duration_days: keyRecord.duration_days,
        timestamp: now
      }
    };

    _keyCache.set(cacheLookupKey, { data: responsePayload, exp: now + 60000 });
    return res.json(responsePayload);
  } catch (err) {
    console.error('[/c/:slug Error]', err);
    return res.status(500).json({ status: false, message: 'Internal Server Error' });
  }
}

// Route Aliases: /c/:slug and /c/:slug/connect
app.post('/c/:slug', handleConnect);
app.post('/c/:slug/connect', handleConnect);
app.get('/c/:slug', handleConnect);
app.get('/c/:slug/connect', handleConnect);

// ============================================================
// 2. AUTHENTICATION & REFERRAL SIGNUP APIS
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const user = (await sql`SELECT * FROM fkc.users WHERE username = ${username.trim()}`)[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    if (user.status === 'blocked') {
      return res.status(403).json({ error: 'Your account has been BLOCKED. Contact SuperAdmin.' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    let ownerSettings = null;
    const effectiveOwnerId = user.role === 'owner' ? user.id : user.owner_id;
    if (effectiveOwnerId) {
      ownerSettings = (await sql`SELECT * FROM fkc.owner_settings WHERE owner_id = ${effectiveOwnerId}`)[0];
    }

    const token = createToken({
      id: user.id,
      username: user.username,
      role: user.role,
      owner_id: user.owner_id,
      admin_id: user.admin_id
    });

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        credits: user.credits,
        owner_id: user.owner_id,
        admin_id: user.admin_id,
        assigned_loaders: user.assigned_loaders,
        owner_settings: ownerSettings
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Redeem Referral Card to Create Account
app.post('/api/auth/register-referral', async (req, res) => {
  const { code, username, password } = req.body;
  if (!code || !username || !password) {
    return res.status(400).json({ error: 'Referral code, username, and password required' });
  }

  try {
    const ref = (await sql`SELECT * FROM fkc.referrals WHERE code = ${code.trim()}`)[0];
    if (!ref) return res.status(404).json({ error: 'Invalid Referral Code' });
    if (ref.status !== 'pending') return res.status(400).json({ error: 'This Referral Code has already been used!' });

    const existingUser = (await sql`SELECT id FROM fkc.users WHERE username = ${username.trim()}`)[0];
    if (existingUser) return res.status(400).json({ error: 'Username already taken, choose another' });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const newUser = (await sql`
      INSERT INTO fkc.users (username, password_hash, role, credits, owner_id, admin_id, assigned_loaders)
      VALUES (${username.trim()}, ${hash}, ${ref.target_role}, ${ref.credits_allocated}, ${ref.owner_id}, ${ref.admin_id}, ${ref.assigned_loaders || '[]'})
      RETURNING id, username, role, credits, owner_id, admin_id, assigned_loaders
    `)[0];

    await sql`UPDATE fkc.referrals SET status = 'used', used_by_id = ${newUser.id} WHERE id = ${ref.id}`;

    if (ref.target_role === 'owner') {
      await sql`
        INSERT INTO fkc.owner_settings (owner_id, brand_name, max_loaders)
        VALUES (${newUser.id}, ${`${username}'s Brand`}, ${ref.max_loaders_allowed || 5})
      `;
      const defaultSlug = `${username.toLowerCase().replace(/[^a-z0-9]/g, '')}_loader`.slice(0, 30);
      await sql`
        INSERT INTO fkc.loaders (owner_id, loader_name, slug, package_name)
        VALUES (${newUser.id}, 'Default Loader', ${defaultSlug}, 'com.pubg.imobile')
      `;
    }

    await sql`
      INSERT INTO fkc.credit_ledger (user_id, actor_id, action_type, amount, balance_after, note)
      VALUES (${newUser.id}, ${ref.creator_id}, 'REFERRAL_SIGNUP', ${ref.credits_allocated}, ${ref.credits_allocated}, ${`Account created via Referral Code ${ref.code}`})
    `;

    const token = createToken({
      id: newUser.id,
      username: newUser.username,
      role: newUser.role,
      owner_id: newUser.owner_id,
      admin_id: newUser.admin_id
    });

    res.json({ token, user: newUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Profile & Fresh Status
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const user = req.user;
    let ownerSettings = null;
    const effectiveOwnerId = user.role === 'owner' ? user.id : user.owner_id;
    if (effectiveOwnerId) {
      ownerSettings = (await sql`SELECT * FROM fkc.owner_settings WHERE owner_id = ${effectiveOwnerId}`)[0];
    }

    res.json({
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        credits: user.credits,
        owner_id: user.owner_id,
        admin_id: user.admin_id,
        assigned_loaders: user.assigned_loaders,
        status: user.status,
        is_impersonating: Boolean(req.isImpersonating),
        real_superadmin: req.realSuperAdmin || null,
        owner_settings: ownerSettings
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// 3. OWNER LOADER MANAGEMENT APIS (WITH ROLE FILTERING)
// ============================================================
app.get('/api/loaders', authenticate, async (req, res) => {
  try {
    const effectiveOwnerId = req.user.role === 'superadmin' 
      ? (req.query.owner_id || null) 
      : (req.user.role === 'owner' ? req.user.id : req.user.owner_id);

    let loaders;
    if (req.user.role === 'superadmin' && !effectiveOwnerId) {
      loaders = await sql`
        SELECT l.*, u.username as owner_username 
        FROM fkc.loaders l 
        JOIN fkc.users u ON l.owner_id = u.id 
        ORDER BY l.id DESC
      `;
    } else {
      loaders = await sql`
        SELECT * FROM fkc.loaders 
        WHERE owner_id = ${effectiveOwnerId} 
        ORDER BY id DESC
      `;
    }

    // Role-based Loader Filtering: If Admin or Reseller has assigned_loaders, filter them!
    if (req.user.role === 'admin' || req.user.role === 'reseller') {
      let assigned = [];
      try { assigned = JSON.parse(req.user.assigned_loaders || '[]'); } catch (e) {}
      if (Array.isArray(assigned) && assigned.length > 0 && !assigned.includes('all')) {
        const allowedIds = assigned.map(Number);
        loaders = loaders.filter(l => allowedIds.includes(l.id));
      }
    }

    res.json({ loaders });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/loaders', authenticate, async (req, res) => {
  if (req.user.role !== 'owner' && req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'Only Owners or SuperAdmin can create Loaders' });
  }

  const { loader_name, slug, package_name, app_version } = req.body;
  if (!loader_name || !slug) {
    return res.status(400).json({ error: 'Loader name and unique slug required' });
  }

  const cleanSlug = String(slug).toLowerCase().trim().replace(/[^a-z0-9_-]/g, '');
  const ownerId = req.user.role === 'owner' ? req.user.id : (req.body.owner_id || req.user.id);

  try {
    const settings = (await sql`SELECT max_loaders FROM fkc.owner_settings WHERE owner_id = ${ownerId}`)[0];
    const maxAllowed = settings?.max_loaders || 5;
    const currentCount = (await sql`SELECT count(*) FROM fkc.loaders WHERE owner_id = ${ownerId}`)[0].count;

    if (parseInt(currentCount) >= maxAllowed) {
      return res.status(400).json({ error: `Loader quota limit reached (${currentCount}/${maxAllowed}). Contact SuperAdmin to expand slots.` });
    }

    const existing = (await sql`SELECT id FROM fkc.loaders WHERE slug = ${cleanSlug}`)[0];
    if (existing) {
      return res.status(400).json({ error: `Slug "${cleanSlug}" is already in use. Choose another slug!` });
    }

    const loader = (await sql`
      INSERT INTO fkc.loaders (owner_id, loader_name, slug, package_name, app_version)
      VALUES (${ownerId}, ${loader_name.trim()}, ${cleanSlug}, ${package_name?.trim() || 'com.pubg.imobile'}, ${app_version?.trim() || '1.0.0'})
      RETURNING *
    `)[0];

    invalidateCache(cleanSlug);
    res.json({ success: true, loader });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/loaders/:id/maintenance', authenticate, async (req, res) => {
  const { id } = req.params;
  const { maintenance, maintenance_msg } = req.body;

  try {
    const loader = (await sql`SELECT * FROM fkc.loaders WHERE id = ${parseInt(id)}`)[0];
    if (!loader) return res.status(404).json({ error: 'Loader not found' });

    if (req.user.role !== 'superadmin' && req.user.id !== loader.owner_id) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    await sql`
      UPDATE fkc.loaders 
      SET maintenance = ${Boolean(maintenance)}, maintenance_msg = ${maintenance_msg || 'Service undergoing maintenance.'}
      WHERE id = ${loader.id}
    `;

    invalidateCache(loader.slug);
    res.json({ success: true, message: 'Maintenance status updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// 4. OWNER PRICING SETTINGS APIS
// ============================================================
app.get('/api/pricing', authenticate, async (req, res) => {
  try {
    const ownerId = req.user.role === 'owner' ? req.user.id : (req.user.owner_id || req.query.owner_id);
    if (!ownerId) {
      return res.status(400).json({ error: 'Owner context required' });
    }

    const settings = (await sql`SELECT * FROM fkc.owner_settings WHERE owner_id = ${ownerId}`)[0];
    res.json({ settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/pricing', authenticate, async (req, res) => {
  if (req.user.role !== 'owner' && req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'Only Owner or SuperAdmin can update credit pricing' });
  }

  const ownerId = req.user.role === 'owner' ? req.user.id : (req.body.owner_id || req.user.id);
  const { brand_name, price_1d, price_7d, price_15d, price_30d, price_60d, price_custom_per_day, max_loaders } = req.body;

  try {
    await sql`
      INSERT INTO fkc.owner_settings (owner_id, brand_name, price_1d, price_7d, price_15d, price_30d, price_60d, price_custom_per_day, max_loaders, updated_at)
      VALUES (${ownerId}, ${brand_name || 'Featurestic Brand'}, ${price_1d || 1}, ${price_7d || 5}, ${price_15d || 10}, ${price_30d || 18}, ${price_60d || 32}, ${price_custom_per_day || 1}, ${max_loaders || 5}, CURRENT_TIMESTAMP)
      ON CONFLICT (owner_id) DO UPDATE SET
        brand_name = EXCLUDED.brand_name,
        price_1d = EXCLUDED.price_1d,
        price_7d = EXCLUDED.price_7d,
        price_15d = EXCLUDED.price_15d,
        price_30d = EXCLUDED.price_30d,
        price_60d = EXCLUDED.price_60d,
        price_custom_per_day = EXCLUDED.price_custom_per_day,
        max_loaders = COALESCE(EXCLUDED.max_loaders, fkc.owner_settings.max_loaders),
        updated_at = CURRENT_TIMESTAMP
    `;

    res.json({ success: true, message: 'Credit pricing updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// 5. REFERRAL INVITE CARD ENGINE (WITH ASSIGNED LOADERS)
// ============================================================
app.get('/api/referrals', authenticate, async (req, res) => {
  try {
    let refs;
    if (req.user.role === 'superadmin') {
      refs = await sql`
        SELECT r.*, u.username as creator_name, used.username as used_by_name
        FROM fkc.referrals r
        JOIN fkc.users u ON r.creator_id = u.id
        LEFT JOIN fkc.users used ON r.used_by_id = used.id
        ORDER BY r.id DESC
      `;
    } else {
      refs = await sql`
        SELECT r.*, u.username as creator_name, used.username as used_by_name
        FROM fkc.referrals r
        JOIN fkc.users u ON r.creator_id = u.id
        LEFT JOIN fkc.users used ON r.used_by_id = used.id
        WHERE r.creator_id = ${req.user.id}
        ORDER BY r.id DESC
      `;
    }
    res.json({ referrals: refs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/referrals', authenticate, async (req, res) => {
  const { target_role, credits_allocated, max_loaders_allowed, assigned_loaders } = req.body;
  const credits = parseInt(credits_allocated || 0);

  if (req.user.role === 'superadmin' && target_role !== 'owner' && target_role !== 'admin' && target_role !== 'reseller') {
    return res.status(400).json({ error: 'SuperAdmin can create any role referral' });
  }
  if (req.user.role === 'owner' && target_role !== 'admin' && target_role !== 'reseller') {
    return res.status(403).json({ error: 'Owners can only create Admin or Reseller referrals' });
  }
  if (req.user.role === 'admin' && target_role !== 'reseller') {
    return res.status(403).json({ error: 'Admins can only create Reseller referrals' });
  }

  // Deduct Credits if creator is Admin
  if (req.user.role === 'admin') {
    const currentAdmin = (await sql`SELECT credits FROM fkc.users WHERE id = ${req.user.id}`)[0];
    if (currentAdmin.credits < credits) {
      return res.status(400).json({ error: `Insufficient Credits! You have ${currentAdmin.credits}, but tried to allocate ${credits}.` });
    }
    await sql`UPDATE fkc.users SET credits = credits - ${credits}::int WHERE id = ${req.user.id}`;
  }

  try {
    const code = `REF-${target_role.slice(0, 3).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const ownerId = req.user.role === 'owner' ? req.user.id : (req.user.owner_id || null);
    const adminId = req.user.role === 'admin' ? req.user.id : null;
    const assignedLoadersStr = JSON.stringify(assigned_loaders || []);

    const ref = (await sql`
      INSERT INTO fkc.referrals (code, creator_id, owner_id, admin_id, target_role, credits_allocated, max_loaders_allowed, assigned_loaders)
      VALUES (${code}, ${req.user.id}, ${ownerId}, ${adminId}, ${target_role}, ${credits}, ${max_loaders_allowed || 1}, ${assignedLoadersStr})
      RETURNING *
    `)[0];

    // Log transaction with typed negative integer
    if (credits > 0 && req.user.role === 'admin') {
      const remaining = (await sql`SELECT credits FROM fkc.users WHERE id = ${req.user.id}`)[0].credits;
      const negCredits = -Math.abs(credits);
      await sql`
        INSERT INTO fkc.credit_ledger (user_id, actor_id, action_type, amount, balance_after, note)
        VALUES (${req.user.id}, ${req.user.id}, 'TRANSFER', ${negCredits}::int, ${remaining}, ${`Allocated to Referral Card ${code}`})
      `;
    }

    res.json({ success: true, referral: ref });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// 6. LICENSE KEY MANAGEMENT (SINGLE & BULK GENERATE)
// ============================================================
app.get('/api/keys', authenticate, async (req, res) => {
  try {
    const { loader_id, status } = req.query;
    const loaderIdParam = loader_id ? parseInt(loader_id) : null;
    const statusParam = status ? String(status).trim() : null;
    let query;

    if (req.user.role === 'superadmin') {
      query = sql`
        SELECT k.*, l.loader_name, l.slug as loader_slug, u.username as creator_name,
               (SELECT count(*) FROM fkc.bound_devices bd WHERE bd.key_id = k.id) as bound_count
        FROM fkc.license_keys k
        JOIN fkc.loaders l ON k.loader_id = l.id
        JOIN fkc.users u ON k.creator_id = u.id
        WHERE (${loaderIdParam}::int IS NULL OR k.loader_id = ${loaderIdParam}::int)
          AND (${statusParam}::varchar IS NULL OR k.status = ${statusParam}::varchar)
        ORDER BY k.id DESC LIMIT 300
      `;
    } else if (req.user.role === 'owner') {
      query = sql`
        SELECT k.*, l.loader_name, l.slug as loader_slug, u.username as creator_name,
               (SELECT count(*) FROM fkc.bound_devices bd WHERE bd.key_id = k.id) as bound_count
        FROM fkc.license_keys k
        JOIN fkc.loaders l ON k.loader_id = l.id
        JOIN fkc.users u ON k.creator_id = u.id
        WHERE k.owner_id = ${req.user.id}
          AND (${loaderIdParam}::int IS NULL OR k.loader_id = ${loaderIdParam}::int)
          AND (${statusParam}::varchar IS NULL OR k.status = ${statusParam}::varchar)
        ORDER BY k.id DESC LIMIT 300
      `;
    } else if (req.user.role === 'admin') {
      query = sql`
        SELECT k.*, l.loader_name, l.slug as loader_slug, u.username as creator_name,
               (SELECT count(*) FROM fkc.bound_devices bd WHERE bd.key_id = k.id) as bound_count
        FROM fkc.license_keys k
        JOIN fkc.loaders l ON k.loader_id = l.id
        JOIN fkc.users u ON k.creator_id = u.id
        WHERE (k.creator_id = ${req.user.id} OR u.admin_id = ${req.user.id})
          AND (${loaderIdParam}::int IS NULL OR k.loader_id = ${loaderIdParam}::int)
          AND (${statusParam}::varchar IS NULL OR k.status = ${statusParam}::varchar)
        ORDER BY k.id DESC LIMIT 300
      `;
    } else {
      query = sql`
        SELECT k.*, l.loader_name, l.slug as loader_slug, u.username as creator_name,
               (SELECT count(*) FROM fkc.bound_devices bd WHERE bd.key_id = k.id) as bound_count
        FROM fkc.license_keys k
        JOIN fkc.loaders l ON k.loader_id = l.id
        JOIN fkc.users u ON k.creator_id = u.id
        WHERE k.creator_id = ${req.user.id}
          AND (${loaderIdParam}::int IS NULL OR k.loader_id = ${loaderIdParam}::int)
          AND (${statusParam}::varchar IS NULL OR k.status = ${statusParam}::varchar)
        ORDER BY k.id DESC LIMIT 300
      `;
    }

    const keys = await query;
    res.json({ keys });
  } catch (err) {
    console.error('[GET /api/keys Error]', err);
    res.status(500).json({ error: err.message });
  }
});

// Single or Bulk Generate Keys
app.post('/api/keys', authenticate, async (req, res) => {
  const { loader_id, duration_type, custom_days, quantity, max_devices, prefix } = req.body;
  const qty = Math.min(Math.max(parseInt(quantity || 1), 1), 100);
  const maxDev = Math.max(parseInt(max_devices || 1), 1);

  let days = 1;
  if (duration_type === '1d') days = 1;
  else if (duration_type === '7d') days = 7;
  else if (duration_type === '15d') days = 15;
  else if (duration_type === '30d') days = 30;
  else if (duration_type === '60d') days = 60;
  else if (duration_type === 'custom') days = Math.max(parseInt(custom_days || 1), 1);

  try {
    const loader = (await sql`SELECT * FROM fkc.loaders WHERE id = ${parseInt(loader_id)}`)[0];
    if (!loader) return res.status(404).json({ error: 'Selected loader not found' });

    const ownerId = loader.owner_id;

    // Check Tenant Alignment
    if (req.user.role !== 'superadmin' && req.user.role !== 'owner' && req.user.owner_id !== ownerId) {
      return res.status(403).json({ error: 'You cannot generate keys for this Owner’s loader!' });
    }

    // Check Assigned Loader Access for Admin / Reseller
    if (req.user.role === 'admin' || req.user.role === 'reseller') {
      let assigned = [];
      try { assigned = JSON.parse(req.user.assigned_loaders || '[]'); } catch (e) {}
      if (Array.isArray(assigned) && assigned.length > 0 && !assigned.includes('all')) {
        const allowedIds = assigned.map(Number);
        if (!allowedIds.includes(loader.id)) {
          return res.status(403).json({ error: 'You do not have permission to generate keys for this specific loader!' });
        }
      }
    }

    // Determine Cost
    let unitCost = 1;
    const settings = (await sql`SELECT * FROM fkc.owner_settings WHERE owner_id = ${ownerId}`)[0];
    if (settings) {
      if (duration_type === '1d') unitCost = settings.price_1d || 1;
      else if (duration_type === '7d') unitCost = settings.price_7d || 5;
      else if (duration_type === '15d') unitCost = settings.price_15d || 10;
      else if (duration_type === '30d') unitCost = settings.price_30d || 18;
      else if (duration_type === '60d') unitCost = settings.price_60d || 32;
      else if (duration_type === 'custom') unitCost = (settings.price_custom_per_day || 1) * days;
    }

    const totalCost = unitCost * qty;

    // Deduct credits with typed integer cast (Prevents SQL unary minus syntax error)
    if (req.user.role === 'admin' || req.user.role === 'reseller') {
      const currentUser = (await sql`SELECT credits FROM fkc.users WHERE id = ${req.user.id}`)[0];
      if (currentUser.credits < totalCost) {
        return res.status(400).json({
          error: `Insufficient credits! Generating ${qty} x ${days}D requires ${totalCost} credits, but you have ${currentUser.credits}.`
        });
      }
      await sql`UPDATE fkc.users SET credits = credits - ${parseInt(totalCost)}::int WHERE id = ${req.user.id}`;
    }

    // Generate Keys
    const cleanPrefix = (prefix || 'FL').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    const generatedKeys = [];

    for (let i = 0; i < qty; i++) {
      const randomStr = crypto.randomBytes(4).toString('hex').toUpperCase();
      const keyString = `${cleanPrefix}-${duration_type.toUpperCase()}-${randomStr}`;

      const inserted = (await sql`
        INSERT INTO fkc.license_keys (owner_id, loader_id, creator_id, user_key, duration_type, duration_days, max_devices)
        VALUES (${ownerId}, ${loader.id}, ${req.user.id}, ${keyString}, ${duration_type}, ${days}, ${maxDev})
        RETURNING *
      `)[0];

      generatedKeys.push(inserted);
    }

    // Log transaction with explicit typed negative value
    if (totalCost > 0 && (req.user.role === 'admin' || req.user.role === 'reseller')) {
      const freshBalance = (await sql`SELECT credits FROM fkc.users WHERE id = ${req.user.id}`)[0].credits;
      const negTotalCost = -Math.abs(parseInt(totalCost));
      await sql`
        INSERT INTO fkc.credit_ledger (user_id, actor_id, action_type, amount, balance_after, note)
        VALUES (${req.user.id}, ${req.user.id}, 'KEY_GEN', ${negTotalCost}::int, ${freshBalance}, ${`Generated ${qty} x ${duration_type} keys for ${loader.loader_name}`})
      `;
    }

    res.json({
      success: true,
      total_cost: totalCost,
      keys: generatedKeys
    });
  } catch (err) {
    console.error('[POST /api/keys Error]', err);
    res.status(500).json({ error: err.message });
  }
});

// 1-Click HWID Reset
app.put('/api/keys/:id/reset-hwid', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    const key = (await sql`SELECT * FROM fkc.license_keys WHERE id = ${parseInt(id)}`)[0];
    if (!key) return res.status(404).json({ error: 'Key not found' });

    if (req.user.role === 'reseller' && key.creator_id !== req.user.id) {
      return res.status(403).json({ error: 'You can only reset your own keys' });
    }

    await sql`DELETE FROM fkc.bound_devices WHERE key_id = ${key.id}`;

    const loader = (await sql`SELECT slug FROM fkc.loaders WHERE id = ${key.loader_id}`)[0];
    if (loader) invalidateCache(loader.slug, key.user_key);

    res.json({ success: true, message: 'HWID successfully reset! Customer can now bind new device.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 1-Click Ban / Unban Toggle
app.put('/api/keys/:id/toggle-ban', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    const key = (await sql`SELECT * FROM fkc.license_keys WHERE id = ${parseInt(id)}`)[0];
    if (!key) return res.status(404).json({ error: 'Key not found' });

    const newStatus = key.status === 'banned' ? 'active' : 'banned';
    await sql`UPDATE fkc.license_keys SET status = ${newStatus} WHERE id = ${key.id}`;

    const loader = (await sql`SELECT slug FROM fkc.loaders WHERE id = ${key.loader_id}`)[0];
    if (loader) invalidateCache(loader.slug, key.user_key);

    res.json({ success: true, status: newStatus, message: `Key status set to ${newStatus.toUpperCase()}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Extend Key Expiry
app.put('/api/keys/:id/extend', authenticate, async (req, res) => {
  const { id } = req.params;
  const { extra_days } = req.body;
  const daysToAdd = Math.max(parseInt(extra_days || 1), 1);

  try {
    const key = (await sql`SELECT * FROM fkc.license_keys WHERE id = ${parseInt(id)}`)[0];
    if (!key) return res.status(404).json({ error: 'Key not found' });

    let newExpiresAt = key.expires_at ? new Date(key.expires_at) : new Date();
    if (newExpiresAt.getTime() < Date.now()) {
      newExpiresAt = new Date();
    }
    newExpiresAt = new Date(newExpiresAt.getTime() + daysToAdd * 24 * 3600 * 1000);

    await sql`
      UPDATE fkc.license_keys 
      SET expires_at = ${newExpiresAt}, duration_days = duration_days + ${daysToAdd}, status = 'active'
      WHERE id = ${key.id}
    `;

    const loader = (await sql`SELECT slug FROM fkc.loaders WHERE id = ${key.loader_id}`)[0];
    if (loader) invalidateCache(loader.slug, key.user_key);

    res.json({ success: true, message: `Key extended by ${daysToAdd} days! New Expiry: ${newExpiresAt.toISOString()}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// 7. USER MANAGEMENT, TOP-UP & CREDIT PASSBOOK
// ============================================================
app.get('/api/users', authenticate, async (req, res) => {
  try {
    let users;
    if (req.user.role === 'superadmin') {
      users = await sql`
        SELECT u.id, u.username, u.role, u.credits, u.status, u.owner_id, u.admin_id, u.assigned_loaders, u.created_at,
               (SELECT count(*) FROM fkc.license_keys k WHERE k.creator_id = u.id) as keys_generated
        FROM fkc.users u
        ORDER BY u.id DESC
      `;
    } else if (req.user.role === 'owner') {
      users = await sql`
        SELECT u.id, u.username, u.role, u.credits, u.status, u.owner_id, u.admin_id, u.assigned_loaders, u.created_at,
               (SELECT count(*) FROM fkc.license_keys k WHERE k.creator_id = u.id) as keys_generated
        FROM fkc.users u
        WHERE u.owner_id = ${req.user.id}
        ORDER BY u.id DESC
      `;
    } else if (req.user.role === 'admin') {
      users = await sql`
        SELECT u.id, u.username, u.role, u.credits, u.status, u.owner_id, u.admin_id, u.assigned_loaders, u.created_at,
               (SELECT count(*) FROM fkc.license_keys k WHERE k.creator_id = u.id) as keys_generated
        FROM fkc.users u
        WHERE u.admin_id = ${req.user.id}
        ORDER BY u.id DESC
      `;
    } else {
      return res.status(403).json({ error: 'Resellers cannot list users' });
    }

    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Top-up Balance
app.post('/api/users/topup', authenticate, async (req, res) => {
  const { target_user_id, amount, note } = req.body;
  const creditsToAdd = parseInt(amount || 0);

  if (creditsToAdd <= 0) {
    return res.status(400).json({ error: 'Top-up amount must be greater than zero' });
  }

  try {
    const targetUser = (await sql`SELECT * FROM fkc.users WHERE id = ${parseInt(target_user_id)}`)[0];
    if (!targetUser) return res.status(404).json({ error: 'Target user not found' });

    if (req.user.role === 'admin') {
      if (targetUser.admin_id !== req.user.id) {
        return res.status(403).json({ error: 'You can only top-up your own resellers' });
      }
      const adminUser = (await sql`SELECT credits FROM fkc.users WHERE id = ${req.user.id}`)[0];
      if (adminUser.credits < creditsToAdd) {
        return res.status(400).json({ error: `Insufficient credits! You have ${adminUser.credits}, attempted top-up ${creditsToAdd}.` });
      }
      await sql`UPDATE fkc.users SET credits = credits - ${creditsToAdd}::int WHERE id = ${req.user.id}`;
    } else if (req.user.role === 'owner') {
      if (targetUser.owner_id !== req.user.id) {
        return res.status(403).json({ error: 'You can only top-up your own Admins or Resellers' });
      }
    }

    const updated = (await sql`
      UPDATE fkc.users 
      SET credits = credits + ${creditsToAdd}::int 
      WHERE id = ${targetUser.id}
      RETURNING credits
    `)[0];

    await sql`
      INSERT INTO fkc.credit_ledger (user_id, actor_id, action_type, amount, balance_after, note)
      VALUES (${targetUser.id}, ${req.user.id}, 'TOP_UP', ${creditsToAdd}::int, ${updated.credits}, ${note || `Top-up by ${req.user.username}`})
    `;

    res.json({ success: true, new_balance: updated.credits, message: `Successfully added ${creditsToAdd} credits!` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Toggle User Block Status
app.put('/api/users/:id/toggle-block', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    const target = (await sql`SELECT * FROM fkc.users WHERE id = ${parseInt(id)}`)[0];
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.role === 'superadmin') return res.status(403).json({ error: 'Cannot block SuperAdmin!' });

    const newStatus = target.status === 'blocked' ? 'active' : 'blocked';
    await sql`UPDATE fkc.users SET status = ${newStatus} WHERE id = ${target.id}`;

    res.json({ success: true, status: newStatus, message: `User ${target.username} is now ${newStatus.toUpperCase()}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Credit Ledger History
app.get('/api/ledger', authenticate, async (req, res) => {
  try {
    let ledger;
    if (req.user.role === 'superadmin') {
      ledger = await sql`
        SELECT l.*, u.username, actor.username as actor_name
        FROM fkc.credit_ledger l
        JOIN fkc.users u ON l.user_id = u.id
        JOIN fkc.users actor ON l.actor_id = actor.id
        ORDER BY l.id DESC LIMIT 150
      `;
    } else {
      ledger = await sql`
        SELECT l.*, u.username, actor.username as actor_name
        FROM fkc.credit_ledger l
        JOIN fkc.users u ON l.user_id = u.id
        JOIN fkc.users actor ON l.actor_id = actor.id
        WHERE l.user_id = ${req.user.id} OR l.actor_id = ${req.user.id}
        ORDER BY l.id DESC LIMIT 150
      `;
    }
    res.json({ ledger });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Dashboard Statistics
app.get('/api/stats', authenticate, async (req, res) => {
  try {
    const effectiveOwnerId = req.user.role === 'superadmin' ? null : (req.user.role === 'owner' ? req.user.id : req.user.owner_id);

    const totalKeys = (await (effectiveOwnerId
      ? sql`SELECT count(*) FROM fkc.license_keys WHERE owner_id = ${effectiveOwnerId}`
      : sql`SELECT count(*) FROM fkc.license_keys`))[0].count;

    const activeKeys = (await (effectiveOwnerId
      ? sql`SELECT count(*) FROM fkc.license_keys WHERE owner_id = ${effectiveOwnerId} AND status = 'active'`
      : sql`SELECT count(*) FROM fkc.license_keys WHERE status = 'active'`))[0].count;

    const activeLoaders = (await (effectiveOwnerId
      ? sql`SELECT count(*) FROM fkc.loaders WHERE owner_id = ${effectiveOwnerId}`
      : sql`SELECT count(*) FROM fkc.loaders`))[0].count;

    const totalDevices = (await (effectiveOwnerId
      ? sql`SELECT count(*) FROM fkc.bound_devices bd JOIN fkc.license_keys k ON bd.key_id = k.id WHERE k.owner_id = ${effectiveOwnerId}`
      : sql`SELECT count(*) FROM fkc.bound_devices`))[0].count;

    res.json({
      stats: {
        total_keys: parseInt(totalKeys),
        active_keys: parseInt(activeKeys),
        active_loaders: parseInt(activeLoaders),
        total_devices: parseInt(totalDevices)
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// 8. STATIC FILES & SINGLE PAGE APP DELIVERY
// ============================================================
app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0 }));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', engine: 'Featurestic Key Center (Phantom X)', uptime: process.uptime() });
});

app.get('*', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (!process.env.VERCEL) {
  initDb().then(() => {
    app.listen(PORT, () => {
      console.log(`[Featurestic Key Center] Engine running on port ${PORT}`);
    });
  }).catch(err => {
    console.error('[FKC-DB Error]', err);
  });
}

export default app;
