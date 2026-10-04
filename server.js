import express from 'express';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import midtransClient from 'midtrans-client';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

/* =========================================================
   BASIC CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 3000);
const DEFAULT_DB_DIR = fs.existsSync('/data') ? '/data' : path.join(__dirname, 'data');
const DB_PATH = String(process.env.DB_PATH || path.join(DEFAULT_DB_DIR, 'data.db')).trim();

// Make sure a custom Railway volume/database directory exists.
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const SESSION_DAYS = 30;
const CODE_RESERVATION_MINUTES = 15;

app.disable('x-powered-by');

app.use(
  express.json({
    limit: '1mb'
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: '1mb'
  })
);

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);


/* =========================================================
   DATABASE
========================================================= */

const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    oauth_provider TEXT,
    oauth_subject TEXT,
    display_name TEXT,
    avatar_url TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS oauth_states(
    state_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS password_resets(
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS sessions(
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id)
      REFERENCES users(id)
      ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS products(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    duration_days INTEGER NOT NULL,
    price INTEGER NOT NULL CHECK(price >= 0),
    active INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS codes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    redeem_code TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'available',
    order_id TEXT,
    reserved_until INTEGER,

    FOREIGN KEY(product_id)
      REFERENCES products(id)
      ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS orders(
    id TEXT PRIMARY KEY,
    user_id INTEGER,
    product_id INTEGER NOT NULL,
    code_id INTEGER,
    amount INTEGER NOT NULL,
    payment_status TEXT NOT NULL DEFAULT 'pending',
    redeem_code TEXT,
    midtrans_transaction_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    paid_at TEXT,

    FOREIGN KEY(user_id)
      REFERENCES users(id)
      ON DELETE SET NULL,

    FOREIGN KEY(product_id)
      REFERENCES products(id)
      ON DELETE RESTRICT,

    FOREIGN KEY(code_id)
      REFERENCES codes(id)
      ON DELETE SET NULL
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_expiry
    ON sessions(expires_at);

  CREATE INDEX IF NOT EXISTS idx_codes_stock
    ON codes(product_id,status);

  CREATE INDEX IF NOT EXISTS idx_codes_reservation
    ON codes(status,reserved_until);

  CREATE INDEX IF NOT EXISTS idx_orders_user
    ON orders(user_id,created_at);

  CREATE INDEX IF NOT EXISTS idx_orders_payment
    ON orders(payment_status);

  CREATE INDEX IF NOT EXISTS idx_orders_midtrans
    ON orders(midtrans_transaction_id);
`);

// Order-contact / fulfillment migrations for existing databases.
const orderColumns = db.prepare(`PRAGMA table_info(orders)`).all().map(x => x.name);
const addOrderColumn = (name, sql) => { if (!orderColumns.includes(name)) db.exec(`ALTER TABLE orders ADD COLUMN ${sql}`); };
addOrderColumn('customer_email', 'customer_email TEXT');
addOrderColumn('customer_phone', 'customer_phone TEXT');
addOrderColumn('delivery_channel', "delivery_channel TEXT NOT NULL DEFAULT 'email'");
addOrderColumn('fulfillment_status', "fulfillment_status TEXT NOT NULL DEFAULT 'pending_payment'");
addOrderColumn('delivery_note', 'delivery_note TEXT');
db.prepare(`UPDATE orders SET fulfillment_status='completed' WHERE payment_status='paid' AND redeem_code IS NOT NULL AND fulfillment_status='pending_payment'`).run();
db.prepare(`UPDATE orders SET fulfillment_status='failed' WHERE payment_status IN ('expire','cancel','deny','failure') AND fulfillment_status='pending_payment'`).run();

// Auth migrations for existing databases.
const userColumns = db.prepare(`PRAGMA table_info(users)`).all().map(x => x.name);
const addUserColumn = (name, sql) => { if (!userColumns.includes(name)) db.exec(`ALTER TABLE users ADD COLUMN ${sql}`); };
addUserColumn('oauth_provider', 'oauth_provider TEXT');
addUserColumn('oauth_subject', 'oauth_subject TEXT');
addUserColumn('display_name', 'display_name TEXT');
addUserColumn('avatar_url', 'avatar_url TEXT');
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oauth ON users(oauth_provider,oauth_subject) WHERE oauth_provider IS NOT NULL AND oauth_subject IS NOT NULL`);
// Enforce one account per email case-insensitively, even if the client changes capitalization.
// Existing email values are normalized to lowercase before this index is created.
db.prepare(`UPDATE users SET email=LOWER(TRIM(email)) WHERE email IS NOT NULL`).run();
try {
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_nocase ON users(LOWER(email))`);
} catch (error) {
  console.error('Could not create case-insensitive email index:', error.message);
}
db.exec(`CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_password_resets_expiry ON password_resets(expires_at)`);


/* =========================================================
   MIDTRANS
========================================================= */

const MIDTRANS_IS_PRODUCTION =
  process.env.MIDTRANS_IS_PRODUCTION === 'true';

const MIDTRANS_SERVER_KEY =
  String(
    process.env.MIDTRANS_SERVER_KEY || ''
  ).trim();

const MIDTRANS_CLIENT_KEY =
  String(
    process.env.MIDTRANS_CLIENT_KEY || ''
  ).trim();

const snap =
  new midtransClient.Snap({
    isProduction:
      MIDTRANS_IS_PRODUCTION,

    serverKey:
      MIDTRANS_SERVER_KEY,

    clientKey:
      MIDTRANS_CLIENT_KEY
  });


/* =========================================================
   HELPERS
========================================================= */

const normalizeEmail = value => String(value || '').trim().toLowerCase();
const normalizePhone = value => { let v = String(value || '').replace(/[^0-9+]/g, ''); if (v.startsWith('+')) v=v.slice(1); if (v.startsWith('0')) v='62'+v.slice(1); return v; };
const validEmail = value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(value));
const validPhone = value => /^62[0-9]{9,13}$/.test(normalizePhone(value));

const safeEmail = value =>
  String(value || '')
    .trim()
    .toLowerCase();

const hashToken = token =>
  crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');

const newToken = () =>
  crypto
    .randomBytes(32)
    .toString('hex');

const newOrderId = () =>
  'TC-' +
  Date.now() +
  '-' +
  crypto
    .randomBytes(4)
    .toString('hex')
    .toUpperCase();

const toMoney = value =>
  Number(value);

const jsonError = (
  res,
  status,
  message
) =>
  res
    .status(status)
    .json({
      error: message
    });

const isValidEmail = email =>
  /^\S+@\S+\.\S+$/.test(email);

const validDurations = [
  1,
  3,
  7,
  30
];


/* =========================================================
   CLEAN EXPIRED SESSIONS
========================================================= */

function cleanupSessions(){

  try{

    db.prepare(
      'DELETE FROM sessions WHERE expires_at <= ?'
    ).run(Date.now());

  }catch(error){

    console.error(
      'Session cleanup error:',
      error.message
    );

  }

}

cleanupSessions();

setInterval(
  cleanupSessions,
  60 * 60 * 1000
).unref();


/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function auth(
  req,
  res,
  next
){

  const authorization =
    String(
      req.headers.authorization || ''
    );

  let bearer =
    authorization
      .replace(
        /^Bearer\s+/i,
        ''
      )
      .trim();

  if(!bearer){
    const cookieHeader = String(req.headers.cookie || '');
    const match = cookieHeader.match(/(?:^|;\s*)tc_session=([^;]+)/);
    if(match) bearer = decodeURIComponent(match[1]);
  }

  if(!bearer){

    return jsonError(
      res,
      401,
      'Login required'
    );

  }

  const session =
    db.prepare(`
      SELECT
        token_hash,
        user_id,
        expires_at
      FROM sessions
      WHERE token_hash = ?
        AND expires_at > ?
    `).get(
      hashToken(bearer),
      Date.now()
    );

  if(!session){

    return jsonError(
      res,
      401,
      'Sesi login berakhir'
    );

  }

  req.userId =
    Number(session.user_id);

  req.rawToken =
    bearer;

  next();
}


/* =========================================================
   ADMIN MIDDLEWARE
========================================================= */

function admin(
  req,
  res,
  next
){

  const configuredKey =
    String(
      process.env.ADMIN_KEY || ''
    ).trim();

  const receivedKey =
    String(
      req.headers['x-admin-key'] || ''
    ).trim();

  if(!configuredKey || !receivedKey){
    return jsonError(res,401,'Unauthorized');
  }

  const a = Buffer.from(receivedKey);
  const b = Buffer.from(configuredKey);
  const same = a.length === b.length && crypto.timingSafeEqual(a,b);

  if(!same){
    return jsonError(res,401,'Unauthorized');
  }

  next();
}


/* =========================================================
   HEALTH / CONFIG
========================================================= */

app.get('/api/admin/check', admin, (req,res) => {
  res.json({ok:true});
});


app.get(
  '/health',
  (req,res) => {

    res.json({
      ok:true,
      service:'top-up-clouds',
      time:new Date().toISOString()
    });

  }
);


app.get(
  '/api/config',
  (req,res) => {

    res.json({

      clientKey:
        MIDTRANS_CLIENT_KEY,

      production:
        MIDTRANS_IS_PRODUCTION

    });

  }
);


/* =========================================================
   PRODUCTS
========================================================= */

app.get(
  '/api/products',
  (req,res) => {

    try{

      const rows =
        db.prepare(`
          SELECT
            id,
            provider,
            name,
            duration_days,
            price,
            active
          FROM products
          WHERE active = 1
          ORDER BY
            provider ASC,
            name ASC,
            duration_days ASC
        `).all();

      res.json(rows);

    }catch(error){

      console.error(
        'Products error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal mengambil produk'
      );

    }

  }
);


/* =========================================================
   AUTH HELPERS / GOOGLE OAUTH / PASSWORD RESET
========================================================= */

function sessionForUser(userId){
  const token = newToken();
  const expiresAt = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  db.prepare(`INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)`).run(hashToken(token), userId, expiresAt);
  return { token, expiresAt };
}

function baseUrl(req){
  return String(process.env.APP_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/,'');
}

function setSessionCookie(res, token){
  const secure = process.env.NODE_ENV === 'production' || process.env.MIDTRANS_IS_PRODUCTION === 'true';
  res.setHeader('Set-Cookie', `tc_session=${encodeURIComponent(token)}; Max-Age=${SESSION_DAYS*24*60*60}; Path=/; HttpOnly; SameSite=Lax${secure?'; Secure':''}`);
}

app.get('/api/me', auth, (req,res) => {
  const user = db.prepare(`SELECT id,email,display_name,avatar_url,oauth_provider FROM users WHERE id=?`).get(req.userId);
  if(!user) return jsonError(res,404,'Akun tidak ditemukan');
  res.json({ok:true,user});
});

app.get('/api/auth/google', (req,res) => {
  const clientId = String(process.env.GOOGLE_CLIENT_ID || '').trim();
  const redirectUri = String(process.env.GOOGLE_REDIRECT_URI || `${baseUrl(req)}/api/auth/google/callback`).trim();
  if(!clientId) return jsonError(res,503,'Google Login belum dikonfigurasi di server');
  const state = newToken();
  db.prepare(`INSERT INTO oauth_states(state_hash,provider,expires_at) VALUES(?,?,?)`).run(hashToken(state),'google',Date.now()+10*60*1000);
  const params = new URLSearchParams({client_id:clientId,redirect_uri:redirectUri,response_type:'code',scope:'openid email profile',state,access_type:'online',prompt:'select_account'});
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/api/auth/google/callback', async (req,res) => {
  try{
    const code = String(req.query.code || '');
    const state = String(req.query.state || '');
    if(!code || !state) return res.redirect('/?oauth_error=missing');
    const stateHash = hashToken(state);
    const stateRow = db.prepare(`SELECT * FROM oauth_states WHERE state_hash=? AND provider='google' AND expires_at>?`).get(stateHash,Date.now());
    db.prepare(`DELETE FROM oauth_states WHERE state_hash=?`).run(stateHash);
    if(!stateRow) return res.redirect('/?oauth_error=state');
    const clientId = String(process.env.GOOGLE_CLIENT_ID || '').trim();
    const clientSecret = String(process.env.GOOGLE_CLIENT_SECRET || '').trim();
    const redirectUri = String(process.env.GOOGLE_REDIRECT_URI || `${baseUrl(req)}/api/auth/google/callback`).trim();
    if(!clientId || !clientSecret) return res.redirect('/?oauth_error=config');
    const tokenResp = await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code,client_id:clientId,client_secret:clientSecret,redirect_uri:redirectUri,grant_type:'authorization_code'})});
    const tokenData = await tokenResp.json();
    if(!tokenResp.ok || !tokenData.access_token) throw new Error('Google token exchange failed');
    const profileResp = await fetch('https://openidconnect.googleapis.com/v1/userinfo',{headers:{Authorization:`Bearer ${tokenData.access_token}`}});
    const profile = await profileResp.json();
    if(!profileResp.ok || !profile.sub || !profile.email) throw new Error('Google profile unavailable');
    const email = normalizeEmail(profile.email);
    let user = db.prepare(`SELECT * FROM users WHERE oauth_provider='google' AND oauth_subject=?`).get(String(profile.sub));
    if(!user) user = db.prepare(`SELECT * FROM users WHERE email=?`).get(email);
    if(user){
      db.prepare(`UPDATE users SET oauth_provider='google',oauth_subject=?,display_name=?,avatar_url=? WHERE id=?`).run(String(profile.sub),String(profile.name||''),String(profile.picture||''),user.id);
    } else {
      const randomPassword = await bcrypt.hash(newToken()+newToken(),12);
      const result = db.prepare(`INSERT INTO users(email,password_hash,oauth_provider,oauth_subject,display_name,avatar_url) VALUES(?,?,?,?,?,?)`).run(email,randomPassword,'google',String(profile.sub),String(profile.name||''),String(profile.picture||''));
      user = {id:result.lastInsertRowid,email};
    }
    const session = sessionForUser(user.id);
    setSessionCookie(res,session.token);
    res.redirect('/#oauth_token='+encodeURIComponent(session.token));
  }catch(error){
    console.error('Google OAuth error:',error.message);
    res.redirect('/?oauth_error=failed');
  }
});

app.post('/api/forgot-password', async (req,res) => {
  const email = normalizeEmail(req.body?.email);
  const publicMessage = 'Jika email terdaftar, link reset password sudah dikirim. Cek Inbox/Spam.';
  if(!validEmail(email)) return res.json({ok:true,message:publicMessage});
  try{
    const user = db.prepare(`SELECT id,email FROM users WHERE email=?`).get(email);
    if(!user) return res.json({ok:true,message:publicMessage});
    if(!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM){
      console.warn('Password reset requested but RESEND_API_KEY/EMAIL_FROM is not configured.');
      return res.json({ok:true,message:publicMessage});
    }
    db.prepare(`DELETE FROM password_resets WHERE user_id=? OR expires_at<=?`).run(user.id,Date.now());
    const rawToken = newToken()+newToken();
    const tokenHash = hashToken(rawToken);
    db.prepare(`INSERT INTO password_resets(token_hash,user_id,expires_at) VALUES(?,?,?)`).run(tokenHash,user.id,Date.now()+30*60*1000);
    const link = `${baseUrl(req)}/?reset_token=${encodeURIComponent(rawToken)}`;
    const r = await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:`Bearer ${process.env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({from:process.env.EMAIL_FROM,to:[email],subject:'Reset Password Top up Clouds',html:`<div style="font-family:Arial,sans-serif;line-height:1.6"><h2>Top up Clouds</h2><p>Klik tombol berikut untuk membuat password baru. Link berlaku 30 menit.</p><p><a href="${link}" style="display:inline-block;padding:12px 18px;background:#64f6a5;color:#06100c;text-decoration:none;border-radius:8px;font-weight:bold">Reset Password</a></p><p>Jika kamu tidak meminta reset password, abaikan email ini.</p></div>`})});
    if(!r.ok) console.error('Resend reset email failed:',r.status,await r.text());
    return res.json({ok:true,message:publicMessage});
  }catch(error){
    console.error('Forgot password error:',error.message);
    return res.json({ok:true,message:publicMessage});
  }
});

app.post('/api/reset-password', async (req,res) => {
  const token = String(req.body?.token || '').trim();
  const password = String(req.body?.password || '');
  if(token.length < 32 || password.length < 8) return jsonError(res,400,'Token reset tidak valid atau password minimal 8 karakter.');
  const row = db.prepare(`SELECT * FROM password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at>?`).get(hashToken(token),Date.now());
  if(!row) return jsonError(res,400,'Link reset password sudah tidak berlaku. Minta link baru.');
  const passwordHash = await bcrypt.hash(password,12);
  db.transaction(()=>{
    db.prepare(`UPDATE users SET password_hash=? WHERE id=?`).run(passwordHash,row.user_id);
    db.prepare(`UPDATE password_resets SET used_at=CURRENT_TIMESTAMP WHERE token_hash=?`).run(hashToken(token));
    db.prepare(`DELETE FROM sessions WHERE user_id=?`).run(row.user_id);
  })();
  const session = sessionForUser(row.user_id);
  setSessionCookie(res,session.token);
  const user = db.prepare(`SELECT email FROM users WHERE id=?`).get(row.user_id);
  res.json({ok:true,token:session.token,email:user?.email||''});
});

/* =========================================================
   REGISTER
========================================================= */

app.post(
  '/api/register',
  async(req,res) => {

    try{

      const email =
        safeEmail(
          req.body?.email
        );

      const password =
        String(
          req.body?.password || ''
        );

      if(
        !isValidEmail(email) ||
        password.length < 8
      ){

        return jsonError(
          res,
          400,
          'Email valid dan password minimal 8 karakter wajib diisi'
        );

      }

      const existing =
        db.prepare(
          'SELECT id FROM users WHERE LOWER(email)=LOWER(?)'
        ).get(email);

      if(existing){
        return jsonError(res,409,'Email sudah terdaftar. Gunakan login atau Lupa password.');
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      let result;
      try {
        result = db.prepare(`
          INSERT INTO users(email,password_hash)
          VALUES(?,?)
        `).run(email,passwordHash);
      } catch (insertError) {
        if (String(insertError.message).toLowerCase().includes('unique')) {
          return jsonError(res,409,'Email sudah terdaftar. Gunakan login atau Lupa password.');
        }
        throw insertError;
      }

      const session = sessionForUser(result.lastInsertRowid);
      setSessionCookie(res,session.token);

      res.json({
        ok:true,
        token:session.token,
        email
      });

    }catch(error){

      console.error(
        'Register error:',
        error
      );

      if(
        String(error.message)
          .includes('UNIQUE')
      ){

        return jsonError(
          res,
          409,
          'Email sudah terdaftar'
        );

      }

      jsonError(
        res,
        500,
        'Gagal membuat akun'
      );

    }

  }
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
  '/api/login',
  async(req,res) => {

    try{

      const email =
        safeEmail(
          req.body?.email
        );

      const password =
        String(
          req.body?.password || ''
        );

      if(
        !isValidEmail(email) ||
        !password
      ){

        return jsonError(
          res,
          400,
          'Email dan password wajib diisi'
        );

      }

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE LOWER(email)=LOWER(?)
        `).get(email);

      if(
        !user ||
        !(await bcrypt.compare(
          password,
          user.password_hash
        ))
      ){

        return jsonError(
          res,
          401,
          'Email atau password salah'
        );

      }

      const session = sessionForUser(user.id);
      setSessionCookie(res,session.token);

      res.json({
        ok:true,
        token:session.token,
        email:user.email
      });

    }catch(error){

      console.error(
        'Login error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal login'
      );

    }

  }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
  '/api/logout',
  auth,
  (req,res) => {

    try{

      db.prepare(
        'DELETE FROM sessions WHERE token_hash=?'
      ).run(
        hashToken(
          req.rawToken
        )
      );

      res.setHeader('Set-Cookie','tc_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax');
      res.json({
        ok:true
      });

    }catch(error){

      console.error(
        'Logout error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal logout'
      );

    }

  }
);


/* =========================================================
   RESERVE REDEEM CODE
========================================================= */

function reserveCode(
  productId,
  orderId
){

  const now =
    Date.now();

  const reservedUntil =
    now +
    CODE_RESERVATION_MINUTES *
    60 *
    1000;

  const transaction =
    db.transaction(() => {

      /*
       * Release expired reservations.
       */
      db.prepare(`
        UPDATE codes
        SET
          status='available',
          order_id=NULL,
          reserved_until=NULL
        WHERE
          status='reserved'
          AND reserved_until IS NOT NULL
          AND reserved_until <= ?
      `).run(now);


      /*
       * Find available code.
       */
      const code =
        db.prepare(`
          SELECT *
          FROM codes
          WHERE
            product_id=?
            AND status='available'
          ORDER BY id ASC
          LIMIT 1
        `).get(
          productId
        );


      if(!code){

        return null;

      }


      /*
       * Atomic update.
       */
      const result =
        db.prepare(`
          UPDATE codes
          SET
            status='reserved',
            order_id=?,
            reserved_until=?
          WHERE
            id=?
            AND status='available'
        `).run(
          orderId,
          reservedUntil,
          code.id
        );


      if(
        result.changes !== 1
      ){

        return null;

      }


      return {
        ...code,
        reserved_until:
          reservedUntil
      };

    });

  return transaction();

}


/* =========================================================
   CREATE ORDER
========================================================= */

app.post(
  '/api/orders',
  auth,
  async(req,res) => {

    let reserved = null;
    let orderId = null;

    try{

      const productId =
        Number(
          req.body?.productId
        );

      const customerEmail = normalizeEmail(req.body?.customerEmail);
      const customerPhone = normalizePhone(req.body?.customerPhone);
      const deliveryChannel = String(req.body?.deliveryChannel || 'email').toLowerCase();
      if (!validEmail(customerEmail)) return jsonError(res, 400, 'Email penerima tidak valid');
      if (!validPhone(customerPhone)) return jsonError(res, 400, 'Nomor telepon tidak valid. Gunakan format 08xxxxxxxxxx atau 628xxxxxxxxxx');
      if (!['email','phone'].includes(deliveryChannel)) return jsonError(res, 400, 'Pilihan pengiriman kode tidak valid');

      if(
        !Number.isInteger(
          productId
        ) ||
        productId <= 0
      ){

        return jsonError(
          res,
          400,
          'productId tidak valid'
        );

      }


      const product =
        db.prepare(`
          SELECT *
          FROM products
          WHERE
            id=?
            AND active=1
        `).get(
          productId
        );


      if(!product){

        return jsonError(
          res,
          404,
          'Produk tidak ditemukan'
        );

      }


      if(
        !Number.isInteger(
          product.price
        ) ||
        product.price < 1
      ){

        return jsonError(
          res,
          400,
          'Harga produk belum siap'
        );

      }


      const user =
        db.prepare(`
          SELECT
            id,
            email
          FROM users
          WHERE id=?
        `).get(
          req.userId
        );


      if(!user){

        return jsonError(
          res,
          401,
          'User tidak ditemukan'
        );

      }


      /*
       * Check Midtrans configuration
       * before reserving stock.
       */
      if(
        !MIDTRANS_SERVER_KEY ||
        !MIDTRANS_CLIENT_KEY
      ){

        return jsonError(
          res,
          503,
          'Pembayaran belum dikonfigurasi'
        );

      }


      orderId =
        newOrderId();


      /*
       * Reserve code.
       */
      reserved =
        reserveCode(
          product.id,
          orderId
        );


      if(!reserved){

        return jsonError(
          res,
          409,
          'Stok Redeem Code habis'
        );

      }


      /*
       * Create local order first.
       */
      db.prepare(`
        INSERT INTO orders(
          id, user_id, product_id, code_id, amount, payment_status,
          customer_email, customer_phone, delivery_channel, fulfillment_status
        )
        VALUES(?,?,?,?,?,'pending',?,?,?,'pending_payment')
      `).run(
        orderId, req.userId, product.id, reserved.id, product.price,
        customerEmail, customerPhone, deliveryChannel
      );


      /*
       * Create Midtrans transaction.
       */
      const transaction =
        await snap.createTransaction({

          transaction_details:{
            order_id:
              orderId,

            gross_amount:
              toMoney(
                product.price
              )
          },

          customer_details:{
            email:
              user.email
          }

        });


      if(
        !transaction ||
        !transaction.token
      ){

        throw new Error(
          'Midtrans tidak mengembalikan token'
        );

      }


      res.json({

        ok:true,

        orderId,

        token:
          transaction.token,

        redirect_url:
          transaction.redirect_url

      });

    }catch(error){

      console.error(
        'Create order error:',
        error?.message ||
        error
      );


      /*
       * Roll back reserved code
       * and local order if Midtrans fails.
       */
      try{

        db.transaction(() => {

          if(reserved){

            db.prepare(`
              UPDATE codes
              SET
                status='available',
                order_id=NULL,
                reserved_until=NULL
              WHERE
                id=?
                AND status='reserved'
            `).run(
              reserved.id
            );

          }

          if(orderId){

            db.prepare(
              'DELETE FROM orders WHERE id=?'
            ).run(
              orderId
            );

          }

        })();

      }catch(cleanupError){

        console.error(
          'Order cleanup error:',
          cleanupError
        );

      }


      jsonError(
        res,
        502,
        'Payment gateway gagal membuat transaksi'
      );

    }

  }
);


/* =========================================================
   MIDTRANS SIGNATURE
========================================================= */

function verifyMidtransSignature(
  notification
){

  if(
    !notification ||
    !notification.order_id ||
    !notification.status_code ||
    !notification.gross_amount
  ){

    return false;

  }

  if(
    !MIDTRANS_SERVER_KEY
  ){

    return false;

  }

  const raw =
    String(
      notification.order_id
    ) +
    String(
      notification.status_code
    ) +
    String(
      notification.gross_amount
    ) +
    MIDTRANS_SERVER_KEY;


  const expected =
    crypto
      .createHash('sha512')
      .update(raw)
      .digest('hex');


  const received =
    String(
      notification.signature_key || ''
    ).toLowerCase();


  if(
    received.length !==
    expected.length
  ){

    return false;

  }


  return crypto.timingSafeEqual(
    Buffer.from(received),
    Buffer.from(expected)
  );

}


/* =========================================================
   MARK ORDER PAID
========================================================= */

const markPaid =
  db.transaction(
    (
      notification,
      order
    ) => {

      const existing =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE id=?
        `).get(
          order.id
        );


      if(!existing){

        return {
          ok:false,
          reason:'order_not_found'
        };

      }


      /*
       * Idempotency:
       * Midtrans may send notification more than once.
       */
      if(
        existing.payment_status ===
        'paid'
      ){

        return {
          ok:true,
          alreadyPaid:true
        };

      }


      /*
       * Verify amount against
       * local order amount.
       */
      const notificationAmount =
        Number(
          notification.gross_amount
        );

      if(
        notificationAmount !==
        Number(existing.amount)
      ){

        throw new Error(
          'Nominal Midtrans tidak sesuai order'
        );

      }


      const code =
        existing.code_id
          ? db.prepare(`
              SELECT *
              FROM codes
              WHERE id=?
            `).get(
              existing.code_id
            )
          : null;


      /*
       * If stock disappeared,
       * do NOT pretend payment was successful
       * with a missing code.
       */
      if(
        !code ||
        (
          code.status !== 'reserved' &&
          code.status !== 'available'
        )
      ){

        db.prepare(`
          UPDATE orders
          SET
            payment_status='paid_no_stock',
            midtrans_transaction_id=?,
            paid_at=CURRENT_TIMESTAMP
          WHERE id=?
        `).run(
          notification.transaction_id || null,
          existing.id
        );


        return {
          ok:false,
          reason:'no_stock'
        };

      }


      /*
       * Sell the reserved code.
       */
      const codeUpdate =
        db.prepare(`
          UPDATE codes
          SET
            status='sold',
            order_id=?,
            reserved_until=NULL
          WHERE
            id=?
            AND (
              status='reserved'
              OR status='available'
            )
        `).run(
          existing.id,
          code.id
        );


      if(
        codeUpdate.changes !== 1
      ){

        throw new Error(
          'Gagal mengunci Redeem Code'
        );

      }


      /*
       * Finish order.
       */
      db.prepare(`
        UPDATE orders
        SET
          payment_status='paid',
          fulfillment_status='processing',
          redeem_code=?,
          midtrans_transaction_id=?,
          paid_at=CURRENT_TIMESTAMP,
          delivery_note='Pembayaran terverifikasi. Kode sedang diproses untuk dikirim.'
        WHERE id=?
      `).run(
        code.redeem_code,
        notification.transaction_id || null,
        existing.id
      );


      return {
        ok:true,
        redeem_code:
          code.redeem_code
      };

    }
  );


/* =========================================================
   CODE DELIVERY
========================================================= */

async function deliverCode(orderId){
  const order = db.prepare(`SELECT o.*, p.name AS product_name FROM orders o JOIN products p ON p.id=o.product_id WHERE o.id=?`).get(orderId);
  if (!order || order.fulfillment_status !== 'processing' || !order.redeem_code) return;
  let delivered = false; let note = '';

  if (order.delivery_channel === 'email' && process.env.RESEND_API_KEY && process.env.EMAIL_FROM) {
    try {
      const r = await fetch('https://api.resend.com/emails', {
        method:'POST', headers:{Authorization:`Bearer ${process.env.RESEND_API_KEY}`,'Content-Type':'application/json'},
        body:JSON.stringify({from:process.env.EMAIL_FROM,to:[order.customer_email],subject:`Redeem Code Top up Clouds - ${order.product_name}`,html:`<div style="font-family:Arial,sans-serif"><h2>Top up Clouds</h2><p>Pembayaran pesanan <b>${order.id}</b> berhasil.</p><p>Produk: ${order.product_name}</p><p style="font-size:22px;font-weight:bold;letter-spacing:2px">${order.redeem_code}</p><p>Jika email ini tidak ditemukan, kode tetap bisa dilihat di menu Pesanan.</p></div>`})
      });
      delivered = r.ok; if (!r.ok) note=`Email gagal dikirim (${r.status}). Kode tetap tersedia di Pesanan.`;
    } catch { note='Email gagal dikirim. Kode tetap tersedia di Pesanan.'; }
  }

  if (order.delivery_channel === 'phone' && process.env.FONNTE_TOKEN) {
    try {
      const body=new URLSearchParams({target:order.customer_phone,message:`Top up Clouds\nPesanan ${order.id} berhasil.\nProduk: ${order.product_name}\nRedeem Code: ${order.redeem_code}`});
      const r=await fetch('https://api.fonnte.com/send',{method:'POST',headers:{Authorization:process.env.FONNTE_TOKEN,'Content-Type':'application/x-www-form-urlencoded'},body});
      delivered=r.ok; if(!r.ok) note=`Pengiriman ke nomor gagal (${r.status}). Kode tetap tersedia di Pesanan.`;
    } catch { note='Pengiriman ke nomor gagal. Kode tetap tersedia di Pesanan.'; }
  }

  if (!delivered && !note) note=order.delivery_channel==='email' ? 'Email delivery belum dikonfigurasi. Kode tetap tersedia di menu Pesanan.' : 'Pengiriman nomor belum dikonfigurasi. Kode tetap tersedia di menu Pesanan.';
  db.prepare(`UPDATE orders SET fulfillment_status='completed', delivery_note=? WHERE id=?`).run(note || 'Kode berhasil dikirim.',orderId);
}


/* =========================================================
   MIDTRANS NOTIFICATION
========================================================= */

app.post(
  '/api/midtrans/notification',
  (req,res) => {

    try{

      const notification =
        req.body || {};


      /*
       * IMPORTANT:
       * Always verify Midtrans signature.
       */
      if(
        !verifyMidtransSignature(
          notification
        )
      ){

        return res
          .status(403)
          .send(
            'invalid signature'
          );

      }


      const order =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE id=?
        `).get(
          notification.order_id
        );


      /*
       * Returning OK for an unknown
       * order prevents endless retries.
       */
      if(!order){

        return res.send('OK');

      }


      const transactionStatus =
        String(
          notification.transaction_status ||
          ''
        ).toLowerCase();


      const fraudStatus =
        String(
          notification.fraud_status ||
          ''
        ).toLowerCase();


      /*
       * Capture/settlement.
       */
      const paid =
        (
          transactionStatus ===
          'settlement'
        ) ||
        (
          transactionStatus ===
          'capture' &&
          (
            !fraudStatus ||
            fraudStatus ===
            'accept'
          )
        );


      if(paid){

        const paidResult = markPaid(notification, order);
        if (paidResult?.ok && !paidResult?.alreadyPaid) {
          deliverCode(order.id).catch(err => console.error('Delivery error:', err));
        }

      }

      /*
       * Failed / expired.
       */
      else if([
        'expire',
        'cancel',
        'deny',
        'failure'
      ].includes(
        transactionStatus
      )){

        db.transaction(() => {

          db.prepare(`
            UPDATE orders
            SET
              payment_status=?,
              fulfillment_status='failed',
              midtrans_transaction_id=?
            WHERE id=?
              AND payment_status != 'paid'
          `).run(
            transactionStatus,
            notification.transaction_id || null,
            order.id
          );


          db.prepare(`
            UPDATE codes
            SET
              status='available',
              order_id=NULL,
              reserved_until=NULL
            WHERE
              id=?
              AND status='reserved'
          `).run(
            order.code_id
          );

        })();

      }

      /*
       * Pending or other state.
       */
      else{

        db.prepare(`
          UPDATE orders
          SET
            payment_status=?,
            midtrans_transaction_id=?
          WHERE
            id=?
            AND payment_status != 'paid'
        `).run(
          transactionStatus ||
            'pending',

          notification.transaction_id ||
            null,

          order.id
        );

      }


      res.send('OK');

    }catch(error){

      console.error(
        'Midtrans notification error:',
        error
      );

      /*
       * Return 500 so Midtrans can retry
       * when our server actually failed.
       */
      res
        .status(500)
        .send('notification processing failed');

    }

  }
);


/* =========================================================
   USER ORDERS
========================================================= */

app.get(
  '/api/orders',
  auth,
  (req,res) => {

    try{

      const rows =
        db.prepare(`
          SELECT
            o.id,
            o.amount,
            o.payment_status,
            o.redeem_code,
            o.created_at,
            o.paid_at,
            o.customer_email,
            o.customer_phone,
            o.delivery_channel,
            o.fulfillment_status,
            o.delivery_note,
            p.provider,
            p.name,
            p.duration_days
          FROM orders o
          JOIN products p
            ON p.id=o.product_id
          WHERE o.user_id=?
          ORDER BY
            o.created_at DESC
        `).all(
          req.userId
        );

      res.json(rows);

    }catch(error){

      console.error(
        'Orders error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal mengambil pesanan'
      );

    }

  }
);


/* =========================================================
   SINGLE ORDER
========================================================= */

app.get(
  '/api/orders/:id',
  auth,
  (req,res) => {

    try{

      const orderId =
        String(
          req.params.id || ''
        ).trim();

      if(!orderId){

        return jsonError(
          res,
          400,
          'Order ID tidak valid'
        );

      }


      const order =
        db.prepare(`
          SELECT
            o.id,
            o.amount,
            o.payment_status,
            o.redeem_code,
            o.created_at,
            o.paid_at,
            o.customer_email,
            o.customer_phone,
            o.delivery_channel,
            o.fulfillment_status,
            o.delivery_note,
            p.provider,
            p.name,
            p.duration_days
          FROM orders o
          JOIN products p
            ON p.id=o.product_id
          WHERE
            o.id=?
            AND o.user_id=?
        `).get(
          orderId,
          req.userId
        );


      if(!order){

        return jsonError(
          res,
          404,
          'Order tidak ditemukan'
        );

      }


      res.json(order);

    }catch(error){

      console.error(
        'Single order error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal mengambil order'
      );

    }

  }
);


/* =========================================================
   ADMIN PRODUCTS - CREATE
========================================================= */

app.post(
  '/api/admin/products',
  admin,
  (req,res) => {

    try{

      const provider =
        String(
          req.body?.provider || ''
        ).trim();

      const name =
        String(
          req.body?.name || ''
        ).trim();

      const duration =
        Number(
          req.body?.duration_days
        );

      const price =
        Number(
          req.body?.price
        );


      if(
        !provider ||
        !name ||
        !validDurations.includes(
          duration
        ) ||
        !Number.isInteger(price) ||
        price < 1
      ){

        return jsonError(
          res,
          400,
          'Provider, nama, durasi 1/3/7/30 dan harga valid wajib diisi'
        );

      }


      const result =
        db.prepare(`
          INSERT INTO products(
            provider,
            name,
            duration_days,
            price,
            active
          )
          VALUES(?,?,?,?,1)
        `).run(
          provider,
          name,
          duration,
          price
        );


      res.json({
        ok:true,
        id:
          result.lastInsertRowid
      });

    }catch(error){

      console.error(
        'Admin create product error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal membuat produk'
      );

    }

  }
);


/* =========================================================
   ADMIN PRODUCTS - LIST
========================================================= */

app.get(
  '/api/admin/products',
  admin,
  (req,res) => {

    try{

      const rows =
        db.prepare(`
          SELECT *
          FROM products
          ORDER BY id DESC
        `).all();

      res.json(rows);

    }catch(error){

      console.error(
        'Admin products error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal mengambil produk admin'
      );

    }

  }
);


/* =========================================================
   ADMIN PRODUCTS - UPDATE
========================================================= */

app.patch(
  '/api/admin/products/:id',
  admin,
  (req,res) => {

    try{

      const id =
        Number(
          req.params.id
        );

      if(
        !Number.isInteger(id) ||
        id <= 0
      ){

        return jsonError(
          res,
          400,
          'ID produk tidak valid'
        );

      }


      const allowed = [
        'provider',
        'name',
        'duration_days',
        'price',
        'active'
      ];

      const fields = [];
      const values = [];


      for(
        const key of allowed
      ){

        if(
          req.body?.[key] ===
          undefined
        ){

          continue;

        }


        let value =
          req.body[key];


        if(
          key ===
          'provider'
        ){

          value =
            String(
              value || ''
            ).trim();

          if(!value){

            return jsonError(
              res,
              400,
              'Provider tidak boleh kosong'
            );

          }

        }


        if(
          key ===
          'name'
        ){

          value =
            String(
              value || ''
            ).trim();

          if(!value){

            return jsonError(
              res,
              400,
              'Nama produk tidak boleh kosong'
            );

          }

        }


        if(
          key ===
          'duration_days'
        ){

          value =
            Number(value);

          if(
            !validDurations.includes(
              value
            )
          ){

            return jsonError(
              res,
              400,
              'Durasi hanya 1, 3, 7 atau 30 hari'
            );

          }

        }


        if(
          key ===
          'price'
        ){

          value =
            Number(value);

          if(
            !Number.isInteger(value) ||
            value < 1
          ){

            return jsonError(
              res,
              400,
              'Harga tidak valid'
            );

          }

        }


        if(
          key ===
          'active'
        ){

          value =
            value ? 1 : 0;

        }


        fields.push(
          `${key}=?`
        );

        values.push(
          value
        );

      }


      if(!fields.length){

        return jsonError(
          res,
          400,
          'Tidak ada perubahan'
        );

      }


      values.push(id);


      const result =
        db.prepare(`
          UPDATE products
          SET ${fields.join(',')}
          WHERE id=?
        `).run(
          ...values
        );


      if(
        result.changes !== 1
      ){

        return jsonError(
          res,
          404,
          'Produk tidak ditemukan'
        );

      }


      res.json({
        ok:true
      });

    }catch(error){

      console.error(
        'Admin update product error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal memperbarui produk'
      );

    }

  }
);


/* =========================================================
   ADMIN PRODUCTS - DELETE
   Menghapus produk + stok kode yang masih terkait.
   Produk yang sudah pernah dipakai order tidak dihapus agar
   riwayat transaksi tetap aman.
========================================================= */

app.delete(
  '/api/admin/products/:id',
  admin,
  (req,res) => {

    try{

      const id = Number(req.params.id);

      if(!Number.isInteger(id) || id <= 0){
        return jsonError(res,400,'ID produk tidak valid');
      }

      const product = db.prepare(`
        SELECT id, provider, name
        FROM products
        WHERE id=?
      `).get(id);

      if(!product){
        return jsonError(res,404,'Produk tidak ditemukan');
      }

      const orderCount = db.prepare(`
        SELECT COUNT(*) AS count
        FROM orders
        WHERE product_id=?
      `).get(id).count;

      if(Number(orderCount) > 0){
        return jsonError(
          res,
          409,
          'Produk tidak bisa dihapus karena sudah memiliki riwayat order. Nonaktifkan produk saja.'
        );
      }

      const transaction = db.transaction(() => {
        db.prepare('DELETE FROM codes WHERE product_id=?').run(id);
        db.prepare('DELETE FROM products WHERE id=?').run(id);
      });

      transaction();

      res.json({
        ok:true,
        deleted_id:id,
        message:'Produk berhasil dihapus'
      });

    }catch(error){

      console.error('Admin delete product error:',error);

      jsonError(
        res,
        500,
        'Gagal menghapus produk'
      );

    }

  }
);


/* =========================================================
   ADMIN CODES - ADD
========================================================= */

app.post(
  '/api/admin/codes',
  admin,
  (req,res) => {

    try{

      const productId =
        Number(
          req.body?.product_id
        );


      const codes =
        Array.isArray(
          req.body?.codes
        )
          ? req.body.codes
              .map(
                code =>
                  String(
                    code || ''
                  ).trim()
              )
              .filter(Boolean)
          : [];


      if(
        !Number.isInteger(
          productId
        ) ||
        productId <= 0
      ){

        return jsonError(
          res,
          400,
          'product_id tidak valid'
        );

      }


      if(!codes.length){

        return jsonError(
          res,
          400,
          'codes wajib diisi'
        );

      }


      if(codes.length > 1000){

        return jsonError(
          res,
          400,
          'Maksimal 1000 kode sekali upload'
        );

      }


      const product =
        db.prepare(`
          SELECT id
          FROM products
          WHERE id=?
        `).get(
          productId
        );


      if(!product){

        return jsonError(
          res,
          404,
          'Produk tidak ditemukan'
        );

      }


      /*
       * Remove duplicates from
       * the submitted list itself.
       */
      const uniqueCodes =
        [
          ...new Set(codes)
        ];


      const statement =
        db.prepare(`
          INSERT INTO codes(
            product_id,
            redeem_code,
            status
          )
          VALUES(?,?,'available')
        `);


      let inserted = 0;
      let skipped = 0;


      const transaction =
        db.transaction(
          list => {

            for(
              const code of list
            ){

              try{

                statement.run(
                  productId,
                  code
                );

                inserted++;

              }catch(error){

                /*
                 * UNIQUE redeem_code:
                 * skip duplicates instead of
                 * crashing the entire upload.
                 */
                if(
                  String(
                    error.message
                  ).includes(
                    'UNIQUE'
                  )
                ){

                  skipped++;

                }else{

                  throw error;

                }

              }

            }

          }
        );


      transaction(
        uniqueCodes
      );


      res.json({

        ok:true,

        count:
          inserted,

        skipped,

        total:
          uniqueCodes.length

      });

    }catch(error){

      console.error(
        'Admin codes error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal menambahkan Redeem Code'
      );

    }

  }
);


/* =========================================================
   ADMIN CODES - LIST
========================================================= */

app.get(
  '/api/admin/codes',
  admin,
  (req,res) => {

    try{

      const rows =
        db.prepare(`
          SELECT
            c.id,
            c.product_id,
            p.provider,
            p.name,
            p.duration_days,
            c.redeem_code,
            c.status,
            c.order_id,
            c.reserved_until
          FROM codes c
          JOIN products p
            ON p.id=c.product_id
          ORDER BY c.id DESC
          LIMIT 500
        `).all();

      res.json(rows);

    }catch(error){

      console.error(
        'Admin code list error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal mengambil Redeem Code'
      );

    }

  }
);


/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  '/api/admin/orders',
  admin,
  (req,res) => {

    try{

      const rows =
        db.prepare(`
          SELECT
            o.*,
            u.email,
            p.provider,
            p.name,
            p.duration_days
          FROM orders o
          LEFT JOIN users u
            ON u.id=o.user_id
          JOIN products p
            ON p.id=o.product_id
          ORDER BY
            o.created_at DESC
          LIMIT 500
        `).all();

      res.json(rows);

    }catch(error){

      console.error(
        'Admin orders error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal mengambil order admin'
      );

    }

  }
);


/* =========================================================
   ADMIN STATS
========================================================= */

app.get(
  '/api/admin/stats',
  admin,
  (req,res) => {

    try{

      const users =
        db.prepare(
          'SELECT COUNT(*) AS count FROM users'
        ).get().count;

      const products =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM products
          WHERE active=1
        `).get().count;

      const availableCodes =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM codes
          WHERE status='available'
        `).get().count;

      const paidOrders =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM orders
          WHERE payment_status='paid'
        `).get().count;

      const pendingOrders =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM orders
          WHERE payment_status='pending'
        `).get().count;


      res.json({

        users:
          Number(users),

        products:
          Number(products),

        available_codes:
          Number(availableCodes),

        paid_orders:
          Number(paidOrders),

        pending_orders:
          Number(pendingOrders)

      });

    }catch(error){

      console.error(
        'Admin stats error:',
        error
      );

      jsonError(
        res,
        500,
        'Gagal mengambil statistik'
      );

    }

  }
);


/* =========================================================
   404 API HANDLER
========================================================= */

app.use(
  '/api',
  (req,res) => {

    jsonError(
      res,
      404,
      'API endpoint tidak ditemukan'
    );

  }
);


/* =========================================================
   FRONTEND ROUTES
========================================================= */

app.get(
  '/admin',
  (req,res) => {

    res.sendFile(
      path.join(
        __dirname,
        'public',
        'admin.html'
      )
    );

  }
);


/*
 * Express 5 compatible SPA fallback.
 *
 * This avoids the old:
 * app.get('/{*splat}', ...)
 * problem on some Express versions.
 */
app.use((req,res,next) => {
  if (req.method !== 'GET' || req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'), err => {
    if (err) next(err);
  });
});


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      'Unhandled server error:',
      error
    );

    if(res.headersSent){

      return next(error);

    }

    jsonError(
      res,
      500,
      'Internal server error'
    );

  }
);


/* =========================================================
   START SERVER
========================================================= */

console.log('Startup check:', {
  publicIndex: fs.existsSync(path.join(__dirname,'public','index.html')),
  publicAdmin: fs.existsSync(path.join(__dirname,'public','admin.html')),
  dbPath: DB_PATH,
  midtransProduction: MIDTRANS_IS_PRODUCTION,
  adminKeyConfigured: Boolean(process.env.ADMIN_KEY)
});

app.listen(
  PORT,
  () => {

    console.log(
      `Top up Clouds running on port ${PORT}`
    );

    console.log(
      `Midtrans mode: ${
        MIDTRANS_IS_PRODUCTION
          ? 'PRODUCTION'
          : 'SANDBOX'
      }`
    );

    console.log(
      `Midtrans Client Key: ${
        MIDTRANS_CLIENT_KEY
          ? 'configured'
          : 'MISSING'
      }`
    );

    console.log(
      `Midtrans Server Key: ${
        MIDTRANS_SERVER_KEY
          ? 'configured'
          : 'MISSING'
      }`
    );

    console.log(
      `Admin Key: ${
        process.env.ADMIN_KEY
          ? 'configured'
          : 'MISSING'
      }`
    );

  }
);