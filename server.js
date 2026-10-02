import express from 'express';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import midtransClient from 'midtrans-client';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

/* =========================================================
   BASIC CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 3000);
const DB_PATH = String(process.env.DB_PATH || path.join(__dirname, 'data.db')).trim();
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
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
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

  const bearer =
    authorization
      .replace(
        /^Bearer\s+/i,
        ''
      )
      .trim();

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
          'SELECT id FROM users WHERE email=?'
        ).get(email);

      if(existing){

        return jsonError(
          res,
          409,
          'Email sudah terdaftar'
        );

      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        db.prepare(`
          INSERT INTO users(
            email,
            password_hash
          )
          VALUES(?,?)
        `).run(
          email,
          passwordHash
        );

      const token =
        newToken();

      const expiresAt =
        Date.now() +
        SESSION_DAYS *
        24 *
        60 *
        60 *
        1000;

      db.prepare(`
        INSERT INTO sessions(
          token_hash,
          user_id,
          expires_at
        )
        VALUES(?,?,?)
      `).run(
        hashToken(token),
        result.lastInsertRowid,
        expiresAt
      );

      res.json({
        ok:true,
        token,
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
          WHERE email=?
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

      const token =
        newToken();

      const expiresAt =
        Date.now() +
        SESSION_DAYS *
        24 *
        60 *
        60 *
        1000;

      db.prepare(`
        INSERT INTO sessions(
          token_hash,
          user_id,
          expires_at
        )
        VALUES(?,?,?)
      `).run(
        hashToken(token),
        user.id,
        expiresAt
      );

      res.json({
        ok:true,
        token,
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
          id,
          user_id,
          product_id,
          code_id,
          amount,
          payment_status
        )
        VALUES(?,?,?,?,?,'pending')
      `).run(
        orderId,
        req.userId,
        product.id,
        reserved.id,
        product.price
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
          redeem_code=?,
          midtrans_transaction_id=?,
          paid_at=CURRENT_TIMESTAMP
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

        markPaid(
          notification,
          order
        );

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
app.get(
  '/{*splat}',
  (req,res) => {

    res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    );

  }
);


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