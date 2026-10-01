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
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const db = new Database(path.join(__dirname, 'data.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,provider TEXT NOT NULL,name TEXT NOT NULL,duration_days INTEGER NOT NULL,price INTEGER NOT NULL CHECK(price>=0),active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS codes(id INTEGER PRIMARY KEY AUTOINCREMENT,product_id INTEGER NOT NULL,redeem_code TEXT UNIQUE NOT NULL,status TEXT DEFAULT 'available',order_id TEXT,reserved_until INTEGER);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,user_id INTEGER,product_id INTEGER NOT NULL,code_id INTEGER,amount INTEGER NOT NULL,payment_status TEXT DEFAULT 'pending',redeem_code TEXT,midtrans_transaction_id TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,paid_at TEXT);
CREATE INDEX IF NOT EXISTS idx_codes_stock ON codes(product_id,status);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id,created_at);
`);

const snap = new midtransClient.Snap({
  isProduction: process.env.MIDTRANS_IS_PRODUCTION === 'true',
  serverKey: process.env.MIDTRANS_SERVER_KEY || '',
  clientKey: process.env.MIDTRANS_CLIENT_KEY || ''
});

const hashToken = t => crypto.createHash('sha256').update(t).digest('hex');
const newToken = () => crypto.randomBytes(32).toString('hex');
const money = n => Number(n);
const auth = (req, res, next) => {
  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (!bearer) return res.status(401).json({ error: 'Login required' });
  const s = db.prepare('SELECT * FROM sessions WHERE token_hash=? AND expires_at>?').get(hashToken(bearer), Date.now());
  if (!s) return res.status(401).json({ error: 'Sesi login berakhir' });
  req.userId = s.user_id; req.rawToken = bearer; next();
};
const admin = (req, res, next) => {
  if (!process.env.ADMIN_KEY || req.headers['x-admin-key'] !== process.env.ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
};
const safeEmail = e => String(e || '').trim().toLowerCase();

app.get('/api/config', (req,res) => res.json({
  clientKey: process.env.MIDTRANS_CLIENT_KEY || '',
  production: process.env.MIDTRANS_IS_PRODUCTION === 'true'
}));

app.get('/api/products', (req,res) => {
  const rows = db.prepare('SELECT id,provider,name,duration_days,price,active FROM products WHERE active=1 ORDER BY provider,name,duration_days').all();
  res.json(rows);
});

app.post('/api/register', async (req,res) => {
  try {
    const email = safeEmail(req.body.email), password = String(req.body.password || '');
    if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 8) return res.status(400).json({ error:'Email valid dan password minimal 8 karakter wajib diisi' });
    const hash = await bcrypt.hash(password, 12);
    const r = db.prepare('INSERT INTO users(email,password_hash) VALUES(?,?)').run(email,hash);
    const token = newToken();
    db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hashToken(token),r.lastInsertRowid,Date.now()+1000*60*60*24*30);
    res.json({ ok:true, token, email });
  } catch(e) { res.status(400).json({ error:'Email sudah terdaftar atau data tidak valid' }); }
});

app.post('/api/login', async (req,res) => {
  const email = safeEmail(req.body.email), password = String(req.body.password || '');
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({ error:'Email atau password salah' });
  const token = newToken();
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hashToken(token),u.id,Date.now()+1000*60*60*24*30);
  res.json({ token, email:u.email });
});

app.post('/api/logout',auth,(req,res)=>{ db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(req.rawToken)); res.json({ok:true}); });

function reserveCode(productId, orderId) {
  const now = Date.now(), until = now + 15*60*1000;
  const tx = db.transaction(() => {
    db.prepare("UPDATE codes SET status='available',order_id=NULL,reserved_until=NULL WHERE product_id=? AND status='reserved' AND reserved_until<=?").run(productId, now);
    const code = db.prepare("SELECT * FROM codes WHERE product_id=? AND status='available' ORDER BY id LIMIT 1").get(productId);
    if (!code) return null;
    const changed = db.prepare("UPDATE codes SET status='reserved',order_id=?,reserved_until=? WHERE id=? AND status='available'").run(orderId,until,code.id);
    return changed.changes ? {...code,reserved_until:until} : null;
  });
  return tx();
}

app.post('/api/orders',auth,async(req,res) => {
  const product = db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(Number(req.body.productId));
  if (!product) return res.status(404).json({error:'Produk tidak ditemukan'});
  if (!Number.isInteger(product.price) || product.price < 1) return res.status(400).json({error:'Harga produk belum siap'});
  const email = db.prepare('SELECT email FROM users WHERE id=?').get(req.userId)?.email;
  const orderId = 'TC-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const reserved = reserveCode(product.id,orderId);
  if (!reserved) return res.status(409).json({error:'Stok Redeem Code habis'});
  try {
    db.prepare('INSERT INTO orders(id,user_id,product_id,code_id,amount) VALUES(?,?,?,?,?)').run(orderId,req.userId,product.id,reserved.id,product.price);
    const transaction = await snap.createTransaction({
      transaction_details:{order_id:orderId,gross_amount:money(product.price)},
      customer_details:{email}
    });
    res.json({orderId,token:transaction.token,redirect_url:transaction.redirect_url});
  } catch(e) {
    db.transaction(()=>{
      db.prepare("UPDATE codes SET status='available',order_id=NULL,reserved_until=NULL WHERE id=? AND status='reserved'").run(reserved.id);
      db.prepare('DELETE FROM orders WHERE id=?').run(orderId);
    })();
    console.error('Midtrans create error',e?.message || e);
    res.status(502).json({error:'Payment gateway gagal membuat transaksi'});
  }
});

const markPaid = db.transaction((n, order) => {
  const existing = db.prepare('SELECT * FROM orders WHERE id=?').get(order.id);
  if (!existing || existing.payment_status === 'paid') return;
  const code = existing.code_id ? db.prepare('SELECT * FROM codes WHERE id=?').get(existing.code_id) : null;
  if (!code || (code.status !== 'reserved' && code.status !== 'available')) {
    db.prepare('UPDATE orders SET payment_status=?,midtrans_transaction_id=?,paid_at=CURRENT_TIMESTAMP WHERE id=?').run('paid_no_stock',n.transaction_id,order.id);
    return;
  }
  db.prepare("UPDATE codes SET status='sold',order_id=?,reserved_until=NULL WHERE id=? AND (status='reserved' OR status='available')").run(order.id,code.id);
  db.prepare('UPDATE orders SET payment_status=?,redeem_code=?,midtrans_transaction_id=?,paid_at=CURRENT_TIMESTAMP WHERE id=?').run('paid',code.redeem_code,n.transaction_id,order.id);
});

app.post('/api/midtrans/notification',(req,res)=>{
  const n=req.body||{};
  const raw=String(n.order_id||'')+String(n.status_code||'')+String(n.gross_amount||'')+String(process.env.MIDTRANS_SERVER_KEY||'');
  const sig=crypto.createHash('sha512').update(raw).digest('hex');
  if (!n.signature_key || sig !== n.signature_key) return res.status(403).send('invalid signature');
  const order=db.prepare('SELECT * FROM orders WHERE id=?').get(n.order_id);
  if (!order) return res.send('OK');
  const paid=['settlement','capture'].includes(n.transaction_status) && (!n.fraud_status || n.fraud_status==='accept');
  if (paid) markPaid(n,order);
  else if (['expire','cancel','deny','failure'].includes(n.transaction_status)) {
    db.transaction(()=>{
      db.prepare('UPDATE orders SET payment_status=?,midtrans_transaction_id=? WHERE id=?').run(n.transaction_status,n.transaction_id,order.id);
      db.prepare("UPDATE codes SET status='available',order_id=NULL,reserved_until=NULL WHERE id=? AND status='reserved'").run(order.code_id);
    })();
  } else db.prepare('UPDATE orders SET payment_status=?,midtrans_transaction_id=? WHERE id=?').run(n.transaction_status||'pending',n.transaction_id,order.id);
  res.send('OK');
});

app.get('/api/orders',auth,(req,res)=>res.json(db.prepare(`SELECT o.id,o.amount,o.payment_status,o.redeem_code,o.created_at,o.paid_at,p.provider,p.name,p.duration_days FROM orders o JOIN products p ON p.id=o.product_id WHERE o.user_id=? ORDER BY o.created_at DESC`).all(req.userId)));

app.get('/api/orders/:id',auth,(req,res)=>{
  const o=db.prepare(`SELECT o.id,o.amount,o.payment_status,o.redeem_code,o.created_at,o.paid_at,p.provider,p.name,p.duration_days FROM orders o JOIN products p ON p.id=o.product_id WHERE o.id=? AND o.user_id=?`).get(req.params.id,req.userId);
  if(!o)return res.status(404).json({error:'Order tidak ditemukan'}); res.json(o);
});

app.post('/api/admin/products',admin,(req,res)=>{
  const provider=String(req.body.provider||'').trim(),name=String(req.body.name||'').trim(),duration=Number(req.body.duration_days),price=Number(req.body.price);
  if(!provider||!name||![1,3,7,30].includes(duration)||!Number.isInteger(price)||price<1)return res.status(400).json({error:'Provider, nama, durasi 1/3/7/30 dan harga valid wajib diisi'});
  const r=db.prepare('INSERT INTO products(provider,name,duration_days,price) VALUES(?,?,?,?)').run(provider,name,duration,price); res.json({id:r.lastInsertRowid});
});
app.get('/api/admin/products',admin,(req,res)=>res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all()));
app.patch('/api/admin/products/:id',admin,(req,res)=>{const fields=[],values=[];for(const k of ['provider','name','duration_days','price','active'])if(req.body[k]!==undefined){fields.push(`${k}=?`);values.push(req.body[k]);}if(!fields.length)return res.status(400).json({error:'Tidak ada perubahan'});values.push(req.params.id);db.prepare(`UPDATE products SET ${fields.join(',')} WHERE id=?`).run(...values);res.json({ok:true});});
app.post('/api/admin/codes',admin,(req,res)=>{
  const productId=Number(req.body.product_id), codes=Array.isArray(req.body.codes)?req.body.codes.map(x=>String(x).trim()).filter(Boolean):[];
  if(!productId||!codes.length)return res.status(400).json({error:'product_id dan codes wajib diisi'});
  const stmt=db.prepare('INSERT INTO codes(product_id,redeem_code) VALUES(?,?)'); let count=0;
  const tx=db.transaction(arr=>{for(const c of arr){try{stmt.run(productId,c);count++;}catch{}}});tx(codes);res.json({ok:true,count});
});
app.get('/api/admin/codes',admin,(req,res)=>res.json(db.prepare('SELECT c.id,c.product_id,p.provider,p.name,p.duration_days,c.redeem_code,c.status,c.order_id FROM codes c JOIN products p ON p.id=c.product_id ORDER BY c.id DESC LIMIT 500').all()));
app.get('/api/admin/orders',admin,(req,res)=>res.json(db.prepare('SELECT o.*,u.email,p.provider,p.name,p.duration_days FROM orders o LEFT JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id ORDER BY o.created_at DESC LIMIT 500').all()));
app.get('/api/admin/stats',admin,(req,res)=>res.json({users:db.prepare('SELECT COUNT(*) c FROM users').get().c,products:db.prepare('SELECT COUNT(*) c FROM products WHERE active=1').get().c,available_codes:db.prepare("SELECT COUNT(*) c FROM codes WHERE status='available'").get().c,paid_orders:db.prepare("SELECT COUNT(*) c FROM orders WHERE payment_status='paid'").get().c}));

app.get('/health',(req,res)=>res.json({ok:true,service:'top-up-clouds'}));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/{*splat}',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`Top up Clouds running on http://localhost:${port}`));
