require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const Stripe       = require('stripe');
const { Pool }     = require('pg');
const rateLimit    = require('express-rate-limit');

const app    = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_xxx');
const JWT    = process.env.JWT_SECRET || 'secret_change_me';

// ── PostgreSQL ────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  connectionTimeoutMillis: 8000,
});
const db = {
  one: async (t,p) => { const r = await pool.query(t,p); return r.rows[0]||null; },
  all: async (t,p) => { const r = await pool.query(t,p); return r.rows; },
  run: (t,p)       => pool.query(t,p),
};

// ── Init DB ───────────────────────────────────────────────
let dbReady = false;
async function initDB() {
  if (dbReady) return;
  const sqls = [
    `CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, avatar TEXT DEFAULT '', is_premium INT DEFAULT 0, premium_until TEXT, stripe_customer_id TEXT, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS watchlist (id SERIAL PRIMARY KEY, user_id INT NOT NULL, anime_id TEXT NOT NULL, title TEXT NOT NULL, img TEXT DEFAULT '', lang TEXT DEFAULT 'VOSTFR', ep_progress INT DEFAULT 0, status TEXT DEFAULT 'watching', added_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id,anime_id))`,
    `CREATE TABLE IF NOT EXISTS animelist (id SERIAL PRIMARY KEY, user_id INT NOT NULL, anime_id TEXT NOT NULL, title TEXT NOT NULL, img TEXT DEFAULT '', lang TEXT DEFAULT 'VOSTFR', status TEXT DEFAULT 'want', score INT DEFAULT 0, added_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id,anime_id))`,
    `CREATE TABLE IF NOT EXISTS comments (id SERIAL PRIMARY KEY, anime_id TEXT NOT NULL, user_id INT NOT NULL, username TEXT NOT NULL, content TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS comment_likes (user_id INT NOT NULL, comment_id INT NOT NULL, PRIMARY KEY(user_id,comment_id))`,
    `CREATE TABLE IF NOT EXISTS chat_messages (id SERIAL PRIMARY KEY, user_id INT NOT NULL, username TEXT NOT NULL, content TEXT NOT NULL, room TEXT DEFAULT 'general', created_at TIMESTAMP DEFAULT NOW())`,
  ];
  for (const sql of sqls) await pool.query(sql);
  dbReady = true;
}

// ── Middleware ────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// Init DB sur chaque requête (serverless = pas de persistance)
app.use(async (req, res, next) => {
  try { await initDB(); } catch(e) { console.error('initDB:', e.message); }
  next();
});

app.use('/api/auth', rateLimit({ windowMs: 15*60*1000, max: 50, standardHeaders: true, legacyHeaders: false }));

// ── Auth helpers ──────────────────────────────────────────
const san = u => ({ id:u.id, username:u.username, email:u.email, avatar:u.avatar||'', is_premium:u.is_premium||0, premium_until:u.premium_until });
function auth(req, res, next) {
  const t = req.headers.authorization?.split(' ')[1];
  if (!t) return res.status(401).json({ error:'Token requis' });
  try { req.user = jwt.verify(t, JWT); next(); }
  catch { res.status(401).json({ error:'Token invalide' }); }
}

// ── Routes ────────────────────────────────────────────────
app.get('/', (req,res) => res.json({ name:'AniStream API', version:'2.0', status:'ok' }));

app.get('/api/health', async (req,res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status:'ok', db:'connected', vars:{ db:!!process.env.DATABASE_URL, jwt:!!process.env.JWT_SECRET } });
  } catch(e) {
    res.status(500).json({ status:'error', error:e.message });
  }
});

// AUTH
app.post('/api/auth/register', async (req,res) => {
  const { username, email, password } = req.body||{};
  if (!username||!email||!password) return res.status(400).json({ error:'Champs manquants' });
  if (password.length<6) return res.status(400).json({ error:'Mot de passe trop court (6 min)' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const u = await db.one('INSERT INTO users(username,email,password) VALUES($1,$2,$3) RETURNING *',[username,email,hash]);
    const token = jwt.sign({ id:u.id, username:u.username, email:u.email, is_premium:0 }, JWT, { expiresIn:'30d' });
    res.json({ token, user:san(u) });
  } catch(e) {
    if (e.code==='23505') return res.status(409).json({ error:'Email ou pseudo déjà utilisé' });
    res.status(500).json({ error:e.message });
  }
});

app.post('/api/auth/login', async (req,res) => {
  const { email, password } = req.body||{};
  if (!email||!password) return res.status(400).json({ error:'Champs manquants' });
  const u = await db.one('SELECT * FROM users WHERE email=$1',[email]);
  if (!u||!await bcrypt.compare(password,u.password)) return res.status(401).json({ error:'Email ou mot de passe incorrect' });
  if (u.premium_until && new Date(u.premium_until)<new Date()) { await db.run('UPDATE users SET is_premium=0 WHERE id=$1',[u.id]); u.is_premium=0; }
  const token = jwt.sign({ id:u.id, username:u.username, email:u.email, is_premium:u.is_premium }, JWT, { expiresIn:'30d' });
  res.json({ token, user:san(u) });
});

app.get('/api/auth/me', auth, async (req,res) => {
  const u = await db.one('SELECT * FROM users WHERE id=$1',[req.user.id]);
  res.json({ user: u ? san(u) : null });
});

// PREMIUM
app.post('/api/premium/checkout', auth, async (req,res) => {
  try {
    const u = await db.one('SELECT * FROM users WHERE id=$1',[req.user.id]);
    let cid = u.stripe_customer_id;
    if (!cid) {
      const c = await stripe.customers.create({ email:u.email, name:u.username });
      cid = c.id;
      await db.run('UPDATE users SET stripe_customer_id=$1 WHERE id=$2',[cid,u.id]);
    }
    const sess = await stripe.checkout.sessions.create({
      customer:cid, mode:'subscription',
      line_items:[{ price:process.env.STRIPE_PRICE_ID, quantity:1 }],
      success_url:`${process.env.FRONTEND_URL||'https://anistreamax.vercel.app'}?premium=success`,
      cancel_url:`${process.env.FRONTEND_URL||'https://anistreamax.vercel.app'}?premium=cancel`,
      metadata:{ user_id:String(u.id) },
    });
    res.json({ url:sess.url });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/premium/activate-test', auth, async (req,res) => {
  const until = new Date(); until.setDate(until.getDate()+30);
  await db.run('UPDATE users SET is_premium=1,premium_until=$1 WHERE id=$2',[until.toISOString(),req.user.id]);
  res.json({ success:true, premium_until:until.toISOString() });
});

app.post('/api/premium/webhook', express.raw({type:'application/json'}), async (req,res) => {
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET); }
  catch(e) { return res.status(400).send('Webhook Error: '+e.message); }
  const until = new Date(); until.setDate(until.getDate()+30);
  if (event.type==='checkout.session.completed') {
    await db.run('UPDATE users SET is_premium=1,premium_until=$1 WHERE id=$2',[until.toISOString(),parseInt(event.data.object.metadata.user_id)]);
  }
  res.json({ received:true });
});

// WATCHLIST
app.get('/api/watchlist', auth, async (req,res) => res.json(await db.all('SELECT * FROM watchlist WHERE user_id=$1 ORDER BY added_at DESC',[req.user.id])));
app.post('/api/watchlist', auth, async (req,res) => {
  const {anime_id,title,img,lang,ep_progress,status} = req.body||{};
  if (!anime_id||!title) return res.status(400).json({error:'Champs manquants'});
  await db.run('INSERT INTO watchlist(user_id,anime_id,title,img,lang,ep_progress,status) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(user_id,anime_id) DO UPDATE SET ep_progress=$6,status=$7',
    [req.user.id,anime_id,title,img||'',lang||'VOSTFR',ep_progress||0,status||'watching']);
  res.json({success:true});
});
app.delete('/api/watchlist/:id', auth, async (req,res) => { await db.run('DELETE FROM watchlist WHERE user_id=$1 AND anime_id=$2',[req.user.id,req.params.id]); res.json({success:true}); });

// ANIMELIST
app.get('/api/animelist', auth, async (req,res) => res.json(await db.all('SELECT * FROM animelist WHERE user_id=$1 ORDER BY added_at DESC',[req.user.id])));
app.post('/api/animelist', auth, async (req,res) => {
  const {anime_id,title,img,lang,status,score} = req.body||{};
  if (!anime_id||!title) return res.status(400).json({error:'Champs manquants'});
  await db.run('INSERT INTO animelist(user_id,anime_id,title,img,lang,status,score) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(user_id,anime_id) DO UPDATE SET status=$6,score=$7',
    [req.user.id,anime_id,title,img||'',lang||'VOSTFR',status||'want',score||0]);
  res.json({success:true});
});
app.delete('/api/animelist/:id', auth, async (req,res) => { await db.run('DELETE FROM animelist WHERE user_id=$1 AND anime_id=$2',[req.user.id,req.params.id]); res.json({success:true}); });

// COMMENTS
app.get('/api/comments/:animeId', async (req,res) => {
  const r = await db.all('SELECT c.*,(SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id=c.id) as likes FROM comments c WHERE c.anime_id=$1 ORDER BY c.created_at DESC LIMIT 50',[req.params.animeId]);
  res.json(r);
});
app.post('/api/comments/:animeId', auth, async (req,res) => {
  const {content} = req.body||{};
  if (!content||content.trim().length<2) return res.status(400).json({error:'Trop court'});
  const c = await db.one('INSERT INTO comments(anime_id,user_id,username,content) VALUES($1,$2,$3,$4) RETURNING *',[req.params.animeId,req.user.id,req.user.username,content.trim()]);
  res.json(c);
});
app.post('/api/comments/:id/like', auth, async (req,res) => {
  try { await db.run('INSERT INTO comment_likes(user_id,comment_id) VALUES($1,$2)',[req.user.id,req.params.id]); }
  catch { await db.run('DELETE FROM comment_likes WHERE user_id=$1 AND comment_id=$2',[req.user.id,req.params.id]); }
  const r = await db.one('SELECT COUNT(*) as c FROM comment_likes WHERE comment_id=$1',[req.params.id]);
  res.json({likes:parseInt(r.c)});
});
app.delete('/api/comments/:id', auth, async (req,res) => {
  const c = await db.one('SELECT user_id FROM comments WHERE id=$1',[req.params.id]);
  if (!c) return res.status(404).json({error:'Introuvable'});
  if (c.user_id!==req.user.id) return res.status(403).json({error:'Non autorisé'});
  await db.run('DELETE FROM comments WHERE id=$1',[req.params.id]);
  res.json({success:true});
});

// CHAT (polling — WebSocket non supporté sur Vercel)
app.get('/api/chat/:room', auth, async (req,res) => {
  const msgs = await db.all('SELECT * FROM chat_messages WHERE room=$1 ORDER BY created_at DESC LIMIT 50',[req.params.room||'general']);
  res.json(msgs.reverse());
});
app.post('/api/chat/:room', auth, async (req,res) => {
  const {content} = req.body||{};
  if (!content?.trim()) return res.status(400).json({error:'Message vide'});
  const msg = await db.one('INSERT INTO chat_messages(user_id,username,content,room) VALUES($1,$2,$3,$4) RETURNING *',[req.user.id,req.user.username,content.trim(),req.params.room||'general']);
  res.json(msg);
});

// STATS
app.get('/api/stats', async (req,res) => {
  try {
    const [u,p,c,m] = await Promise.all([
      db.one('SELECT COUNT(*) as c FROM users'),
      db.one('SELECT COUNT(*) as c FROM users WHERE is_premium=1'),
      db.one('SELECT COUNT(*) as c FROM comments'),
      db.one('SELECT COUNT(*) as c FROM chat_messages'),
    ]);
    res.json({ users:+u.c, premium:+p.c, comments:+c.c, messages:+m.c });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── Export pour Vercel (serverless) ───────────────────────
module.exports = app;

// ── Dev local ─────────────────────────────────────────────
if (require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => console.log(`✅ AniStream API — http://localhost:${PORT}`));
}
