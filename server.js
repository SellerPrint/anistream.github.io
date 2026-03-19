// ============================================================
// AniStream Premium Backend — PostgreSQL edition
// Compatible Vercel, Render, Railway, VPS
// ============================================================
require('dotenv').config();
const express     = require('express');
const cors        = require('cors');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const Stripe      = require('stripe');
const { WebSocketServer } = require('ws');
const { Pool }    = require('pg');
const http        = require('http');
const path        = require('path');
const rateLimit   = require('express-rate-limit');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server, path: '/ws' });
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_xxx');

// ── PostgreSQL ────────────────────────────────────────────
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL manquante ! Ajoutez-la dans les variables Vercel.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 10,
});

pool.on('error', (err) => console.error('PostgreSQL pool error:', err.message));

const db = {
  query: (t,p) => pool.query(t,p),
  one:   async (t,p) => { const r = await pool.query(t,p); return r.rows[0]||null; },
  all:   async (t,p) => { const r = await pool.query(t,p); return r.rows; },
  run:   (t,p) => pool.query(t,p),
};

// ── DB Init ───────────────────────────────────────────────
async function initDB() {
  try {
    const tables = [
      `CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, avatar TEXT DEFAULT '', is_premium INTEGER DEFAULT 0, premium_until TEXT DEFAULT NULL, stripe_customer_id TEXT DEFAULT NULL, created_at TIMESTAMP DEFAULT NOW())`,
      `CREATE TABLE IF NOT EXISTS watchlist (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, anime_id TEXT NOT NULL, title TEXT NOT NULL, img TEXT DEFAULT '', lang TEXT DEFAULT 'VOSTFR', ep_progress INTEGER DEFAULT 0, status TEXT DEFAULT 'watching', added_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, anime_id))`,
      `CREATE TABLE IF NOT EXISTS animelist (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, anime_id TEXT NOT NULL, title TEXT NOT NULL, img TEXT DEFAULT '', lang TEXT DEFAULT 'VOSTFR', status TEXT DEFAULT 'want', score INTEGER DEFAULT 0, added_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, anime_id))`,
      `CREATE TABLE IF NOT EXISTS comments (id SERIAL PRIMARY KEY, anime_id TEXT NOT NULL, user_id INTEGER NOT NULL, username TEXT NOT NULL, content TEXT NOT NULL, likes INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`,
      `CREATE TABLE IF NOT EXISTS chat_messages (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, username TEXT NOT NULL, avatar TEXT DEFAULT '', content TEXT NOT NULL, room TEXT DEFAULT 'general', created_at TIMESTAMP DEFAULT NOW())`,
      `CREATE TABLE IF NOT EXISTS comment_likes (user_id INTEGER NOT NULL, comment_id INTEGER NOT NULL, PRIMARY KEY(user_id, comment_id))`,
    ];
    for (const sql of tables) await pool.query(sql);
    console.log('✅ DB initialisée');
  } catch(e) {
    console.error('❌ initDB error:', e.message);
  }
}

// ── HEALTH CHECK ──────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected', vars: { db: !!process.env.DATABASE_URL, jwt: !!process.env.JWT_SECRET } });
  } catch(e) {
    res.status(500).json({ status: 'error', error: e.message, hint: 'Vérifiez DATABASE_URL dans Vercel → Settings → Environment Variables' });
  }
});

// ── Middleware ────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use('/api/premium/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/auth', rateLimit({ windowMs: 15*60*1000, max: 100 }));

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requis' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET||'secret'); next(); }
  catch { res.status(401).json({ error: 'Token invalide' }); }
}
const san = u => ({ id:u.id,username:u.username,email:u.email,avatar:u.avatar,is_premium:u.is_premium,premium_until:u.premium_until });

// ── AUTH ──────────────────────────────────────────────────
app.post('/api/auth/register', async (req,res) => {
  const { username, email, password } = req.body;
  if (!username||!email||!password) return res.status(400).json({ error:'Champs manquants' });
  if (password.length<6) return res.status(400).json({ error:'Mot de passe trop court' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const user = await db.one('INSERT INTO users(username,email,password) VALUES($1,$2,$3) RETURNING *',[username,email,hash]);
    const token = jwt.sign({id:user.id,username:user.username,email:user.email,is_premium:0},process.env.JWT_SECRET||'secret',{expiresIn:'30d'});
    res.json({ token, user: san(user) });
  } catch(e) {
    if (e.code==='23505') return res.status(409).json({ error:'Email ou pseudo déjà utilisé' });
    res.status(500).json({ error:'Erreur serveur' });
  }
});

app.post('/api/auth/login', async (req,res) => {
  const { email, password } = req.body;
  const user = await db.one('SELECT * FROM users WHERE email=$1',[email]);
  if (!user) return res.status(401).json({ error:'Email ou mot de passe incorrect' });
  if (!await bcrypt.compare(password,user.password)) return res.status(401).json({ error:'Email ou mot de passe incorrect' });
  if (user.premium_until && new Date(user.premium_until)<new Date()) {
    await db.run('UPDATE users SET is_premium=0 WHERE id=$1',[user.id]); user.is_premium=0;
  }
  const token = jwt.sign({id:user.id,username:user.username,email:user.email,is_premium:user.is_premium},process.env.JWT_SECRET||'secret',{expiresIn:'30d'});
  res.json({ token, user: san(user) });
});

app.get('/api/auth/me', auth, async (req,res) => {
  const user = await db.one('SELECT * FROM users WHERE id=$1',[req.user.id]);
  if (!user) return res.status(404).json({ error:'Introuvable' });
  res.json({ user: san(user) });
});

// ── PREMIUM ───────────────────────────────────────────────
app.post('/api/premium/checkout', auth, async (req,res) => {
  try {
    const user = await db.one('SELECT * FROM users WHERE id=$1',[req.user.id]);
    let cid = user.stripe_customer_id;
    if (!cid) {
      const c = await stripe.customers.create({email:user.email,name:user.username});
      cid = c.id;
      await db.run('UPDATE users SET stripe_customer_id=$1 WHERE id=$2',[cid,user.id]);
    }
    const sess = await stripe.checkout.sessions.create({
      customer:cid, mode:'subscription',
      line_items:[{price:process.env.STRIPE_PRICE_ID,quantity:1}],
      success_url:`${process.env.FRONTEND_URL||'http://localhost:3001'}?premium=success`,
      cancel_url:`${process.env.FRONTEND_URL||'http://localhost:3001'}?premium=cancel`,
      metadata:{user_id:String(user.id)},
    });
    res.json({ url: sess.url });
  } catch(e) { res.status(500).json({ error:'Erreur paiement: '+e.message }); }
});

app.post('/api/premium/webhook', async (req,res) => {
  let event;
  try { event = stripe.webhooks.constructEvent(req.body,req.headers['stripe-signature'],process.env.STRIPE_WEBHOOK_SECRET); }
  catch(e) { return res.status(400).send('Webhook Error: '+e.message); }
  const until = new Date(); until.setDate(until.getDate()+30);
  if (event.type==='checkout.session.completed') {
    await db.run('UPDATE users SET is_premium=1,premium_until=$1 WHERE id=$2',[until.toISOString(),parseInt(event.data.object.metadata.user_id)]);
  }
  if (event.type==='invoice.payment_succeeded') {
    const u = await db.one('SELECT id FROM users WHERE stripe_customer_id=$1',[event.data.object.customer]);
    if (u) await db.run('UPDATE users SET is_premium=1,premium_until=$1 WHERE id=$2',[until.toISOString(),u.id]);
  }
  if (event.type==='customer.subscription.deleted') {
    const u = await db.one('SELECT id FROM users WHERE stripe_customer_id=$1',[event.data.object.customer]);
    if (u) await db.run('UPDATE users SET is_premium=0,premium_until=NULL WHERE id=$1',[u.id]);
  }
  res.json({ received:true });
});

app.post('/api/premium/activate-test', auth, async (req,res) => {
  const until = new Date(); until.setDate(until.getDate()+30);
  await db.run('UPDATE users SET is_premium=1,premium_until=$1 WHERE id=$2',[until.toISOString(),req.user.id]);
  res.json({ success:true, premium_until:until.toISOString() });
});

// ── WATCHLIST ─────────────────────────────────────────────
app.get('/api/watchlist', auth, async (req,res) => res.json(await db.all('SELECT * FROM watchlist WHERE user_id=$1 ORDER BY added_at DESC',[req.user.id])));
app.post('/api/watchlist', auth, async (req,res) => {
  const {anime_id,title,img,lang,ep_progress,status} = req.body;
  if (!anime_id||!title) return res.status(400).json({error:'anime_id et title requis'});
  await db.run('INSERT INTO watchlist(user_id,anime_id,title,img,lang,ep_progress,status) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(user_id,anime_id) DO UPDATE SET ep_progress=$6,status=$7',
    [req.user.id,anime_id,title,img||'',lang||'VOSTFR',ep_progress||0,status||'watching']);
  res.json({success:true});
});
app.delete('/api/watchlist/:id', auth, async (req,res) => { await db.run('DELETE FROM watchlist WHERE user_id=$1 AND anime_id=$2',[req.user.id,req.params.id]); res.json({success:true}); });

// ── ANIMELIST ─────────────────────────────────────────────
app.get('/api/animelist', auth, async (req,res) => res.json(await db.all('SELECT * FROM animelist WHERE user_id=$1 ORDER BY added_at DESC',[req.user.id])));
app.post('/api/animelist', auth, async (req,res) => {
  const {anime_id,title,img,lang,status,score} = req.body;
  if (!anime_id||!title) return res.status(400).json({error:'anime_id et title requis'});
  await db.run('INSERT INTO animelist(user_id,anime_id,title,img,lang,status,score) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(user_id,anime_id) DO UPDATE SET status=$6,score=$7',
    [req.user.id,anime_id,title,img||'',lang||'VOSTFR',status||'want',score||0]);
  res.json({success:true});
});
app.delete('/api/animelist/:id', auth, async (req,res) => { await db.run('DELETE FROM animelist WHERE user_id=$1 AND anime_id=$2',[req.user.id,req.params.id]); res.json({success:true}); });

// ── COMMENTAIRES ──────────────────────────────────────────
app.get('/api/comments/:animeId', async (req,res) => {
  const r = await db.all('SELECT c.*,(SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id=c.id) as likes FROM comments c WHERE c.anime_id=$1 ORDER BY c.created_at DESC LIMIT 50',[req.params.animeId]);
  res.json(r);
});
app.post('/api/comments/:animeId', auth, async (req,res) => {
  const {content} = req.body;
  if (!content||content.trim().length<2) return res.status(400).json({error:'Commentaire trop court'});
  const c = await db.one('INSERT INTO comments(anime_id,user_id,username,content) VALUES($1,$2,$3,$4) RETURNING *',[req.params.animeId,req.user.id,req.user.username,content.trim()]);
  broadcastToRoom('comments_'+req.params.animeId,{type:'new_comment',comment:c});
  res.json(c);
});
app.post('/api/comments/:id/like', auth, async (req,res) => {
  try { await db.run('INSERT INTO comment_likes(user_id,comment_id) VALUES($1,$2)',[req.user.id,req.params.id]); }
  catch { await db.run('DELETE FROM comment_likes WHERE user_id=$1 AND comment_id=$2',[req.user.id,req.params.id]); }
  const r = await db.one('SELECT COUNT(*) as c FROM comment_likes WHERE comment_id=$1',[req.params.id]);
  res.json({likes:parseInt(r.c)});
});
app.delete('/api/comments/:id', auth, async (req,res) => {
  const c = await db.one('SELECT * FROM comments WHERE id=$1',[req.params.id]);
  if (!c) return res.status(404).json({error:'Introuvable'});
  if (c.user_id!==req.user.id) return res.status(403).json({error:'Non autorisé'});
  await db.run('DELETE FROM comments WHERE id=$1',[req.params.id]);
  res.json({success:true});
});

// ── CHAT ─────────────────────────────────────────────────
app.get('/api/chat/:room', auth, async (req,res) => {
  const msgs = await db.all('SELECT * FROM chat_messages WHERE room=$1 ORDER BY created_at DESC LIMIT 50',[req.params.room||'general']);
  res.json(msgs.reverse());
});

// ── WEBSOCKET ─────────────────────────────────────────────
const clients = new Map();
function broadcastToRoom(room,data) {
  const msg = JSON.stringify(data);
  clients.forEach((info,ws) => { if(ws.readyState===1&&info.rooms.has(room)) ws.send(msg); });
}
wss.on('connection', ws => {
  const info = {userId:null,username:'Anonyme',avatar:'',rooms:new Set()};
  clients.set(ws,info);
  ws.on('message', async raw => {
    let msg; try{msg=JSON.parse(raw);}catch{return;}
    if (msg.type==='auth') {
      try {
        const u = jwt.verify(msg.token,process.env.JWT_SECRET||'secret');
        info.userId=u.id; info.username=u.username;
        ws.send(JSON.stringify({type:'auth_ok',username:info.username}));
      } catch { ws.send(JSON.stringify({type:'auth_error'})); }
    }
    if (msg.type==='join_room') {
      info.rooms.add(msg.room);
      const h = await db.all('SELECT * FROM chat_messages WHERE room=$1 ORDER BY created_at DESC LIMIT 20',[msg.room]);
      ws.send(JSON.stringify({type:'room_history',room:msg.room,messages:h.reverse()}));
      broadcastToRoom(msg.room,{type:'user_joined',username:info.username,room:msg.room});
    }
    if (msg.type==='chat_message') {
      if (!info.userId){ws.send(JSON.stringify({type:'error',error:'Auth requise'}));return;}
      if (!msg.content?.trim()||msg.content.length>300) return;
      const room = msg.room||'general';
      const saved = await db.one('INSERT INTO chat_messages(user_id,username,avatar,content,room) VALUES($1,$2,$3,$4,$5) RETURNING *',[info.userId,info.username,info.avatar,msg.content.trim(),room]);
      broadcastToRoom(room,{type:'chat_message',message:saved});
    }
    if (msg.type==='typing') broadcastToRoom(msg.room||'general',{type:'typing',username:info.username,room:msg.room||'general'});
  });
  ws.on('close',()=>{ info.rooms.forEach(r=>broadcastToRoom(r,{type:'user_left',username:info.username,room:r})); clients.delete(ws); });
});

// ── STATS ─────────────────────────────────────────────────
app.get('/api/stats', async (req,res) => {
  const [u,p,c,m] = await Promise.all([
    db.one('SELECT COUNT(*) as c FROM users'),
    db.one('SELECT COUNT(*) as c FROM users WHERE is_premium=1'),
    db.one('SELECT COUNT(*) as c FROM comments'),
    db.one('SELECT COUNT(*) as c FROM chat_messages'),
  ]);
  res.json({users:+u.c,premium:+p.c,comments:+c.c,messages:+m.c,online:clients.size});
});

// ── START ──────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;

// Sur Vercel serverless, on init la DB sans bloquer le démarrage
initDB().catch(e => console.error('initDB warning:', e.message));

server.listen(PORT, () => {
  console.log(`✅ AniStream Backend — port ${PORT}`);
});

// Export pour Vercel serverless
module.exports = app;
