// ============================================================
// AniStream Premium Backend
// Node.js + Express + WebSocket + JWT + Stripe + SQLite
// ============================================================
require('dotenv').config();
const express     = require('express');
const cors        = require('cors');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const Stripe      = require('stripe');
const { WebSocketServer } = require('ws');
const Database    = require('better-sqlite3');
const http        = require('http');
const path        = require('path');
const rateLimit   = require('express-rate-limit');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server, path: '/ws' });
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_xxx');
const db     = new Database('./anistream.db');

// ── DB Setup ──────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    UNIQUE NOT NULL,
    email      TEXT    UNIQUE NOT NULL,
    password   TEXT    NOT NULL,
    avatar     TEXT    DEFAULT '',
    is_premium INTEGER DEFAULT 0,
    premium_until TEXT DEFAULT NULL,
    stripe_customer_id TEXT DEFAULT NULL,
    created_at TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS watchlist (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  INTEGER NOT NULL,
    anime_id TEXT    NOT NULL,
    title    TEXT    NOT NULL,
    img      TEXT    DEFAULT '',
    lang     TEXT    DEFAULT 'VOSTFR',
    ep_progress INTEGER DEFAULT 0,
    status   TEXT    DEFAULT 'watching',
    added_at TEXT    DEFAULT (datetime('now')),
    UNIQUE(user_id, anime_id)
  );

  CREATE TABLE IF NOT EXISTS animelist (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  INTEGER NOT NULL,
    anime_id TEXT    NOT NULL,
    title    TEXT    NOT NULL,
    img      TEXT    DEFAULT '',
    lang     TEXT    DEFAULT 'VOSTFR',
    status   TEXT    DEFAULT 'want',
    score    INTEGER DEFAULT 0,
    added_at TEXT    DEFAULT (datetime('now')),
    UNIQUE(user_id, anime_id)
  );

  CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    anime_id   TEXT    NOT NULL,
    user_id    INTEGER NOT NULL,
    username   TEXT    NOT NULL,
    content    TEXT    NOT NULL,
    likes      INTEGER DEFAULT 0,
    created_at TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS chat_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    username   TEXT    NOT NULL,
    avatar     TEXT    DEFAULT '',
    content    TEXT    NOT NULL,
    room       TEXT    DEFAULT 'general',
    created_at TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS comment_likes (
    user_id    INTEGER NOT NULL,
    comment_id INTEGER NOT NULL,
    PRIMARY KEY(user_id, comment_id)
  );
`);

// ── Middleware ────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use('/api/premium/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// Servir les fichiers statiques (anistream_user.html)
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/auth', limiter);

// ── JWT Middleware ────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requis' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

function premiumMiddleware(req, res, next) {
  if (!req.user.is_premium) return res.status(403).json({ error: 'Premium requis' });
  next();
}

// ── AUTH ──────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'Champs manquants' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Mot de passe trop court (6 min)' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    const result = stmt.run(username, email, hash);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, is_premium: 0 },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '30d' }
    );
    res.json({ token, user: sanitizeUser(user) });
  } catch (e) {
    if (e.message.includes('UNIQUE'))
      return res.status(409).json({ error: 'Email ou pseudo déjà utilisé' });
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  // Vérifier si le premium a expiré
  if (user.premium_until && new Date(user.premium_until) < new Date()) {
    db.prepare('UPDATE users SET is_premium = 0 WHERE id = ?').run(user.id);
    user.is_premium = 0;
  }
  const token = jwt.sign(
    { id: user.id, username: user.username, email: user.email, is_premium: user.is_premium },
    process.env.JWT_SECRET || 'secret',
    { expiresIn: '30d' }
  );
  res.json({ token, user: sanitizeUser(user) });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Introuvable' });
  res.json({ user: sanitizeUser(user) });
});

function sanitizeUser(u) {
  return { id: u.id, username: u.username, email: u.email, avatar: u.avatar, is_premium: u.is_premium, premium_until: u.premium_until };
}

// ── PREMIUM / STRIPE ──────────────────────────────────────
app.post('/api/premium/checkout', authMiddleware, async (req, res) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

    // Créer ou récupérer le client Stripe
    let customerId = user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email, name: user.username });
      customerId = customer.id;
      db.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?').run(customerId, user.id);
    }

    const session = await stripe.checkout.sessions.create({
      customer:    customerId,
      mode:        'subscription',
      line_items:  [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${process.env.FRONTEND_URL || 'http://localhost:3001'}?premium=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${process.env.FRONTEND_URL || 'http://localhost:3001'}?premium=cancel`,
      metadata:    { user_id: String(user.id) },
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error('Stripe error:', e);
    res.status(500).json({ error: 'Erreur paiement: ' + e.message });
  }
});

app.post('/api/premium/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = parseInt(session.metadata.user_id);
    // Activer premium 30 jours
    const until = new Date();
    until.setDate(until.getDate() + 30);
    db.prepare('UPDATE users SET is_premium = 1, premium_until = ? WHERE id = ?')
      .run(until.toISOString(), userId);
    console.log(`✅ Premium activé pour user ${userId} jusqu'au ${until.toISOString()}`);
  }

  if (event.type === 'invoice.payment_succeeded') {
    const invoice = event.data.object;
    const customer = db.prepare('SELECT * FROM users WHERE stripe_customer_id = ?').get(invoice.customer);
    if (customer) {
      const until = new Date();
      until.setDate(until.getDate() + 30);
      db.prepare('UPDATE users SET is_premium = 1, premium_until = ? WHERE id = ?')
        .run(until.toISOString(), customer.id);
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    const customer = db.prepare('SELECT * FROM users WHERE stripe_customer_id = ?').get(sub.customer);
    if (customer) {
      db.prepare('UPDATE users SET is_premium = 0, premium_until = NULL WHERE id = ?').run(customer.id);
    }
  }

  res.json({ received: true });
});

// Route pour activer premium manuellement (test)
app.post('/api/premium/activate-test', authMiddleware, (req, res) => {
  const until = new Date();
  until.setDate(until.getDate() + 30);
  db.prepare('UPDATE users SET is_premium = 1, premium_until = ? WHERE id = ?')
    .run(until.toISOString(), req.user.id);
  res.json({ success: true, premium_until: until.toISOString() });
});

// ── WATCHLIST ─────────────────────────────────────────────
app.get('/api/watchlist', authMiddleware, (req, res) => {
  const list = db.prepare('SELECT * FROM watchlist WHERE user_id = ? ORDER BY added_at DESC').all(req.user.id);
  res.json(list);
});

app.post('/api/watchlist', authMiddleware, (req, res) => {
  const { anime_id, title, img, lang, ep_progress, status } = req.body;
  if (!anime_id || !title) return res.status(400).json({ error: 'anime_id et title requis' });
  db.prepare(`
    INSERT INTO watchlist (user_id, anime_id, title, img, lang, ep_progress, status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, anime_id) DO UPDATE SET
      ep_progress = excluded.ep_progress,
      status = excluded.status
  `).run(req.user.id, anime_id, title, img || '', lang || 'VOSTFR', ep_progress || 0, status || 'watching');
  res.json({ success: true });
});

app.delete('/api/watchlist/:animeId', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM watchlist WHERE user_id = ? AND anime_id = ?').run(req.user.id, req.params.animeId);
  res.json({ success: true });
});

// ── ANIMELIST ─────────────────────────────────────────────
app.get('/api/animelist', authMiddleware, (req, res) => {
  const list = db.prepare('SELECT * FROM animelist WHERE user_id = ? ORDER BY added_at DESC').all(req.user.id);
  res.json(list);
});

app.post('/api/animelist', authMiddleware, (req, res) => {
  const { anime_id, title, img, lang, status, score } = req.body;
  if (!anime_id || !title) return res.status(400).json({ error: 'anime_id et title requis' });
  db.prepare(`
    INSERT INTO animelist (user_id, anime_id, title, img, lang, status, score)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, anime_id) DO UPDATE SET
      status = excluded.status,
      score = excluded.score
  `).run(req.user.id, anime_id, title, img || '', lang || 'VOSTFR', status || 'want', score || 0);
  res.json({ success: true });
});

app.delete('/api/animelist/:animeId', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM animelist WHERE user_id = ? AND anime_id = ?').run(req.user.id, req.params.animeId);
  res.json({ success: true });
});

// ── COMMENTAIRES ──────────────────────────────────────────
app.get('/api/comments/:animeId', (req, res) => {
  const comments = db.prepare(`
    SELECT c.*, 
      (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id) as likes
    FROM comments c
    WHERE c.anime_id = ?
    ORDER BY c.created_at DESC
    LIMIT 50
  `).all(req.params.animeId);
  res.json(comments);
});

app.post('/api/comments/:animeId', authMiddleware, (req, res) => {
  const { content } = req.body;
  if (!content || content.trim().length < 2)
    return res.status(400).json({ error: 'Commentaire trop court' });
  if (content.length > 500)
    return res.status(400).json({ error: 'Commentaire trop long (500 max)' });
  const result = db.prepare(`
    INSERT INTO comments (anime_id, user_id, username, content)
    VALUES (?, ?, ?, ?)
  `).run(req.params.animeId, req.user.id, req.user.username, content.trim());
  const comment = db.prepare('SELECT * FROM comments WHERE id = ?').get(result.lastInsertRowid);
  // Broadcast via WebSocket
  broadcastToRoom('comments_' + req.params.animeId, { type: 'new_comment', comment });
  res.json(comment);
});

app.post('/api/comments/:commentId/like', authMiddleware, (req, res) => {
  try {
    db.prepare('INSERT INTO comment_likes (user_id, comment_id) VALUES (?, ?)').run(req.user.id, req.params.commentId);
  } catch {
    db.prepare('DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?').run(req.user.id, req.params.commentId);
  }
  const count = db.prepare('SELECT COUNT(*) as c FROM comment_likes WHERE comment_id = ?').get(req.params.commentId);
  res.json({ likes: count.c });
});

app.delete('/api/comments/:commentId', authMiddleware, (req, res) => {
  const comment = db.prepare('SELECT * FROM comments WHERE id = ?').get(req.params.commentId);
  if (!comment) return res.status(404).json({ error: 'Introuvable' });
  if (comment.user_id !== req.user.id) return res.status(403).json({ error: 'Non autorisé' });
  db.prepare('DELETE FROM comments WHERE id = ?').run(req.params.commentId);
  res.json({ success: true });
});

// ── CHAT HISTORY ──────────────────────────────────────────
app.get('/api/chat/:room', authMiddleware, (req, res) => {
  const messages = db.prepare(`
    SELECT * FROM chat_messages WHERE room = ?
    ORDER BY created_at DESC LIMIT 50
  `).all(req.params.room || 'general');
  res.json(messages.reverse());
});

// ── WEBSOCKET ─────────────────────────────────────────────
const clients = new Map(); // ws → { userId, username, avatar, rooms: Set }

function broadcastToRoom(room, data) {
  const msg = JSON.stringify(data);
  clients.forEach((info, ws) => {
    if (ws.readyState === 1 && info.rooms.has(room)) {
      ws.send(msg);
    }
  });
}

wss.on('connection', (ws, req) => {
  const info = { userId: null, username: 'Anonyme', avatar: '', rooms: new Set() };
  clients.set(ws, info);

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {

      case 'auth': {
        try {
          const user = jwt.verify(msg.token, process.env.JWT_SECRET || 'secret');
          info.userId   = user.id;
          info.username = user.username;
          const dbUser = db.prepare('SELECT avatar FROM users WHERE id = ?').get(user.id);
          info.avatar = dbUser?.avatar || '';
          ws.send(JSON.stringify({ type: 'auth_ok', username: info.username }));
        } catch {
          ws.send(JSON.stringify({ type: 'auth_error', error: 'Token invalide' }));
        }
        break;
      }

      case 'join_room': {
        info.rooms.add(msg.room);
        // Envoyer les 20 derniers messages de la room
        const history = db.prepare(`
          SELECT * FROM chat_messages WHERE room = ?
          ORDER BY created_at DESC LIMIT 20
        `).all(msg.room).reverse();
        ws.send(JSON.stringify({ type: 'room_history', room: msg.room, messages: history }));
        // Notifier les autres
        broadcastToRoom(msg.room, {
          type: 'user_joined',
          username: info.username,
          room: msg.room
        });
        break;
      }

      case 'leave_room': {
        info.rooms.delete(msg.room);
        break;
      }

      case 'chat_message': {
        if (!info.userId) {
          ws.send(JSON.stringify({ type: 'error', error: 'Authentification requise' }));
          return;
        }
        if (!msg.content || msg.content.trim().length === 0) return;
        if (msg.content.length > 300) return;
        const room = msg.room || 'general';
        // Sauvegarder
        const result = db.prepare(`
          INSERT INTO chat_messages (user_id, username, avatar, content, room)
          VALUES (?, ?, ?, ?, ?)
        `).run(info.userId, info.username, info.avatar, msg.content.trim(), room);
        const saved = db.prepare('SELECT * FROM chat_messages WHERE id = ?').get(result.lastInsertRowid);
        // Broadcast
        broadcastToRoom(room, { type: 'chat_message', message: saved });
        break;
      }

      case 'typing': {
        if (!info.userId) return;
        broadcastToRoom(msg.room || 'general', {
          type: 'typing',
          username: info.username,
          room: msg.room || 'general'
        });
        break;
      }
    }
  });

  ws.on('close', () => {
    info.rooms.forEach(room => {
      broadcastToRoom(room, { type: 'user_left', username: info.username, room });
    });
    clients.delete(ws);
  });
});

// ── STATS ─────────────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  const users    = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const premium  = db.prepare('SELECT COUNT(*) as c FROM users WHERE is_premium = 1').get().c;
  const comments = db.prepare('SELECT COUNT(*) as c FROM comments').get().c;
  const messages = db.prepare('SELECT COUNT(*) as c FROM chat_messages').get().c;
  res.json({ users, premium, comments, messages, online: clients.size });
});

// ── START ──────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║   AniStream Backend  ✅  PORT ${PORT}   ║
  ╚══════════════════════════════════════╝
  → API : http://localhost:${PORT}/api
  → WS  : ws://localhost:${PORT}/ws
  `);
});
