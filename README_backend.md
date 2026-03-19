# AniStream Premium — Backend Setup (PostgreSQL)

## Pourquoi ce changement ?
`better-sqlite3` ne compile pas sur Node.js 24 (Vercel) → remplacé par **PostgreSQL** via `pg`.

## Installation

```bash
npm install
cp .env.example .env
# → Remplis .env
node server.js
```

## Base de données gratuite : Neon

1. Va sur **neon.tech** → crée un compte gratuit
2. Crée un projet → copie la **Connection string**
3. Colle dans `.env` → `DATABASE_URL=postgresql://...`

Les tables se créent automatiquement au démarrage.

## Déploiement sur Vercel

```bash
# 1. Push ton code sur GitHub
git add . && git commit -m "backend" && git push

# 2. Sur vercel.com → New Project → importe ton repo
# 3. Dans Settings → Environment Variables → ajoute:
#    DATABASE_URL, JWT_SECRET, STRIPE_SECRET_KEY, etc.
# 4. Deploy !
```

> ⚠️ Vercel = serverless. Le WebSocket ne fonctionne pas sur Vercel.
> Pour le chat temps réel → utilise **Render** ou **Railway** (gratuits aussi).

## Déploiement sur Render (recommandé pour le WebSocket)

1. render.com → New Web Service → connecte GitHub
2. Build: `npm install` | Start: `node server.js`
3. Ajoute les variables d'environnement
4. Deploy → copie l'URL → mets dans `anistream_user.html` :
   ```js
   const API = 'https://ton-app.onrender.com/api';
   ```

## Variables d'environnement requises

| Variable | Description |
|---|---|
| `DATABASE_URL` | URL PostgreSQL (Neon) |
| `JWT_SECRET` | Clé secrète JWT (32+ chars) |
| `STRIPE_SECRET_KEY` | Clé Stripe |
| `STRIPE_WEBHOOK_SECRET` | Secret webhook Stripe |
| `STRIPE_PRICE_ID` | ID du prix 2€/mois |
| `FRONTEND_URL` | URL de ton frontend |
| `PORT` | Port (défaut: 3001) |
