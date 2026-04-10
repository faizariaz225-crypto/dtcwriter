/**
 * DTCWriter Reverse Proxy Server
 * 
 * Handles:
 *  - Admin API: manage users, packages, issues, proxy config & cookies
 *  - /proxy/* : reverse-proxy to the configured target, injecting admin-set cookies
 *  - Static frontend serving
 */

require('dotenv').config();
const express       = require('express');
const cors          = require('cors');
const cookieParser  = require('cookie-parser');
const session       = require('express-session');
const helmet        = require('helmet');
const fetch         = require('node-fetch');
const path          = require('path');
const http          = require('http');
const https         = require('https');
const { URL }       = require('url');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dtcwriter-super-secret-key-change-in-prod';

// ─── In-memory store (replace with DB in production) ───────────────────────
const db = {
  users: [
    { id: 1, name: 'Alice Chen',    email: 'alice@example.com',   username: 'alice',    password: 'pass123',  package: 'Pro',        status: 'Active',   expires: '2025-12-31' },
    { id: 2, name: 'Bob Martinez',  email: 'bob@example.com',     username: 'bob',      password: 'pass123',  package: 'Basic',      status: 'Active',   expires: '2025-09-15' },
    { id: 3, name: 'Carol White',   email: 'carol@example.com',   username: 'carol',    password: 'pass123',  package: 'Enterprise', status: 'Active',   expires: '2026-03-01' },
    { id: 4, name: 'David Kim',     email: 'david@example.com',   username: 'david',    password: 'pass123',  package: 'Basic',      status: 'Inactive', expires: '2025-05-01' },
    { id: 5, name: 'Emma Lee',      email: 'emma@example.com',    username: 'customer', password: 'cust123',  package: 'Pro',        status: 'Active',   expires: '2025-11-20' },
  ],
  packages: [
    { id: 1, name: 'Basic',      price: '$9/mo',  features: ['5 articles/month', 'Email support', 'Basic analytics', '1 user seat'] },
    { id: 2, name: 'Pro',        price: '$29/mo', features: ['50 articles/month', 'Priority support', 'Advanced analytics', '5 user seats', 'API access'] },
    { id: 3, name: 'Enterprise', price: '$99/mo', features: ['Unlimited articles', 'Dedicated support', 'Custom analytics', 'Unlimited seats', 'White-label', 'SLA 99.9%'] },
  ],
  issues: [
    { id: 1, userId: 1, title: 'Cannot access article editor', priority: 'High',     status: 'Open',        date: '2025-04-08' },
    { id: 2, userId: 2, title: 'Billing invoice not received',  priority: 'Medium',   status: 'In Progress', date: '2025-04-07' },
    { id: 3, userId: 5, title: 'Slow loading on dashboard',     priority: 'Low',      status: 'Resolved',    date: '2025-04-05' },
    { id: 4, userId: 3, title: 'API rate limit exceeded',       priority: 'Critical', status: 'Open',        date: '2025-04-09' },
  ],
  proxyConfig: {
    targetUrl: 'https://example.com',
    mode: 'server',       // 'server' | 'iframe'
    cookies: [
      { name: 'auth_token',  value: 'eyJhbGciOiJIUzI1NiJ9...' },
      { name: 'session_id',  value: 'sess_abc123xyz' },
    ],
    // Extra headers forwarded to target
    headers: {},
    // Strip these response headers from target (avoids frame-busting)
    stripResponseHeaders: ['x-frame-options', 'content-security-policy', 'x-xss-protection'],
  },
  // Admin accounts (in prod use hashed passwords)
  admins: [
    { username: 'admin', password: 'admin123' }
  ],
  nextId: 6,
};

// ─── Middleware ─────────────────────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Helmet with relaxed CSP so the frontend & proxy work
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false,
}));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));

// Serve static files (frontend)
app.use(express.static(path.join(__dirname, '../public')));

// ─── Auth middleware ─────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.session?.role === 'admin') return next();
  res.status(401).json({ error: 'Unauthorized' });
}

function requireAuth(req, res, next) {
  if (req.session?.userId || req.session?.role === 'admin') return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  // Check admin
  const admin = db.admins.find(a => a.username === username && a.password === password);
  if (admin) {
    req.session.role = 'admin';
    req.session.username = username;
    return res.json({ role: 'admin', displayName: 'Admin', email: 'admin@dtcwriter.io' });
  }

  // Check customer
  const user = db.users.find(u => u.username === username && u.password === password);
  if (user) {
    req.session.role = 'customer';
    req.session.userId = user.id;
    req.session.username = username;
    return res.json({ role: 'customer', displayName: user.name, email: user.email, userId: user.id });
  }

  res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session?.role) return res.status(401).json({ error: 'Not logged in' });
  res.json({ role: req.session.role, userId: req.session.userId, username: req.session.username });
});

// ─── USER ROUTES (admin only) ────────────────────────────────────────────────
app.get('/api/users', requireAdmin, (req, res) => res.json(db.users));

app.post('/api/users', requireAdmin, (req, res) => {
  const { name, email, username, password, package: pkg, status, expires } = req.body;
  if (!name || !username) return res.status(400).json({ error: 'Name and username required' });
  if (db.users.find(u => u.username === username)) return res.status(400).json({ error: 'Username taken' });
  const user = { id: db.nextId++, name, email, username, password, package: pkg, status: status || 'Active', expires: expires || '', lastActive: 'Just now' };
  db.users.push(user);
  res.status(201).json(user);
});

app.put('/api/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const idx = db.users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  db.users[idx] = { ...db.users[idx], ...req.body, id };
  res.json(db.users[idx]);
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const idx = db.users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  db.users.splice(idx, 1);
  res.json({ ok: true });
});

// Customer: get own profile
app.get('/api/users/me', requireAuth, (req, res) => {
  if (req.session.role === 'admin') return res.json({ role: 'admin' });
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  // Don't expose password
  const { password, ...safe } = user;
  res.json(safe);
});

// ─── PACKAGE ROUTES ───────────────────────────────────────────────────────────
app.get('/api/packages', requireAuth, (req, res) => res.json(db.packages));

app.post('/api/packages', requireAdmin, (req, res) => {
  const { name, price, features } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'Name and price required' });
  const pkg = { id: db.nextId++, name, price, features: features || [] };
  db.packages.push(pkg);
  res.status(201).json(pkg);
});

app.put('/api/packages/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const idx = db.packages.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Package not found' });
  db.packages[idx] = { ...db.packages[idx], ...req.body, id };
  res.json(db.packages[idx]);
});

app.delete('/api/packages/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const idx = db.packages.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Package not found' });
  db.packages.splice(idx, 1);
  res.json({ ok: true });
});

// ─── ISSUE ROUTES ─────────────────────────────────────────────────────────────
app.get('/api/issues', requireAuth, (req, res) => {
  if (req.session.role === 'admin') return res.json(db.issues);
  // Customers see only their own
  res.json(db.issues.filter(i => i.userId === req.session.userId));
});

app.post('/api/issues', requireAuth, (req, res) => {
  const { title, priority, status, userId } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const assignedUserId = req.session.role === 'admin' ? (userId || null) : req.session.userId;
  const issue = { id: db.nextId++, userId: assignedUserId, title, priority: priority || 'Medium', status: status || 'Open', date: new Date().toISOString().split('T')[0] };
  db.issues.push(issue);
  res.status(201).json(issue);
});

app.put('/api/issues/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const idx = db.issues.findIndex(i => i.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Issue not found' });
  db.issues[idx] = { ...db.issues[idx], ...req.body, id };
  res.json(db.issues[idx]);
});

app.delete('/api/issues/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const idx = db.issues.findIndex(i => i.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Issue not found' });
  db.issues.splice(idx, 1);
  res.json({ ok: true });
});

// ─── PROXY CONFIG ROUTES (admin only) ────────────────────────────────────────
app.get('/api/proxy-config', requireAdmin, (req, res) => res.json(db.proxyConfig));

app.put('/api/proxy-config', requireAdmin, (req, res) => {
  const { targetUrl, mode, cookies, headers, stripResponseHeaders } = req.body;
  if (targetUrl !== undefined) db.proxyConfig.targetUrl = targetUrl;
  if (mode !== undefined) db.proxyConfig.mode = mode;
  if (cookies !== undefined) db.proxyConfig.cookies = cookies;
  if (headers !== undefined) db.proxyConfig.headers = headers;
  if (stripResponseHeaders !== undefined) db.proxyConfig.stripResponseHeaders = stripResponseHeaders;
  res.json(db.proxyConfig);
});

// ─── REVERSE PROXY HANDLER ────────────────────────────────────────────────────
/**
 * All requests to /proxy/* are proxied to the configured target URL.
 * Admin-configured cookies and headers are injected.
 * Frame-busting headers are stripped from responses.
 * Relative URLs in HTML/CSS are rewritten to go through /proxy/.
 */
app.use('/proxy', requireAuth, async (req, res) => {
  const { targetUrl, cookies, headers: extraHeaders, stripResponseHeaders } = db.proxyConfig;

  if (!targetUrl) return res.status(400).send('No proxy target configured');

  let base;
  try { base = new URL(targetUrl); }
  catch (e) { return res.status(400).send('Invalid proxy target URL'); }

  // Build target URL: strip "/proxy" prefix, keep rest of path + query
  const subPath = req.url === '/' ? '' : req.url;
  const target = new URL(subPath || '/', base);

  // Build cookie header from admin config
  const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ');

  // Forward headers
  const forwardHeaders = {
    'host': base.host,
    'accept': req.headers['accept'] || '*/*',
    'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'user-agent': req.headers['user-agent'] || 'DTCWriter-Proxy/1.0',
  };

  if (cookieHeader) forwardHeaders['cookie'] = cookieHeader;
  if (req.headers['content-type']) forwardHeaders['content-type'] = req.headers['content-type'];
  if (req.headers['accept-encoding']) forwardHeaders['accept-encoding'] = 'identity'; // avoid compressed responses

  // Merge admin-configured extra headers
  Object.assign(forwardHeaders, extraHeaders || {});

  let body = undefined;
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    body = JSON.stringify(req.body);
  }

  try {
    const upstream = await fetch(target.toString(), {
      method: req.method,
      headers: forwardHeaders,
      body,
      redirect: 'follow',
      // Use appropriate agent
      agent: target.protocol === 'https:' ? new https.Agent({ rejectUnauthorized: false }) : new http.Agent(),
    });

    // Strip frame-busting / CSP headers
    const strip = (stripResponseHeaders || []).map(h => h.toLowerCase());
    upstream.headers.forEach((value, key) => {
      if (!strip.includes(key.toLowerCase())) {
        // Rewrite Location headers for redirects
        if (key.toLowerCase() === 'location') {
          try {
            const loc = new URL(value, base);
            if (loc.origin === base.origin) {
              res.setHeader('Location', '/proxy' + loc.pathname + loc.search);
              return;
            }
          } catch {}
        }
        res.setHeader(key, value);
      }
    });

    // Always allow framing from our own origin
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
    res.status(upstream.status);

    const contentType = (upstream.headers.get('content-type') || '').toLowerCase();
    const isHtml = contentType.includes('text/html');
    const isCss  = contentType.includes('text/css');

    if (isHtml || isCss) {
      let text = await upstream.text();
      text = rewriteUrls(text, base, isHtml);
      res.setHeader('Content-Type', contentType);
      res.send(text);
    } else {
      upstream.body.pipe(res);
    }
  } catch (err) {
    console.error('[Proxy Error]', err.message);
    res.status(502).send(`
      <html><body style="font-family:sans-serif;padding:40px;background:#0a0c10;color:#e8eaf0">
        <h2 style="color:#ef4444">502 Bad Gateway</h2>
        <p>Could not reach <code>${target.toString()}</code></p>
        <p style="color:#8892a4">${err.message}</p>
        <p><a href="javascript:history.back()" style="color:#00e5ff">← Go back</a></p>
      </body></html>
    `);
  }
});

/**
 * Rewrite URLs in HTML/CSS to route through /proxy/
 */
function rewriteUrls(content, base, isHtml) {
  const baseOrigin = base.origin;
  const baseHref   = base.href;

  const rewrite = (url) => {
    if (!url || url.startsWith('data:') || url.startsWith('javascript:') || url.startsWith('#')) return url;
    try {
      const abs = new URL(url, baseHref);
      if (abs.origin === baseOrigin) {
        return '/proxy' + abs.pathname + abs.search + abs.hash;
      }
    } catch {}
    return url;
  };

  if (isHtml) {
    // Inject <base> to help relative URLs, then rewrite key attributes
    content = content
      // href attributes
      .replace(/(\shref=["'])([^"']+)(["'])/gi, (m, p1, url, p2) => p1 + rewrite(url) + p2)
      // src attributes
      .replace(/(\ssrc=["'])([^"']+)(["'])/gi, (m, p1, url, p2) => p1 + rewrite(url) + p2)
      // action attributes (forms)
      .replace(/(\saction=["'])([^"']+)(["'])/gi, (m, p1, url, p2) => p1 + rewrite(url) + p2)
      // CSS url() inside style tags
      .replace(/url\(["']?([^"')]+)["']?\)/gi, (m, url) => `url('${rewrite(url)}')`);
  } else {
    // CSS file
    content = content.replace(/url\(["']?([^"')]+)["']?\)/gi, (m, url) => `url('${rewrite(url)}')`);
  }
  return content;
}

// ─── Catch-all: serve frontend ────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ─── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ DTCWriter Proxy Server running on http://localhost:${PORT}`);
  console.log(`   Admin:    http://localhost:${PORT}  (admin / admin123)`);
  console.log(`   Customer: http://localhost:${PORT}  (customer / cust123)`);
  console.log(`   Proxy:    http://localhost:${PORT}/proxy/*\n`);
});

module.exports = app;
