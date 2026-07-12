/**
 * DTCWriter Reverse Proxy Server — v2 (Cache & Auth Fix)
 *
 * Fixes in this version:
 *  1. Origin/Referer spoofed to match second site (CSRF bypass)
 *  2. CSRF token auto-extracted from HTML pages and replayed on POST
 *  3. CSRF token injected into form bodies + XHR/fetch headers
 *  4. Form bodies re-encoded correctly (urlencoded / multipart / JSON)
 *  5. Set-Cookie rewritten for cross-site (SameSite=None; Secure)
 *  6. Runtime interceptor injected — patches fetch, XHR, forms, links
 *  7. MutationObserver fixes dynamically rendered content (React/Vue)
 *  8. CORS preflight handled
 *  9. Expanded default strip headers
 * 10. Session cookie secure for Render (HTTPS)
 * 11. FIX: no-store Cache-Control on all /api routes (eliminates 304 stale)
 * 12. FIX: /api/proxy-config now accessible to authenticated customers (fixes 401)
 * 13. FIX: /api/auth/me and /api/users/me explicitly set no-store header
 * 14. FIX: CORS origin now echoes exact request origin instead of wildcard *
 *          (wildcard * conflicts with credentials:true causing 401 on session requests)
 * 15. FIX: Forward all CORS headers from target site (Access-Control-Allow-Credentials,
 *          Methods, Headers) — missing headers blocked Next.js interactions
 * 16. FIX: Removed cross-origin-* from alwaysStrip — Next.js needs these
 * 17. FIX: Full CORS headers on OPTIONS preflight, JSON passthrough and all responses
 */

if (process.env.NODE_ENV !== 'production') require('dotenv').config();

const express      = require('express');
const cors         = require('cors');
const cookieParser = require('cookie-parser');
const session      = require('express-session');
const helmet       = require('helmet');
const fetch        = require('node-fetch');
const path         = require('path');
const http         = require('http');
const https        = require('https');
const { URL }      = require('url');

const app = express();
app.set('trust proxy', 1);

const PORT           = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dtcwriter-change-this-secret';

function jsonEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  try { return JSON.parse(raw); }
  catch (error) {
    console.warn(`[Config] Ignoring invalid ${name}: ${error.message}`);
    return fallback;
  }
}

// ─── CSRF Token store (per DTCWriter session) ─────────────────────────────────
const csrfTokenStore = {};

function extractCSRFToken(html) {
  const patterns = [
    /<meta[^>]+name=["']csrf-token["'][^>]+content=["']([^"']+)["']/i,
    /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']csrf-token["']/i,
    /<meta[^>]+name=["']_token["'][^>]+content=["']([^"']+)["']/i,
    /<meta[^>]+name=["']csrf["'][^>]+content=["']([^"']+)["']/i,
    /<input[^>]+name=["']_csrf["'][^>]+value=["']([^"']+)["']/i,
    /<input[^>]+value=["']([^"']+)["'][^>]+name=["']_csrf["']/i,
    /<input[^>]+name=["']_token["'][^>]+value=["']([^"']+)["']/i,
    /<input[^>]+value=["']([^"']+)["'][^>]+name=["']_token["']/i,
    /<input[^>]+name=["']csrfmiddlewaretoken["'][^>]+value=["']([^"']+)["']/i,
    /<input[^>]+value=["']([^"']+)["'][^>]+name=["']csrfmiddlewaretoken["']/i,
    /<input[^>]+name=["']authenticity_token["'][^>]+value=["']([^"']+)["']/i,
    /<input[^>]+value=["']([^"']+)["'][^>]+name=["']authenticity_token["']/i,
  ];
  for (const p of patterns) {
    const m = html.match(p);
    if (m) return m[1];
  }
  return null;
}

// ─── In-memory DB ─────────────────────────────────────────────────────────────
const db = {
  users: [
    { id: 1, name: 'Alice Chen',   email: 'alice@example.com',   username: 'alice',    password: 'pass123', package: 'Pro',        status: 'Active',   expires: '2025-12-31' },
    { id: 2, name: 'Bob Martinez', email: 'bob@example.com',     username: 'bob',      password: 'pass123', package: 'Basic',      status: 'Active',   expires: '2025-09-15' },
    { id: 3, name: 'Carol White',  email: 'carol@example.com',   username: 'carol',    password: 'pass123', package: 'Enterprise', status: 'Active',   expires: '2026-03-01' },
    { id: 4, name: 'David Kim',    email: 'david@example.com',   username: 'david',    password: 'pass123', package: 'Basic',      status: 'Inactive', expires: '2025-05-01' },
    { id: 5, name: 'Emma Lee',     email: 'emma@example.com',    username: 'customer', password: 'cust123', package: 'Pro',        status: 'Active',   expires: '2025-11-20' },
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
    targetUrl: process.env.PROXY_TARGET_URL || '',
    mode: process.env.PROXY_MODE || 'server',
    cookies: jsonEnv('PROXY_COOKIES_JSON', []),
    headers: jsonEnv('PROXY_HEADERS_JSON', {}),
    stripResponseHeaders: jsonEnv('PROXY_STRIP_HEADERS_JSON', [
      'x-frame-options',
      'content-security-policy',
      'x-xss-protection',
      'strict-transport-security',
    ]),
  },
  admins:  [{ username: 'admin', password: 'admin123' }],
  nextId: 6,
};

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile, curl, Postmark, same-origin)
    if (!origin) return callback(null, true);
    // Echo back the exact requesting origin instead of wildcard *
    // This is required when credentials: true is set
    callback(null, origin);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-CSRF-Token', 'X-XSRF-Token', 'X-Requested-With'],
  exposedHeaders: ['Set-Cookie'],
  optionsSuccessStatus: 200,
}));
app.use(cookieParser());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use(helmet({
  contentSecurityPolicy:     false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy:   false,
  crossOriginResourcePolicy: false,
}));

app.use(session({
  name:              'dtc.sid',
  secret:            SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure:   process.env.NODE_ENV === 'production',
    maxAge:   8 * 60 * 60 * 1000,
  },
}));

app.use(express.static(path.join(__dirname, '../public')));

// ─── Disable caching for all API routes (fixes 304 stale responses) ──────────
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// ─── Auth middleware ──────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.session?.role === 'admin') return next();
  res.status(401).json({ error: 'Unauthorized' });
}
function requireAuth(req, res, next) {
  if (req.session?.userId || req.session?.role === 'admin') return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ─── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const admin = db.admins.find(a => a.username === username && a.password === password);
  if (admin) {
    req.session.role = 'admin';
    req.session.username = username;
    return res.json({ role: 'admin', displayName: 'Admin', email: 'admin@dtcwriter.io' });
  }
  const user = db.users.find(u => u.username === username && u.password === password);
  if (user) {
    req.session.role     = 'customer';
    req.session.userId   = user.id;
    req.session.username = username;
    return res.json({ role: 'customer', displayName: user.name, email: user.email, userId: user.id });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/auth/me', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!req.session?.role) return res.status(401).json({ error: 'Not logged in' });
  res.json({ role: req.session.role, userId: req.session.userId, username: req.session.username });
});

// ─── User routes ──────────────────────────────────────────────────────────────
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
  const id  = parseInt(req.params.id);
  const idx = db.users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  db.users[idx] = { ...db.users[idx], ...req.body, id };
  res.json(db.users[idx]);
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const id  = parseInt(req.params.id);
  const idx = db.users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  db.users.splice(idx, 1);
  res.json({ ok: true });
});

app.get('/api/users/me', requireAuth, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.session.role === 'admin') return res.json({ role: 'admin' });
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { password, ...safe } = user;
  res.json(safe);
});

// ─── Package routes ───────────────────────────────────────────────────────────
app.get('/api/packages', requireAuth, (req, res) => res.json(db.packages));

app.post('/api/packages', requireAdmin, (req, res) => {
  const { name, price, features } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'Name and price required' });
  const pkg = { id: db.nextId++, name, price, features: features || [] };
  db.packages.push(pkg);
  res.status(201).json(pkg);
});

app.put('/api/packages/:id', requireAdmin, (req, res) => {
  const id  = parseInt(req.params.id);
  const idx = db.packages.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.packages[idx] = { ...db.packages[idx], ...req.body, id };
  res.json(db.packages[idx]);
});

app.delete('/api/packages/:id', requireAdmin, (req, res) => {
  const id  = parseInt(req.params.id);
  const idx = db.packages.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.packages.splice(idx, 1);
  res.json({ ok: true });
});

// ─── Issue routes ─────────────────────────────────────────────────────────────
app.get('/api/issues', requireAuth, (req, res) => {
  if (req.session.role === 'admin') return res.json(db.issues);
  res.json(db.issues.filter(i => i.userId === req.session.userId));
});

app.post('/api/issues', requireAuth, (req, res) => {
  const { title, priority, status, userId } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const assignedUserId = req.session.role === 'admin' ? (userId || null) : req.session.userId;
  const issue = {
    id: db.nextId++, userId: assignedUserId, title,
    priority: priority || 'Medium', status: status || 'Open',
    date: new Date().toISOString().split('T')[0],
  };
  db.issues.push(issue);
  res.status(201).json(issue);
});

app.put('/api/issues/:id', requireAdmin, (req, res) => {
  const id  = parseInt(req.params.id);
  const idx = db.issues.findIndex(i => i.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.issues[idx] = { ...db.issues[idx], ...req.body, id };
  res.json(db.issues[idx]);
});

app.delete('/api/issues/:id', requireAdmin, (req, res) => {
  const id  = parseInt(req.params.id);
  const idx = db.issues.findIndex(i => i.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.issues.splice(idx, 1);
  res.json({ ok: true });
});

// ─── Proxy config routes ──────────────────────────────────────────────────────
app.get('/api/proxy-config', requireAuth, (req, res) => {
  // Admins get full config; customers get only what they need to use the proxy
  if (req.session.role === 'admin') return res.json(db.proxyConfig);
  // Customers only need targetUrl and mode to connect through the proxy
  const { targetUrl, mode } = db.proxyConfig;
  res.json({ targetUrl, mode });
});

app.put('/api/proxy-config', requireAdmin, (req, res) => {
  const { targetUrl, mode, cookies, headers, stripResponseHeaders } = req.body;
  if (targetUrl            !== undefined) db.proxyConfig.targetUrl            = targetUrl;
  if (mode                 !== undefined) db.proxyConfig.mode                 = mode;
  if (cookies              !== undefined) db.proxyConfig.cookies              = cookies;
  if (headers              !== undefined) db.proxyConfig.headers              = headers;
  if (stripResponseHeaders !== undefined) db.proxyConfig.stripResponseHeaders = stripResponseHeaders;
  res.json(db.proxyConfig);
});

// ─── REVERSE PROXY ────────────────────────────────────────────────────────────
// ─── Proxy cookie helpers ────────────────────────────────────────────────────
function parseCookieHeader(header = '') {
  const result = new Map();
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const name = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    if (name && name !== 'dtc.sid') result.set(name, value);
  }
  return result;
}

function buildUpstreamCookieHeader(browserHeader, configuredCookies = []) {
  const jar = parseCookieHeader(browserHeader);
  // Admin-configured cookies intentionally override browser copies.
  for (const cookie of configuredCookies) {
    if (cookie && cookie.name) jar.set(String(cookie.name).trim(), String(cookie.value ?? ''));
  }
  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function rewriteUpstreamSetCookie(value) {
  // The upstream cookie is stored on the proxy host, so its original Domain and
  // Path must not be retained. The proxy is same-site with its iframe/new tab.
  const cleaned = String(value)
    .replace(/;\s*Domain=[^;]*/gi, '')
    .replace(/;\s*Path=[^;]*/gi, '')
    .replace(/;\s*SameSite=[^;]*/gi, '')
    .replace(/;\s*Secure/gi, '')
    .replace(/;\s*$/g, '');
  return `${cleaned}; Path=/; Secure; SameSite=Lax`;
}

app.use('/proxy', requireAuth, async (req, res) => {
  const { targetUrl, cookies, headers: extraHeaders, stripResponseHeaders } = db.proxyConfig;

  if (!targetUrl) {
    return res.status(400).send('No proxy target configured — set it in Admin → Proxy & Cookie Config');
  }

  let base;
  try { base = new URL(targetUrl); }
  catch { return res.status(400).send('Invalid proxy target URL'); }

  // ── Handle CORS preflight ──────────────────────────────────────────────────
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin',      req.headers['origin'] || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods',     'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',     'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-CSRF-Token, X-XSRF-Token, Cookie');
    res.setHeader('Access-Control-Expose-Headers',    'Set-Cookie, Authorization');
    res.setHeader('Access-Control-Max-Age',           '86400');
    res.setHeader('Vary',                             'Origin');
    return res.status(204).end();
  }

  // ── Build upstream URL ─────────────────────────────────────────────────────
  const subPath = req.url === '/' ? '' : req.url;
  const target  = new URL(subPath || '/', base);

  // ── Build cookie string ────────────────────────────────────────────────────
  const cookieHeader = buildUpstreamCookieHeader(req.headers['cookie'] || '', cookies || []);

  // Preserve application-specific headers used by modern frontends, while
  // removing hop-by-hop headers and rewriting host/origin for the upstream.
  const blockedRequestHeaders = new Set([
    'host', 'cookie', 'connection', 'keep-alive', 'proxy-authenticate',
    'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
    'content-length', 'accept-encoding', 'origin', 'referer'
  ]);
  const forwardHeaders = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (!blockedRequestHeaders.has(key.toLowerCase()) && value !== undefined) {
      forwardHeaders[key] = Array.isArray(value) ? value.join(', ') : value;
    }
  }
  Object.assign(forwardHeaders, {
    host:                 base.host,
    origin:               base.origin,
    referer:              new URL(subPath || '/', base).toString(),
    accept:               req.headers['accept'] || '*/*',
    'accept-encoding':    'identity',
    'user-agent':         req.headers['user-agent'] || 'Mozilla/5.0 DTCWriter-Proxy/1.0',
    'x-forwarded-host':   base.host,
    'x-forwarded-proto':  base.protocol.replace(':', ''),
  });
  if (cookieHeader) forwardHeaders.cookie = cookieHeader;

  // Forward CSRF headers exactly as supplied by the upstream application.
  // Generic token scraping/injection is intentionally avoided because it breaks
  // rotating/double-submit tokens and is not a substitute for proper SSO.
  const isWrite = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);

  // Merge admin extra headers last — they override everything
  Object.assign(forwardHeaders, extraHeaders || {});

  // ── Build request body ─────────────────────────────────────────────────────
  // JSON and URL-encoded bodies have already been parsed by Express. Other
  // content types (multipart uploads, text, binary) remain readable streams and
  // are forwarded without reconstruction.
  let body;
  if (isWrite) {
    const ct = (req.headers['content-type'] || '').toLowerCase();
    if (ct.includes('application/x-www-form-urlencoded')) {
      body = new URLSearchParams(req.body || {}).toString();
      forwardHeaders['content-type'] = 'application/x-www-form-urlencoded';
      forwardHeaders['content-length'] = Buffer.byteLength(body).toString();
    } else if (ct.includes('application/json') || ct.includes('+json')) {
      body = JSON.stringify(req.body ?? {});
      forwardHeaders['content-type'] = req.headers['content-type'] || 'application/json';
      forwardHeaders['content-length'] = Buffer.byteLength(body).toString();
    } else {
      body = req;
      if (req.headers['content-type']) forwardHeaders['content-type'] = req.headers['content-type'];
      if (req.headers['content-length']) forwardHeaders['content-length'] = req.headers['content-length'];
    }
  }

  // ── Fetch from second site ─────────────────────────────────────────────────
  try {
    const upstream = await fetch(target.toString(), {
      method:   req.method,
      headers:  forwardHeaders,
      body,
      redirect: 'manual',
      agent:    target.protocol === 'https:'
        ? new https.Agent({ rejectUnauthorized: false })
        : new http.Agent(),
    });

    // ── Rewrite response headers ───────────────────────────────────────────
    const alwaysStrip = new Set([
      'x-frame-options',
      'content-security-policy',
      'x-xss-protection',
      'strict-transport-security',
      // NOTE: cross-origin-* headers removed — Next.js needs these to function
      // 'cross-origin-opener-policy',
      // 'cross-origin-embedder-policy',
      // 'cross-origin-resource-policy',
    ]);
    const adminStrip = (stripResponseHeaders || []).map(h => h.toLowerCase());

    upstream.headers.forEach((value, key) => {
      const lk = key.toLowerCase();

      // Strip frame-busting, stale entity-length, and hop-by-hop headers.
      if (alwaysStrip.has(lk) || adminStrip.includes(lk)) return;
      if (['set-cookie','content-length','content-encoding','transfer-encoding','connection','etag'].includes(lk)) return;

      // Forward CORS headers — replace origin with exact requesting origin
      // so credentials work correctly (wildcard * breaks credentialed requests)
      if (lk === 'access-control-allow-origin') {
        res.setHeader('Access-Control-Allow-Origin',      req.headers['origin'] || value || '*');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods',     'GET,POST,PUT,PATCH,DELETE,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers',     'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-CSRF-Token, X-XSRF-Token, Cookie');
        res.setHeader('Access-Control-Expose-Headers',    'Set-Cookie, Authorization');
        res.setHeader('Access-Control-Max-Age',           '86400');
        return;
      }
      if (lk === 'access-control-allow-credentials' ||
          lk === 'access-control-allow-methods'     ||
          lk === 'access-control-allow-headers'     ||
          lk === 'access-control-expose-headers'    ||
          lk === 'access-control-max-age') {
        // Already set above — skip to avoid duplicates
        return;
      }

      // FIX 5: Rewrite redirect Location to stay inside proxy
      if (lk === 'location') {
        try {
          const loc = new URL(value, base.href);
          const rewritten = loc.origin === base.origin
            ? '/proxy' + loc.pathname + loc.search + loc.hash
            : value;
          res.setHeader('Location', rewritten);
        } catch { res.setHeader('Location', value); }
        return;
      }

      res.setHeader(key, value);
    });

    // node-fetch v2 exposes separate Set-Cookie lines through raw(); forEach()
    // may collapse them, which corrupts Expires values and session rotation.
    const upstreamSetCookies = upstream.headers.raw()['set-cookie'] || [];
    for (const cookie of upstreamSetCookies) {
      res.append('Set-Cookie', rewriteUpstreamSetCookie(cookie));
    }

    // Inject permissive framing + CORS
    res.setHeader('X-Frame-Options',              'SAMEORIGIN');
    res.setHeader('Content-Security-Policy',      "frame-ancestors 'self'");
    res.setHeader('Access-Control-Allow-Origin',      req.headers['origin'] || req.headers['referer'] || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
    res.status(upstream.status);

    // ── Rewrite body ───────────────────────────────────────────────────────
    const contentType = (upstream.headers.get('content-type') || '').toLowerCase();

    // ── JSON / XML / text — pass through untouched ─────────────────────────
    if (
      contentType.includes('application/json') ||
      contentType.includes('text/json')        ||
      contentType.includes('application/xml')  ||
      contentType.includes('text/xml')         ||
      contentType.includes('text/plain')
    ) {
      const raw = await upstream.text();
      res.setHeader('Content-Type',                    contentType);
      res.setHeader('Access-Control-Allow-Origin',      req.headers['origin'] || '*');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods',     'GET,POST,PUT,PATCH,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers',     'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-CSRF-Token, X-XSRF-Token, Cookie');
      res.setHeader('Access-Control-Expose-Headers',    'Set-Cookie, Authorization');
      res.setHeader('Vary',                             'Origin');
      console.log(`[Proxy] JSON passthrough: ${target.pathname} (${raw.length} bytes)`);
      return res.send(raw);
    }

    const isHtml = contentType.includes('text/html');
    const isCss  = contentType.includes('text/css');
    const isJs   = contentType.includes('javascript');

    if (isHtml || isCss || isJs) {
      let text = await upstream.text();

      // Do not scrape or synthesize CSRF tokens. The upstream application's
      // own cookie/header mechanism is forwarded unchanged.

      text = rewriteUrls(text, base, isHtml, false);

      // FIX 6+7: Inject runtime interceptor into every HTML page
      if (isHtml) {
        const interceptor = buildInterceptor(base);
        text = text.replace(/<head([^>]*)>/i, m => m + interceptor);

        // Native form behavior is left intact; the interceptor rewrites explicit actions.
      }

      res.setHeader('Content-Type', contentType);
      return res.send(text);
    }

    // Binary / other — stream unchanged
    upstream.body.pipe(res);

  } catch (err) {
    console.error('[Proxy Error]', err.message);
    res.status(502).send(`
      <html>
      <body style="font-family:sans-serif;padding:40px;background:#0a0c10;color:#e8eaf0">
        <h2 style="color:#ef4444">502 Bad Gateway</h2>
        <p>Could not reach <code>${target.toString()}</code></p>
        <p style="color:#8892a4">${err.message}</p>
        <a href="javascript:history.back()" style="color:#00e5ff">← Go back</a>
      </body>
      </html>`);
  }
});

// ─── Runtime interceptor injected into every proxied HTML page ────────────────
function buildInterceptor(base) {
  const upstreamOrigin = JSON.stringify(base.origin);
  return `
<script>
(function(){
  'use strict';
  var UPSTREAM_ORIGIN = ${upstreamOrigin};

  function proxify(value) {
    if (!value || typeof value !== 'string') return value;
    if (/^(data:|blob:|mailto:|tel:|javascript:|#)/i.test(value)) return value;
    if (value === '/proxy' || value.startsWith('/proxy/')) return value;
    try {
      var resolved = new URL(value, UPSTREAM_ORIGIN + '/');
      if (resolved.origin === UPSTREAM_ORIGIN) {
        return '/proxy' + resolved.pathname + resolved.search + resolved.hash;
      }
      // A separate API/CDN origin needs an explicit, owner-controlled proxy route.
      console.warn('[DTCWriter] External origin not proxied:', resolved.origin, value);
      return value;
    } catch (_) {
      return value;
    }
  }

  var nativeFetch = window.fetch && window.fetch.bind(window);
  if (nativeFetch) {
    window.fetch = function(input, init) {
      init = Object.assign({}, init || {}, { credentials: 'include' });
      if (input instanceof Request) {
        input = new Request(proxify(input.url), input);
      } else {
        input = proxify(input);
      }
      return nativeFetch(input, init);
    };
  }

  var nativeOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    var args = Array.prototype.slice.call(arguments);
    args[1] = proxify(url);
    return nativeOpen.apply(this, args);
  };

  if (window.EventSource) {
    var NativeEventSource = window.EventSource;
    window.EventSource = function(url, options) {
      return new NativeEventSource(proxify(url), Object.assign({ withCredentials: true }, options || {}));
    };
    window.EventSource.prototype = NativeEventSource.prototype;
  }

  if (navigator.sendBeacon) {
    var nativeBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function(url, data) { return nativeBeacon(proxify(url), data); };
  }

  document.addEventListener('submit', function(event) {
    var form = event.target;
    if (form && form.tagName === 'FORM') {
      var action = form.getAttribute('action');
      if (action) form.setAttribute('action', proxify(action));
    }
  }, true);

  console.info('[DTCWriter] HTTP proxy interceptor active for', UPSTREAM_ORIGIN);
})();
</script>`;
}

// ─── URL rewriter ─────────────────────────────────────────────────────────────
function rewriteUrls(content, base, isHtml, isJs = false) {
  const baseOrigin = base.origin;
  const baseHref   = base.href;

  const rewrite = (url) => {
    if (!url) return url;
    const t = url.trim();
    if (t.startsWith('data:') || t.startsWith('javascript:') ||
        t.startsWith('#')     || t.startsWith('/proxy')) return url;
    try {
      const abs = new URL(t, baseHref);
      if (abs.origin === baseOrigin) return '/proxy' + abs.pathname + abs.search + abs.hash;
    } catch {}
    return url;
  };

  if (isJs) {
    const esc = baseOrigin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return content
      .replace(new RegExp(`(['"\`])(${esc})(/[^'"\`]*?)(['"\`])`, 'g'),
        (m, q1, _, path, q2) => q1 + '/proxy' + path + q2)
      .replace(/(['"`])(\/(?!proxy\/)[a-zA-Z0-9_\-/.?=&#%@+,;:~*()[\]$!]{2,})(['"`])/g,
        (m, q1, path, q2) => q1 + '/proxy' + path + q2)
      .replace(/(window\.location(?:\.href)?\s*=\s*)(['"`])([^'"`]+)(['"`])/g,
        (m, pre, q1, url, q2) => pre + q1 + rewrite(url) + q2);
  }

  if (isHtml) {
    content = content.replace(/<head([^>]*)>/i, m => m + '\n<base href="/proxy/">');
    content = content.replace(/\s+integrity="[^"]*"/gi, '');
    content = content.replace(/\s+crossorigin="[^"]*"/gi, '');
    return content
      .replace(/(\shref=["'])([^"']+)(["'])/gi,        (m,p1,u,p2) => p1+rewrite(u)+p2)
      .replace(/(\ssrc=["'])([^"']+)(["'])/gi,          (m,p1,u,p2) => p1+rewrite(u)+p2)
      .replace(/(\saction=["'])([^"']+)(["'])/gi,       (m,p1,u,p2) => p1+rewrite(u)+p2)
      .replace(/(\sdata-url=["'])([^"']+)(["'])/gi,     (m,p1,u,p2) => p1+rewrite(u)+p2)
      .replace(/(\sdata-href=["'])([^"']+)(["'])/gi,    (m,p1,u,p2) => p1+rewrite(u)+p2)
      .replace(/(\sdata-action=["'])([^"']+)(["'])/gi,  (m,p1,u,p2) => p1+rewrite(u)+p2)
      .replace(/(\sdata-src=["'])([^"']+)(["'])/gi,     (m,p1,u,p2) => p1+rewrite(u)+p2)
      .replace(/url\(["']?([^"')]+)["']?\)/gi,          (m,u) => `url('${rewrite(u)}')`)
      .replace(/(window\.location(?:\.href)?\s*=\s*)(['"`])([^'"`]+)(['"`])/g,
        (m,pre,q1,url,q2) => pre+q1+rewrite(url)+q2);
  }

  return content.replace(/url\(["']?([^"')]+)["']?\)/gi, (m,u) => `url('${rewrite(u)}')`);
}

// ─── Catch-all → frontend ─────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ DTCWriter Proxy Server running on http://localhost:${PORT}`);
  console.log(`   Admin:    http://localhost:${PORT}  (admin / admin123)`);
  console.log(`   Customer: http://localhost:${PORT}  (customer / cust123)`);
  console.log(`   Proxy:    http://localhost:${PORT}/proxy/*\n`);
});

module.exports = app;
