/**
 * DTCWriter Reverse Proxy Server — Revised
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
    targetUrl: '',
    mode: 'server',
    cookies: [],
    headers: {},
    stripResponseHeaders: [
      'x-frame-options',
      'content-security-policy',
      'x-xss-protection',
      'strict-transport-security',
    ],
  },
  admins:  [{ username: 'admin', password: 'admin123' }],
  nextId: 6,
};

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
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
  secret:            SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    secure:   process.env.NODE_ENV === 'production',
    maxAge:   8 * 60 * 60 * 1000,
  },
}));

app.use(express.static(path.join(__dirname, '../public')));

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
app.get('/api/proxy-config', requireAdmin, (req, res) => res.json(db.proxyConfig));

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
    res.setHeader('Access-Control-Allow-Headers',     'Content-Type,Authorization,Cookie,X-CSRF-Token,X-XSRF-Token,X-Requested-With');
    return res.status(204).end();
  }

  // ── Build upstream URL ─────────────────────────────────────────────────────
  const subPath = req.url === '/' ? '' : req.url;
  const target  = new URL(subPath || '/', base);

  // ── Build cookie string ────────────────────────────────────────────────────
  const injected     = (cookies || []).map(c => `${c.name}=${c.value}`).join('; ');
  const fromBrowser  = req.headers['cookie'] || '';
  const cookieHeader = [injected, fromBrowser].filter(Boolean).join('; ');

  // ── FIX 1: Spoof origin/referer — tricks second site into allowing request ─
  const forwardHeaders = {
    'host':              base.host,
    'origin':            base.origin,
    'referer':           base.origin + (subPath || '/'),
    'accept':            req.headers['accept']          || '*/*',
    'accept-language':   req.headers['accept-language'] || 'en-US,en;q=0.9',
    'accept-encoding':   'identity',
    'user-agent':        req.headers['user-agent']      || 'Mozilla/5.0 DTCWriter-Proxy/1.0',
    'x-forwarded-host':  base.host,
    'x-forwarded-proto': 'https',
    'x-requested-with':  'XMLHttpRequest',
  };

  if (cookieHeader)                     forwardHeaders['cookie']           = cookieHeader;
  if (req.headers['content-type'])      forwardHeaders['content-type']     = req.headers['content-type'];
  if (req.headers['x-requested-with'])  forwardHeaders['x-requested-with'] = req.headers['x-requested-with'];

  // ── FIX 2: Replay saved CSRF token on every write request ─────────────────
  const isWrite   = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
  const savedCSRF = csrfTokenStore[req.session.id];

  if (isWrite && savedCSRF) {
    forwardHeaders['x-csrf-token'] = savedCSRF;
    forwardHeaders['x-xsrf-token'] = savedCSRF;
    console.log(`[Proxy] CSRF token injected: ${savedCSRF.substring(0, 12)}…`);
  }

  // Merge admin extra headers last — they override everything
  Object.assign(forwardHeaders, extraHeaders || {});

  // ── FIX 4: Build body correctly per content-type ───────────────────────────
  let body = undefined;
  if (isWrite) {
    const ct = (req.headers['content-type'] || '').toLowerCase();

    if (ct.includes('application/x-www-form-urlencoded')) {
      const params = new URLSearchParams(req.body);
      // FIX 3: Inject CSRF token into form fields under all common names
      if (savedCSRF) {
        params.set('_csrf',               savedCSRF);
        params.set('_token',              savedCSRF);
        params.set('csrfmiddlewaretoken', savedCSRF);
        params.set('authenticity_token',  savedCSRF);
      }
      body = params.toString();
      forwardHeaders['content-type']   = 'application/x-www-form-urlencoded';
      forwardHeaders['content-length'] = Buffer.byteLength(body).toString();

    } else if (ct.includes('multipart/form-data')) {
      body = req; // stream raw — do not touch multipart boundary
      forwardHeaders['content-type'] = req.headers['content-type'];

    } else {
      // JSON or unknown
      let parsed;
      const raw = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
      try { parsed = JSON.parse(raw); } catch { parsed = null; }
      if (parsed && savedCSRF) {
        parsed._csrf  = parsed._csrf  || savedCSRF;
        parsed._token = parsed._token || savedCSRF;
        body = JSON.stringify(parsed);
      } else {
        body = raw;
      }
      forwardHeaders['content-type']   = 'application/json';
      forwardHeaders['content-length'] = Buffer.byteLength(body).toString();
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
      'cross-origin-opener-policy',
      'cross-origin-embedder-policy',
      'cross-origin-resource-policy',
    ]);
    const adminStrip = (stripResponseHeaders || []).map(h => h.toLowerCase());

    upstream.headers.forEach((value, key) => {
      const lk = key.toLowerCase();

      // Strip frame-busting / security headers
      if (alwaysStrip.has(lk) || adminStrip.includes(lk)) return;

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

      // FIX 5: Rewrite Set-Cookie for cross-site delivery
      if (lk === 'set-cookie') {
        const rewritten = value
          .replace(/Domain=[^;,\s]+[;,]?\s*/gi, '') // strip original domain
          .replace(/SameSite=\w+/gi, 'SameSite=None') // must be None cross-site
          .replace(/;\s*$/, '')
          + '; Secure; Path=/';
        res.append('Set-Cookie', rewritten);
        return;
      }

      res.setHeader(key, value);
    });

    // Inject permissive framing + CORS
    res.setHeader('X-Frame-Options',              'SAMEORIGIN');
    res.setHeader('Content-Security-Policy',      "frame-ancestors 'self'");
    res.setHeader('Access-Control-Allow-Origin',      req.headers['origin'] || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.status(upstream.status);

    // ── Rewrite body ───────────────────────────────────────────────────────
    const contentType = (upstream.headers.get('content-type') || '').toLowerCase();

    // ── JSON / XML — pass through untouched so validation responses ─────────
    // are never mangled by the URL rewriter. This is the main reason
    // buttons stay disabled after typing — the validation API response
    // was being rewritten and the JS couldn't parse it.
    if (
      contentType.includes('application/json') ||
      contentType.includes('text/json')        ||
      contentType.includes('application/xml')  ||
      contentType.includes('text/xml')         ||
      contentType.includes('text/plain')
    ) {
      const raw = await upstream.text();
      res.setHeader('Content-Type', contentType);
      res.setHeader('Access-Control-Allow-Origin',      req.headers['origin'] || '*');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      console.log(`[Proxy] JSON passthrough: ${target.pathname} (${raw.length} bytes)`);
      return res.send(raw);
    }

    const isHtml = contentType.includes('text/html');
    const isCss  = contentType.includes('text/css');
    const isJs   = contentType.includes('javascript');

    if (isHtml || isCss || isJs) {
      let text = await upstream.text();

      // FIX 2: Extract CSRF token from HTML and save for next POST
      if (isHtml) {
        const token = extractCSRFToken(text);
        if (token) {
          csrfTokenStore[req.session.id] = token;
          console.log(`[Proxy] CSRF token saved: ${token.substring(0, 12)}…`);
        }
      }

      text = rewriteUrls(text, base, isHtml, isJs);

      // FIX 6+7: Inject runtime interceptor into every HTML page
      if (isHtml) {
        const interceptor = buildInterceptor(base, savedCSRF || '');
        text = text.replace(/<head([^>]*)>/i, m => m + interceptor);

        // Fix forms with no action — default to current proxy path
        text = text.replace(/<form([^>]*)>/gi, (m, attrs) => {
          if (!attrs.includes('action')) return `<form${attrs} action="/proxy/">`;
          return m;
        });
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
function buildInterceptor(base, csrfToken) {
  return `
<script>
(function(){
  var BASE   = '${base.origin}';
  var CSRF   = '${csrfToken}';

  // Convert any URL pointing to the second site into a /proxy/... path
  function fixUrl(u) {
    if (!u || typeof u !== 'string') return u;
    if (u.startsWith('/proxy') || u.startsWith('data:') ||
        u.startsWith('mailto:') || u.startsWith('tel:') ||
        u.startsWith('#') || u.startsWith('blob:')) return u;
    if (u.startsWith('/'))    return '/proxy' + u;
    if (u.startsWith(BASE))  return '/proxy' + u.slice(BASE.length);
    return u;
  }

  // Read CSRF token from the page (always prefer live value over injected)
  function getCSRF() {
    var selectors = [
      'meta[name="csrf-token"]',
      'meta[name="_token"]',
      'meta[name="csrf"]',
    ];
    for (var i = 0; i < selectors.length; i++) {
      var el = document.querySelector(selectors[i]);
      if (el) return el.getAttribute('content');
    }
    var inputs = [
      'input[name="_csrf"]', 'input[name="_token"]',
      'input[name="csrfmiddlewaretoken"]', 'input[name="authenticity_token"]',
    ];
    for (var j = 0; j < inputs.length; j++) {
      var inp = document.querySelector(inputs[j]);
      if (inp) return inp.value;
    }
    return CSRF;
  }

  // Inject CSRF token into a headers object
  function injectCSRF(headers, method) {
    if (['GET','HEAD'].indexOf((method||'GET').toUpperCase()) !== -1) return headers;
    var token = getCSRF();
    if (!token) return headers;
    if (typeof headers.set === 'function') {
      headers.set('X-CSRF-Token',  token);
      headers.set('X-XSRF-Token',  token);
    } else {
      headers['X-CSRF-Token']  = token;
      headers['X-XSRF-Token']  = token;
    }
    return headers;
  }

  // ── Patch fetch() ────────────────────────────────────────────────────────
  var _fetch = window.fetch;
  window.fetch = function(input, init) {
    init = Object.assign({ credentials: 'include' }, init || {});
    if (typeof input === 'string') {
      input = fixUrl(input);
    } else if (input && input.url) {
      input = new Request(fixUrl(input.url), input);
    }
    init.headers = injectCSRF(init.headers || {}, init.method);
    return _fetch(input, init);
  };

  // ── Patch XMLHttpRequest ──────────────────────────────────────────────────
  var _open = XMLHttpRequest.prototype.open;
  var _send = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
    this._dtcMethod = method;
    return _open.call(this, method, fixUrl(url),
      async !== undefined ? async : true, user, pass);
  };

  XMLHttpRequest.prototype.send = function(body) {
    this.withCredentials = true;
    if (['GET','HEAD'].indexOf((this._dtcMethod || 'GET').toUpperCase()) === -1) {
      var token = getCSRF();
      if (token) {
        try { this.setRequestHeader('X-CSRF-Token', token); } catch(e) {}
        try { this.setRequestHeader('X-XSRF-Token', token); } catch(e) {}
      }
    }
    return _send.call(this, body);
  };

  // ── Patch location navigations ────────────────────────────────────────────
  try {
    var _assign  = window.location.assign.bind(window.location);
    var _replace = window.location.replace.bind(window.location);
    window.location.assign  = function(u) { _assign(fixUrl(u)); };
    window.location.replace = function(u) { _replace(fixUrl(u)); };
  } catch(e) {}

  // ── Fix forms and links in DOM ────────────────────────────────────────────
  function fixDOM() {
    // Fix all forms
    document.querySelectorAll('form').forEach(function(f) {
      var action = f.getAttribute('action');
      if (action) f.setAttribute('action', fixUrl(action));

      // Inject CSRF token as hidden fields in every form
      var token = getCSRF();
      if (token) {
        ['_csrf', '_token', 'csrfmiddlewaretoken', 'authenticity_token'].forEach(function(name) {
          var existing = f.querySelector('[name="' + name + '"]');
          if (existing) {
            existing.value = token;
          } else {
            var inp = document.createElement('input');
            inp.type  = 'hidden';
            inp.name  = name;
            inp.value = token;
            f.appendChild(inp);
          }
        });
      }

      // Re-fix action on submit in case JS changed it
      f.addEventListener('submit', function() {
        var a = f.getAttribute('action');
        if (a && !a.startsWith('/proxy')) f.setAttribute('action', fixUrl(a));
      }, true);
    });

    // Fix all links
    document.querySelectorAll('a[href]').forEach(function(a) {
      var h = a.getAttribute('href');
      if (h && !h.startsWith('#') && !h.startsWith('mailto:') && !h.startsWith('tel:')) {
        a.setAttribute('href', fixUrl(h));
      }
    });

    // ── Fix button activation after typing ───────────────────────────────
    // Many frameworks (React/Vue) disable buttons until input is valid.
    // They listen for 'input' and 'change' events to re-run validation.
    // Through the proxy the validation API response is now passed through
    // cleanly (JSON passthrough) but we also re-fire native events so
    // the framework's validation logic re-runs and enables the button.
    document.querySelectorAll('input, textarea, select').forEach(function(el) {
      // Don't double-attach
      if (el._dtcFixed) return;
      el._dtcFixed = true;

      el.addEventListener('input', function() {
        setTimeout(function() {
          // Re-fire all events the framework might be listening to
          ['input','change','keyup','blur'].forEach(function(evtName) {
            try {
              var evt = new Event(evtName, { bubbles: true, cancelable: true });
              el.dispatchEvent(evt);
            } catch(e) {}
          });

          // Also re-evaluate any disabled buttons in the same form
          var form = el.closest('form');
          if (form) {
            form.querySelectorAll('button[disabled], input[type="submit"][disabled]').forEach(function(btn) {
              // Check if all required fields have values
              var allFilled = true;
              form.querySelectorAll('[required]').forEach(function(req) {
                if (!req.value || req.value.trim() === '') allFilled = false;
              });
              if (allFilled) {
                btn.removeAttribute('disabled');
                btn.disabled = false;
              }
            });
          }
        }, 150);
      }, true);
    });
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', fixDOM);
  } else {
    fixDOM();
  }

  // ── FIX 7: Watch for dynamically added content (React, Vue, AJAX) ─────────
  new MutationObserver(function(mutations) {
    mutations.forEach(function(m) {
      m.addedNodes.forEach(function(node) {
        if (!node.querySelectorAll) return;

        // Fix forms
        node.querySelectorAll('form').forEach(function(f) {
          var a = f.getAttribute('action');
          if (a) f.setAttribute('action', fixUrl(a));
          var token = getCSRF();
          if (token) {
            var inp = f.querySelector('[name="_csrf"]');
            if (!inp) {
              inp = document.createElement('input');
              inp.type = 'hidden'; inp.name = '_csrf';
              f.appendChild(inp);
            }
            inp.value = token;
          }
        });

        // Fix links
        node.querySelectorAll('a[href]').forEach(function(a) {
          var h = a.getAttribute('href');
          if (h && !h.startsWith('#') && !h.startsWith('mailto:')) {
            a.setAttribute('href', fixUrl(h));
          }
        });

        // Fix inputs — re-attach validation event re-dispatcher
        node.querySelectorAll('input, textarea, select').forEach(function(el) {
          if (el._dtcFixed) return;
          el._dtcFixed = true;
          el.addEventListener('input', function() {
            setTimeout(function() {
              ['input','change','keyup','blur'].forEach(function(evtName) {
                try {
                  el.dispatchEvent(new Event(evtName, { bubbles: true, cancelable: true }));
                } catch(e) {}
              });
              var form = el.closest('form');
              if (form) {
                form.querySelectorAll('button[disabled], input[type="submit"][disabled]').forEach(function(btn) {
                  var allFilled = true;
                  form.querySelectorAll('[required]').forEach(function(req) {
                    if (!req.value || req.value.trim() === '') allFilled = false;
                  });
                  if (allFilled) {
                    btn.removeAttribute('disabled');
                    btn.disabled = false;
                  }
                });
              }
            }, 150);
          }, true);
        });
      });
    });
  }).observe(document.documentElement, { childList: true, subtree: true });

  console.log('[DTCWriter] Interceptors active for', BASE);
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
