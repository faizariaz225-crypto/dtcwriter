# Render proxy compatibility fix

This build is intended only for websites and API origins you own or are authorized to administer.
It is not a safe or reliable way to reuse a session from an unrelated third-party service.
For two applications you control, OAuth/OIDC, a signed JWT exchange, or a shared identity provider is the preferred production design.

## Why the page loaded but actions failed

The original injected browser script created a recursive event loop:

1. It listened for an `input` event.
2. Inside that listener, it dispatched another `input` event.
3. The second event ran the same listener again.

That can lock React/Vue state and make buttons, typing, and form actions appear broken.

The original proxy also:

- forwarded only a small set of request headers, dropping application-specific headers;
- rewrote JavaScript bundles using regular expressions, which can break minified code and hydration;
- handled multiple `Set-Cookie` headers as one combined string;
- mixed the control-panel session cookie with upstream cookies;
- did not support WebSocket upgrades;
- kept users, proxy configuration, and sessions only in process memory.

## Changes in this build

- Removed all synthetic React/Vue input events and forced button enabling.
- Added a small, non-recursive `fetch`, XHR, EventSource, and `sendBeacon` URL shim.
- Stopped rewriting JavaScript bundles.
- Preserved custom browser request headers.
- Forwarded JSON, forms, text, binary bodies, and multipart uploads correctly.
- Read each upstream `Set-Cookie` line separately and rewrote it for the proxy host.
- Renamed the control-panel cookie to `dtc.sid` so it is not sent upstream.
- Added a **Full page** button next to the iframe close button.
- Added optional Render environment variables for bootstrapping proxy configuration.

## Render settings

Create a **Web Service**.

- Build command: `npm ci`
- Start command: `npm start`
- Health check path: `/api/health`.
- Set `NODE_ENV=production`.
- Set a long random `SESSION_SECRET`.
- Keep all real cookie values in Render secret environment variables or a database.

Optional bootstrap variables:

```text
PROXY_TARGET_URL=https://second-site.example
PROXY_MODE=server
PROXY_COOKIES_JSON=[{"name":"your_session_cookie","value":"secret"}]
PROXY_HEADERS_JSON={}
PROXY_STRIP_HEADERS_JSON=["x-frame-options","content-security-policy","x-xss-protection","strict-transport-security"]
```

Do not commit a real `.env` file.

## Browser checks after deployment

Open Chrome DevTools inside the proxied page and inspect **Console** and **Network**.

- Requests to `/proxy/...` that return `200` indicate ordinary HTTP proxying is working.
- `401` or `403` from `/proxy/...` means the upstream rejected the supplied session, CSRF token, account state, or request headers.
- Requests going directly to another hostname indicate the second app uses a separate API origin. This build deliberately does not proxy arbitrary external origins. Configure the owned app to use same-origin API URLs or create an explicit allowlisted proxy for that owned API.
- Failed `ws://` or `wss://` requests mean the app requires WebSockets. This Express `fetch` proxy does not implement HTTP Upgrade; add a dedicated WebSocket reverse proxy for your owned endpoint.
- Failed file uploads should be checked for upstream body-size limits and Render request limits.

## Production limitations still remaining

The project uses an in-memory user database, plaintext demo passwords, and the default Express session store. A Render restart, redeploy, or scale-out can lose state or invalidate sessions. Move users/configuration to PostgreSQL, hash passwords with Argon2 or bcrypt, and use Redis/Render Key Value for sessions before real customer use.
