# DTCWriter Control Panel — Backend Proxy Server

A full-stack Node.js application with:
- **Admin portal** — manage users, packages, issues, proxy config & cookies
- **Customer portal** — dashboard, package view, issue reporting
- **Server-side reverse proxy** at `/proxy/*` with cookie injection, header rewriting, and frame-busting header stripping

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Copy and edit environment file
cp .env.example .env
# Edit .env — at minimum change SESSION_SECRET

# 3. Start the server
npm start
# → http://localhost:3000
```

### Demo accounts
| Role     | Username   | Password   |
|----------|------------|------------|
| Admin    | `admin`    | `admin123` |
| Customer | `customer` | `cust123`  |

---

## Architecture

```
dtcwriter/
├── src/
│   └── server.js        ← Express app, all API routes, proxy handler
├── public/
│   └── index.html       ← Single-page frontend (served as static)
├── package.json
├── .env.example
└── README.md
```

---

## API Reference

### Auth
| Method | Path              | Auth     | Description         |
|--------|-------------------|----------|---------------------|
| POST   | /api/auth/login   | —        | Login               |
| POST   | /api/auth/logout  | session  | Logout              |
| GET    | /api/auth/me      | session  | Current session     |

### Users (admin only except /me)
| Method | Path              | Auth     | Description         |
|--------|-------------------|----------|---------------------|
| GET    | /api/users        | admin    | List all users      |
| POST   | /api/users        | admin    | Create user         |
| PUT    | /api/users/:id    | admin    | Update user         |
| DELETE | /api/users/:id    | admin    | Delete user         |
| GET    | /api/users/me     | any      | Own profile         |

### Packages
| Method | Path              | Auth     | Description         |
|--------|-------------------|----------|---------------------|
| GET    | /api/packages     | any      | List packages       |
| POST   | /api/packages     | admin    | Create package      |
| PUT    | /api/packages/:id | admin    | Update package      |
| DELETE | /api/packages/:id | admin    | Delete package      |

### Issues
| Method | Path              | Auth     | Description         |
|--------|-------------------|----------|---------------------|
| GET    | /api/issues       | any      | List (filtered by role) |
| POST   | /api/issues       | any      | Create issue        |
| PUT    | /api/issues/:id   | admin    | Update issue        |
| DELETE | /api/issues/:id   | admin    | Delete issue        |

### Proxy Config (admin only)
| Method | Path              | Auth     | Description         |
|--------|-------------------|----------|---------------------|
| GET    | /api/proxy-config | admin    | Get proxy config    |
| PUT    | /api/proxy-config | admin    | Update proxy config |

### Reverse Proxy
| Method | Path    | Auth     | Description                          |
|--------|---------|----------|--------------------------------------|
| ANY    | /proxy/* | any     | Proxy to configured target + inject cookies |

---

## Proxy Features

The `/proxy/*` endpoint:
1. **Injects cookies** — all cookies configured in the admin panel are sent as a `Cookie:` header to the upstream target
2. **Injects extra headers** — any custom headers from the admin panel are forwarded
3. **Strips frame-busting headers** — `X-Frame-Options`, `Content-Security-Policy`, etc. are removed from responses so the site renders inside the DTCWriter iframe
4. **Rewrites relative URLs** — `href`, `src`, `action`, and CSS `url()` references are rewritten to route through `/proxy/`
5. **Handles redirects** — `Location` headers pointing to the same origin are rewritten to stay within the proxy

---

## Production Deployment

1. **Change `SESSION_SECRET`** in `.env`
2. **Add HTTPS** — use nginx or a reverse proxy in front:
   ```nginx
   server {
     listen 443 ssl;
     server_name yourapp.com;
     location / { proxy_pass http://localhost:3000; proxy_set_header Cookie $http_cookie; }
   }
   ```
3. **Replace in-memory store** with a real database (PostgreSQL + Prisma recommended)
4. **Hash passwords** with bcrypt before storing

---

## Adding a Database (optional next step)

```bash
npm install prisma @prisma/client bcrypt
npx prisma init
```

Define your schema in `prisma/schema.prisma`, then replace the `db` object in `src/server.js` with Prisma client calls.
