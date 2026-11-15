# Stored XSS via SVG upload: script-bearing SVG served inline from the CMS origin

- Product: SonicJS (`@sonicjs-cms/core`, npm)
- Affected: <= 3.0.0 (verified on 3.0.0)
- Severity (provisional): High
- CWE: CWE-79 (Cross-site Scripting), CWE-434 (Unrestricted Upload of File with Dangerous Type)
- Finder: FrosterDL
- Verification: SonicJS @sonicjs-cms/core 3.0.0 (commit 68f6d23, 2026-11-13), live-verified 2026-11-16 on a stock reference-app configuration (Node adapter, SQLite, filesystem media) deployed by the finder.

## Summary
The media upload allow-list includes `image/svg+xml` in both upload paths (routes/api-media.ts, routes/admin-media.ts). Validation checks only the client-supplied multipart MIME string; uploaded bytes are never sniffed or sanitised, and no SVG sanitiser exists anywhere in the codebase. The file is stored with the attacker-supplied content type and `Content-Disposition: inline`, and is then served by the unauthenticated GET /files/* handler with the stored headers verbatim, a one-year cache, wildcard CORS, and no Content-Security-Policy (the application sets no CSP at all, and no `sandbox` directive is applied to file responses). The upload gate is any authenticated account; public registration is enabled by default and grants the `viewer` role, so any self-registered user can plant a script-bearing SVG that executes in the CMS origin when a victim (e.g. an admin previewing media or following a link) navigates to it.

## Impact
Stored cross-site scripting in the CMS origin: session-adjacent actions and admin-context script execution when an authenticated user is lured to the file URL; persistent (1-year cache) and publicly fetchable without authentication.

## Steps to reproduce
1. Register a normal account (role `viewer`) on a stock SonicJS 3.0.0.
2. POST /api/media/upload (Bearer token, multipart) with file pwn.svg, type image/svg+xml, body: <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><script>alert(document.domain)</script></svg> -> upload succeeds.
3. Unauthenticated: GET /files/uploads/<uuid>.svg -> 200, Content-Type: image/svg+xml, Content-Disposition: inline, no Content-Security-Policy, body verbatim. Opening the URL in a browser executes the script in the CMS origin.
4. Control: unauthenticated upload is rejected (401) - the flaw is the authenticated low-privilege upload + inline same-origin serving, not anonymous upload.

## Proof
See harness.py (check S-004) and EVIDENCE.md: live response headers and body captured.

## Suggested fix
Remove image/svg+xml from the upload allow-list, or sanitise SVGs on upload (e.g. DOMPurify-style SVG profile) and serve user uploads with Content-Disposition: attachment or a `Content-Security-Policy: sandbox` header from a separate origin.

## Duplicate check
Prior SonicJS CVE CVE-2026-119707 covers missing authorization on the /api/:collection and
/api/content *write* routes for authenticated authors/editors. This finding is a different
route/principal/class and was live-verified separately (see EVIDENCE.md).
