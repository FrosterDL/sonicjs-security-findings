# Stored XSS in the admin media selector via unescaped media alt text / original filename

- Product: SonicJS (`@sonicjs-cms/core`, npm)
- Affected: <= 3.0.0 (verified on 3.0.0)
- Severity (provisional): Moderate
- CWE: CWE-79 (Cross-site Scripting)
- Finder: FrosterDL
- Verification: SonicJS @sonicjs-cms/core 3.0.0 (commit 68f6d23, 2026-11-13), live-verified 2026-11-16 on a stock reference-app configuration (Node adapter, SQLite, filesystem media) deployed by the finder.

## Summary
GET /admin/media/selector (routes/admin-media.ts) builds its HTML with raw() interpolation of user-controlled media fields without escaping - notably `alt` in an <img> attribute and `original_name`. A low-privilege authenticated user controls both: the original filename at upload, and `alt` afterwards via PATCH /api/media/:id (owner-scoped, so any uploader can weaponise their own file). When an editor or admin opens the media selector (e.g. while editing content), the injected markup executes in their session context. The sibling /admin/media/search handler was previously fixed for exactly this class of bug (its code comment describes it as stored XSS via user-controlled filenames); the selector handler was missed. The main media grid/details templates correctly use escapeHtml, so this is a provable inconsistency.

## Impact
Stored cross-site scripting targeting editors/admins: a viewer-level uploader can execute script in an administrator's browser when the administrator opens the media picker, enabling admin-context actions.

## Steps to reproduce
1. As a self-registered viewer, upload any valid PNG via POST /api/media/upload.
2. PATCH /api/media/<id> {"alt": "\"><svg onload=alert(document.domain)>"} -> update succeeds.
3. As an admin/editor, open GET /admin/media/selector -> the response HTML contains the payload verbatim as a live element: alt=""><svg onload=alert(document.domain)>" - the injected SVG fires onload when the page renders.

## Proof
See EVIDENCE.md and selector-evidence.html in the proof repository: the admin selector response captured live contains the injected element unescaped.

## Suggested fix
Escape all interpolated media fields in the selector handler with the existing escapeHtml helper (as the grid/details templates and the fixed /search handler already do), including attribute contexts.

## Duplicate check
Prior SonicJS CVE CVE-2026-119707 covers missing authorization on the /api/:collection and
/api/content *write* routes for authenticated authors/editors. This finding is a different
route/principal/class and was live-verified separately (see EVIDENCE.md).
