# Stored DOM XSS in admin search via unauthenticated search-history poisoning

- Product: SonicJS (`@sonicjs-cms/core`, npm)
- Affected: <= 3.0.0 (verified on 3.0.0)
- Severity (provisional): Moderate
- CWE: CWE-79 (Cross-site Scripting)
- Finder: FrosterDL
- Verification: SonicJS @sonicjs-cms/core 3.0.0 (commit 68f6d23, 2026-11-13), live-verified 2026-11-16 on a stock reference-app configuration (Node adapter, SQLite, filesystem media) deployed by the finder.

## Summary
POST /api/search is unauthenticated and persists the caller's query string verbatim as search history (capped at 200 chars). GET /api/search/suggest returns prior queries verbatim. The admin Advanced Search UI (templates/pages/admin-content-list.template.ts, duplicated in the ai-search search-modal) renders suggestions and result titles by assigning them to innerHTML with no escaping, and the application sets no Content-Security-Policy. An unauthenticated attacker therefore seeds a payload such as `sonic<img src=x onerror=alert(document.domain)>`; when an admin later types the matching prefix (e.g. "so") in Advanced Search, the suggestion is inserted as HTML and the event handler executes in the admin's session.

## Impact
Unauthenticated-to-admin stored DOM cross-site scripting: no account is needed to plant the payload, and it fires in an administrator's browser during normal content search.

## Steps to reproduce
1. Unauthenticated: POST /api/search {"query":"sonic<img src=x onerror=alert(document.domain)>"} (twice, to register in history).
2. GET /api/search/suggest?q=so -> returns ["sonic<img src=x onerror=alert(document.domain)>"] verbatim.
3. An admin opening Advanced Search in the content list and typing "so" receives the suggestion through the innerHTML sink in admin-content-list.template.ts, executing the handler.

## Proof
See harness.py (check S-006) and EVIDENCE.md: live suggest response captured verbatim; sink verified in the shipped template source.

## Suggested fix
Render suggestions with textContent (or escape before insertion) in both the content-list template and the ai-search modal, and/or strip HTML metacharacters from stored search queries.

## Duplicate check
Prior SonicJS CVE CVE-2026-119707 covers missing authorization on the /api/:collection and
/api/content *write* routes for authenticated authors/editors. This finding is a different
route/principal/class and was live-verified separately (see EVIDENCE.md).
