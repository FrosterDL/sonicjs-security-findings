# Anonymous callers are exempt from the document ACL on the legacy /api/content read endpoints

- Product: SonicJS (`@sonicjs-cms/core`, npm)
- Affected: <= 3.0.0 (verified on 3.0.0)
- Severity (provisional): Moderate
- CWE: CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization)
- Finder: FrosterDL
- Verification: SonicJS @sonicjs-cms/core 3.0.0 (commit 68f6d23, 2026-11-13), live-verified 2026-11-16 on a stock reference-app configuration (Node adapter, SQLite, filesystem media) deployed by the finder.

## Summary
On the legacy REST content API (routes/api.ts, also api-content-crud.ts), the code decides whether the document ACL must be applied with `needsAcl = !isAnonymous && !canReadNonPublicContent(role)` - anonymous callers are explicitly exempted and receive only an `is_published = 1` filter. A collection or document that is published but NOT granted public access (the documented default for a collection without an `access` block is deny-public) is therefore readable by anyone without an account. The newer documents API (routes/api-documents.ts) applies the ACL to every principal including anonymous, so the same content is correctly hidden there - the two surfaces disagree, and the legacy one leaks.

## Impact
Unauthenticated disclosure of published-but-restricted content: collections intended for authenticated/internal audiences only, and per-document public-deny overrides, are readable by anyone. Drafts are NOT exposed by this issue (the published filter holds); this is a restricted-content confidentiality issue.

## Steps to reproduce
1. On a stock SonicJS 3.0.0, as an editor/admin publish an item in the stock `faq` collection (it defines no `access` block, so public access is denied by default).
2. Unauthenticated: GET /api/documents?type=faq -> [] (ACL enforced - control).
3. Unauthenticated: GET /api/content?collection=faq -> the published FAQ, including its answer text, is returned.

## Proof
See harness.py (check S-003) and EVIDENCE.md: the same FAQ marker was absent from /api/documents and present in /api/content for an anonymous caller.

## Suggested fix
Apply the document ACL to anonymous callers on the /api/content read paths exactly as api-documents.ts does; remove the anonymous exemption in the needsAcl computation and add an ACL check to the single-item handler in api-content-crud.ts.

## Duplicate check
Prior SonicJS CVE CVE-2026-119707 covers missing authorization on the /api/:collection and
/api/content *write* routes for authenticated authors/editors. This finding is a different
route/principal/class and was live-verified separately (see EVIDENCE.md).
