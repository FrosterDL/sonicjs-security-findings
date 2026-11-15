# GraphQL resolvers do not enforce document ACLs: unauthenticated draft/internal disclosure and low-privilege create-and-publish

- Product: SonicJS (`@sonicjs-cms/core`, npm)
- Affected: <= 3.0.0 (verified on 3.0.0)
- Severity (provisional): High
- CWE: CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization)
- Finder: FrosterDL
- Verification: SonicJS @sonicjs-cms/core 3.0.0 (commit 68f6d23, 2026-11-13), live-verified 2026-11-16 on a stock reference-app configuration (Node adapter, SQLite, filesystem media) deployed by the finder.

## Summary
The GraphQL plugin (enabled with default options in the shipped reference application, my-sonicjs-app/src/index.ts) does not enforce the document access-control model that the REST documents API enforces.

1) Read side (unauthenticated): the `documents` query honours caller-supplied `status: "draft"` / `"all"` for anonymous callers and never applies the per-type/per-document ACL (`isAllowed`). The `document(id:)` query likewise returns a document in any state, including drafts and soft-deleted rows. Internal, admin-only document types are not excluded, so anonymous callers can read draft content, RBAC assignments (`rbac_user_roles`, including which user IDs hold the admin role), RBAC role definitions, plugin records and other internal documents.
2) Write side (low-privilege): `createDocument` checks only that *some* user is authenticated. Unlike every sibling mutation (update/publish/delete), it never calls `requireWritePermission()`, and it passes the attacker-controlled `publishOnCreate` flag through. A self-registered `viewer` account (public registration is enabled by default and grants `viewer`) can therefore create and immediately publish content of any type, which then appears on the public site/API.

## Impact
Unauthenticated disclosure of unpublished drafts and internal system documents (including RBAC user-to-role assignments); content-integrity compromise by the lowest-privilege registered account, which can publish arbitrary content without any editorial review.

## Steps to reproduce
1. Run SonicJS 3.0.0 with the GraphQL plugin registered with defaults (as in the shipped reference app) and an editor/admin creates a draft post (publishOnCreate: false).
2. Unauthenticated: POST /graphql {"query":"{ documents(status:\"draft\", limit:50) { items { id title data } } }"} -> the draft, including its full body, is returned. POST /graphql {"query":"{ documents(status:\"all\", limit:100) { items { typeId data } } }"} -> internal types incl. rbac_user_roles are returned. POST /graphql with document(id:) for the draft id returns it directly.
3. Control: unauthenticated GET /api/documents?type=blog_post&status=draft returns only published items - the REST surface enforces the model the GraphQL surface skips.
4. Register a normal account (granted role `viewer`), then: POST /graphql mutation { createDocument(typeId:"blog_post", title:"PWN", slug:"pwn", data:{...}, publishOnCreate:true) { id } } -> succeeds and the post is publicly visible via GET /api/documents.

## Proof
See harness.py (checks S-001/S-002) and EVIDENCE.md in the proof repository: live run captured the draft body marker, the rbac_user_roles admin assignment, and the viewer-published document id.

## Suggested fix
Apply the same authorization as the REST documents API in the GraphQL resolvers: force published-only + schedule window for anonymous callers, filter every result through the document ACL (isAllowed) including internal-type exclusion, and call requireWritePermission('create') (and 'publish' when publishOnCreate is set) in createDocument.

## Duplicate check
Prior SonicJS CVE CVE-2026-119707 covers missing authorization on the /api/:collection and
/api/content *write* routes for authenticated authors/editors. This finding is a different
route/principal/class and was live-verified separately (see EVIDENCE.md).
