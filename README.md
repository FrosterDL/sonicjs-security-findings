# SonicJS Security Findings

Security research by FrosterDL.

Findings against SonicJS `@sonicjs-cms/core` 3.0.0 (source commit 68f6d23, 2026-11-13),
each reproduced live on a stock deployment of the shipped reference application
(Node adapter, SQLite, filesystem media) on 2026-11-16.

| ID | Finding | Severity (provisional) |
|----|---------|------------------------|
| S-GQL | [GraphQL resolvers do not enforce document ACLs: unauthenticated draft/internal disclosure and low-privilege create-and-publish](S-GQL-graphql-acl.md) | High |
| S-RESTACL | [Anonymous callers are exempt from the document ACL on the legacy /api/content read endpoints](S-RESTACL-anon-read.md) | Moderate |
| S-SVG | [Stored XSS via SVG upload served inline from the CMS origin](S-SVG-stored-xss.md) | High |
| S-SEL | [Stored XSS in the admin media selector via unescaped media alt text](S-SEL-media-selector-xss.md) | Moderate |
| S-SEARCH | [Stored DOM XSS in admin search via unauthenticated search-history poisoning](S-SEARCH-suggest-xss.md) | Moderate |

- [EVIDENCE.md](EVIDENCE.md) — full live-reproduction log with control-vs-attack results.
- [harness.py](harness.py) — re-runs the automated checks (S-001/S-002/S-003/S-004/S-006) against a running instance.
- [selector-evidence.html](selector-evidence.html) — captured admin media-selector response for S-SEL.

Note: the upstream repository has private vulnerability reporting disabled and no
security policy, so these findings are published here and submitted to VulDB for
CVE assignment. Prior related CVE: CVE-2026-119707 (write-side content ACL bypass)
is a different issue from S-RESTACL (anonymous read side); see each report.
