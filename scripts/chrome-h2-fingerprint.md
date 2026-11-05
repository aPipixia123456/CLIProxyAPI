# Chrome / browser HTTP/2 (Akamai) fingerprint — Scheme A + per-account profiles

## Problem

The chatgpt.com / Codex uTLS path used `HelloChrome_*` for TLS, but built h2 with
`(&http2.Transport{}).NewClientConn`. That emits the **Go** Akamai fingerprint
(`a,m,p,s` pseudo order, Go SETTINGS including `MAX_FRAME_SIZE`), which
Cloudflare can flag as 1010 when JA3 looks like Chrome.

## Fix (this PR)

Only the **Chrome / chatgpt.com** branch of `helps.NewUtlsHTTPClient` changes:

| Knob | Value |
|------|--------|
| Default ClientHello | pinned `utls.HelloChrome_131` (not `HelloChrome_Auto`) |
| Default SETTINGS | `HEADER_TABLE_SIZE=65536`, `ENABLE_PUSH=0`, `INITIAL_WINDOW_SIZE=6291456`, `MAX_HEADER_LIST_SIZE=262144` (no `MAX_FRAME_SIZE`) |
| WINDOW_UPDATE (conn) | `15663105` |
| Pseudo order | `:method :authority :scheme :path` → Akamai `m,a,s,p` |

Implementation: `chrome_h2.go` drives preface / SETTINGS / headers with
`http2.Framer` + `hpack`. Profile tables live in `browser_fingerprint.go` so
TLS ClientHello and H2 Akamai stay **paired** (never mix Chrome TLS + Safari H2).

Claude Code / Antigravity / non-chatgpt.com paths are unchanged. Proxy dialing
still goes through `proxyutil.BuildDialer`.

## One account, one fingerprint

Codex auth JSON may set `fingerprint_profile` (also accepted as
`fingerprint-profile`). CPA copies it onto `auth.Attributes` /
`auth.Metadata` the same way as other credential fields (`proxy_url`, Claude
`fingerprint_profile`).

| Profile | ClientHello (utls) | Akamai H2 target | Suggested UA |
|---------|--------------------|------------------|--------------|
| `chrome_131` (default) | `HelloChrome_131` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | Chrome/131 … Safari/537.36 |
| `chrome_120` | `HelloChrome_120` | same Chrome Akamai (JA3 differs) | Chrome/120 … Safari/537.36 |
| `safari_17` | `HelloSafari_16_0` (utls desktop Safari ceiling) | `4:4194304;3:100\|10485760\|0\|m,s,p,a` | Version/17.0 Safari/605.1.15 |

Notes:

- Empty / unknown / `claude-code-cli` on this path → `chrome_131`.
- utls v1.8.2 has **no** `HelloChrome_124`; use `chrome_120` as the second Chrome identity.
- Connection pool key is `(proxyURL, fingerprint_profile)` so different profiles never share a TLS/H2 conn.
- Application User-Agent is **not** rewritten by the transport. If you set a custom UA on the account, keep it aligned with the profile version (document only; optional override left to operators).

### Auth JSON examples (3 Codex accounts)

```json
{
  "type": "codex",
  "email": "a@example.com",
  "proxy_url": "socks5://1.2.3.4:1080",
  "fingerprint_profile": "chrome_131"
}
```

```json
{
  "type": "codex",
  "email": "b@example.com",
  "proxy_url": "socks5://5.6.7.8:1080",
  "fingerprint_profile": "chrome_120"
}
```

```json
{
  "type": "codex",
  "email": "c@example.com",
  "proxy_url": "socks5://9.9.9.9:1080",
  "fingerprint_profile": "safari_17"
}
```

## Verify against peet.ws

```bash
PROFILE=all go run ./scripts/verify_chrome_h2_peet.go
COMPARE_GO=1 PROFILE=chrome_131 go run ./scripts/verify_chrome_h2_peet.go
```

Captured 2026-11-05 (Asia/Shanghai):

| Profile | ja3_hash (GREASE-sensitive) | ja4 | akamai_fingerprint |
|---------|-----------------------------|-----|--------------------|
| chrome_131 | (varies with GREASE) | `t13d1516h2_8daaf6152771_02713d6af862` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| chrome_120 | different ja3 string / hash vs 131 | same JA4 family as 131 | same Chrome Akamai |
| safari_17 | distinct | `t13d2014h2_a09f3c656075_14788d8d241b` | `4:4194304;3:100\|10485760\|0\|m,s,p,a` |

Go `net/http` baseline Akamai remains
`2:0;4:4194304;5:1048576;6:10485760|1073741824|0|a,m,p,s`.

## Flow-control (kept)

`chromeH2Conn` splits connection vs stream send windows (RFC 7540 §6.9). Do not
regress to a single `sendWin` overwritten by peer `SETTINGS_INITIAL_WINDOW_SIZE`.

## Out of scope

- Scheme B: `HTTPWireProfile.TLSClientProfile` for plugins (TODO comment only).
- Scheme C: codearts/reg bypass clients.
- Deploy / merge to upstream / online CPA / hosts 104 & 156.

## Risks

- Custom Framer client is single-stream-busy per connection; concurrent requests
  on one conn get "connection busy" and dial fresh (idle pool mitigates).
- Header order after pseudos follows Go map iteration (not full Chrome header
  order fingerprint). Akamai SETTINGS/WU/pseudo are the CF-sensitive bits.
- chrome_120 and chrome_131 share Akamai + JA4 family; diversity is mainly JA3
  extension order. Prefer safari_17 when you need a fully distinct Akamai/JA4.

## 104 verification checklist (bookworm + CGO) — for pipixia

Do **not** deploy from this PR automatically. On host **104** only, after an
explicit rebuild:

1. Build on **Debian bookworm** with **`CGO_ENABLED=1`** (box/`CGO=0` breaks plugins).
2. Binary tag/name should identify this commit (e.g. `v8.0.56-chrome-h2-<shortsha>`).
3. Keep existing **一号一 IP** (`proxy_url` per Codex auth JSON); add distinct
   `fingerprint_profile` per account (`chrome_131` / `chrome_120` / `safari_17`).
4. Align custom UA with the profile when present; otherwise leave Codex UA as-is.
5. Smoke: one non-stream Codex call per account → no CF 1010 / unexpected 403.
6. Smoke: large POST + SSE stream → no `FLOW_CONTROL_ERROR` / `chrome h2: stream reset`.
7. Confirm logs show no cross-profile connection reuse surprises; different
   profiles must not share pooled conns (pool key includes profile).
8. Do **not** touch host **156** in this batch. Do **not** merge upstream until
   104 smoke is green.
