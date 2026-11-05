# Chrome HTTP/2 (Akamai) fingerprint — Scheme A

## Problem

The chatgpt.com / Codex uTLS path used `HelloChrome_*` for TLS, but built h2 with
`(&http2.Transport{}).NewClientConn`. That emits the **Go** Akamai fingerprint
(`a,m,p,s` pseudo order, Go SETTINGS including `MAX_FRAME_SIZE`), which
Cloudflare can flag as 1010 when JA3 looks like Chrome.

## Fix (this PR)

Only the **Chrome / chatgpt.com** branch of `helps.NewUtlsHTTPClient` changes:

| Knob | Value |
|------|--------|
| ClientHello | pinned `utls.HelloChrome_131` (not `HelloChrome_Auto`) |
| SETTINGS | `HEADER_TABLE_SIZE=65536`, `ENABLE_PUSH=0`, `INITIAL_WINDOW_SIZE=6291456`, `MAX_HEADER_LIST_SIZE=262144` (no `MAX_FRAME_SIZE`) |
| WINDOW_UPDATE (conn) | `15663105` |
| Pseudo order | `:method :authority :scheme :path` → Akamai `m,a,s,p` |

Implementation: `internal/runtime/executor/helps/chrome_h2.go` drives preface /
SETTINGS / headers with `http2.Framer` + `hpack` because `x/net/http2.Transport`
cannot emit this fingerprint (hard-coded SETTINGS order / `MAX_FRAME_SIZE` /
`a,m,p,s` EncodeHeaders).

Claude Code / Antigravity / non-chatgpt.com paths are unchanged. Proxy dialing
still goes through `proxyutil.BuildDialer`. RoundTrippers are cached by proxy URL
(`chromeRoundTripperCache`); an open response body (SSE) holds the connection
until `Body.Close`.

## Verify against peet.ws

```bash
COMPARE_GO=1 go run ./scripts/verify_chrome_h2_peet.go
```

Captured 2026-11-05 (Asia/Shanghai):

| | Chrome_131 + scheme A | Go `net/http` baseline |
|--|--|--|
| akamai_fingerprint | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | `2:0;4:4194304;5:1048576;6:10485760\|1073741824\|0\|a,m,p,s` |
| akamai hash | `52d84b11737d980aef856699f885ca86` | `b4e6bd27e907d4aa4316619ce615fda4` |
| ja4 | `t13d1516h2_8daaf6152771_02713d6af862` | `t13d1312h2_f57a46bbacb6_f50d94e863eb` |

## Out of scope

- Scheme B: `HTTPWireProfile.TLSClientProfile` for plugins (TODO comment only).
- Scheme C: codearts/reg bypass clients.
- Deploy / merge to upstream / online CPA.

## Risks

- Custom Framer client is single-stream-busy per connection; concurrent requests
  on one conn get "connection busy" and dial fresh (idle pool mitigates).
- Header order after pseudos follows Go map iteration (not full Chrome header
  order fingerprint). Akamai SETTINGS/WU/pseudo are the CF-sensitive bits.
