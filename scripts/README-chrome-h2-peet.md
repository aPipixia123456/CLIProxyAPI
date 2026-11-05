# verify_chrome_h2_peet.go

Standalone dialer that mirrors Scheme A browser profiles (matched ClientHello +
Akamai HTTP/2 SETTINGS) against `https://tls.peet.ws/api/all`.

```bash
PROFILE=all go run ./scripts/verify_chrome_h2_peet.go
PROFILE=chrome_131 COMPARE_GO=1 go run ./scripts/verify_chrome_h2_peet.go
PROFILE=safari_17 go run ./scripts/verify_chrome_h2_peet.go
```

Supported `PROFILE` values: `chrome_131` (default), `chrome_120`, `safari_17`, `all`.

See `docs/chrome-h2-fingerprint.md` for captured results, auth JSON examples, and
the 104 bookworm+CGO verification checklist. Does not print or require secrets.
