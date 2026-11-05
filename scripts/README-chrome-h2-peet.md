# verify_chrome_h2_peet.go

Standalone dialer that mirrors Scheme A (Chrome_131 ClientHello + Chrome Akamai
HTTP/2 SETTINGS) against `https://tls.peet.ws/api/all`.

```bash
COMPARE_GO=1 go run ./scripts/verify_chrome_h2_peet.go
```

See `docs/chrome-h2-fingerprint.md` for captured results and design notes.
Does not print or require any secrets.
