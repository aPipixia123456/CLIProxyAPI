package helps

import (
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"golang.org/x/net/http2"
)

func TestResolveBrowserFingerprintProfileDefaultsAndAliases(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", BrowserFingerprintProfileChrome131},
		{"  ", BrowserFingerprintProfileChrome131},
		{"chrome_131", BrowserFingerprintProfileChrome131},
		{"Chrome_131", BrowserFingerprintProfileChrome131},
		{"chrome_120", BrowserFingerprintProfileChrome120},
		{"safari_17", BrowserFingerprintProfileSafari17},
		{"safari_16_0", BrowserFingerprintProfileSafari17},
		{"claude-code-cli", BrowserFingerprintProfileChrome131},
		{"not-a-profile", BrowserFingerprintProfileChrome131},
	}
	for _, tc := range cases {
		got := ResolveBrowserFingerprintProfile(tc.raw)
		if got.Name != tc.want {
			t.Fatalf("Resolve(%q).Name = %q, want %q", tc.raw, got.Name, tc.want)
		}
	}
}

func TestBrowserFingerprintProfilesAreSelfConsistent(t *testing.T) {
	seenAkamai := map[string]string{}
	seenHello := map[string]string{}
	for _, p := range SupportedBrowserFingerprintProfiles() {
		if p.ClientHello.Client == "" || p.ClientHello.Version == "" {
			t.Fatalf("%s missing ClientHello", p.Name)
		}
		if len(p.Settings) == 0 || len(p.PseudoOrder) != 4 || p.ConnWindowUpdate == 0 {
			t.Fatalf("%s incomplete H2 profile", p.Name)
		}
		helloKey := p.ClientHello.Client + "/" + p.ClientHello.Version
		if prev, ok := seenHello[helloKey]; ok {
			t.Fatalf("ClientHello %s shared by %s and %s", helloKey, prev, p.Name)
		}
		seenHello[helloKey] = p.Name

		akamai := p.akamaiFingerprint()
		// Chrome_120 and Chrome_131 intentionally share H2; TLS differs.
		if p.Name == BrowserFingerprintProfileChrome120 || p.Name == BrowserFingerprintProfileChrome131 {
			wantChrome := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
			if akamai != wantChrome {
				t.Fatalf("%s akamai = %q, want %q", p.Name, akamai, wantChrome)
			}
			continue
		}
		if prev, ok := seenAkamai[akamai]; ok {
			t.Fatalf("akamai %q shared by %s and %s", akamai, prev, p.Name)
		}
		seenAkamai[akamai] = p.Name
	}

	safari := ResolveBrowserFingerprintProfile(BrowserFingerprintProfileSafari17)
	wantSafari := "4:4194304;3:100|10485760|0|m,s,p,a"
	if got := safari.akamaiFingerprint(); got != wantSafari {
		t.Fatalf("safari akamai = %q, want %q", got, wantSafari)
	}
	if safari.Settings[0].ID != http2.SettingInitialWindowSize {
		t.Fatalf("safari settings order starts with %v", safari.Settings[0].ID)
	}
}

func TestBrowserFingerprintProfileFromAuth(t *testing.T) {
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{"fingerprint_profile": "safari_17"},
		Metadata:   map[string]any{"fingerprint_profile": "chrome_120"},
	}
	// Attributes win (same precedence as Claude path).
	if got := BrowserFingerprintProfileFromAuth(auth); got.Name != BrowserFingerprintProfileSafari17 {
		t.Fatalf("attributes win: got %s", got.Name)
	}
	auth2 := &cliproxyauth.Auth{Metadata: map[string]any{"fingerprint-profile": "chrome_120"}}
	if got := BrowserFingerprintProfileFromAuth(auth2); got.Name != BrowserFingerprintProfileChrome120 {
		t.Fatalf("metadata legacy key: got %s", got.Name)
	}
	if got := BrowserFingerprintProfileFromAuth(nil); got.Name != BrowserFingerprintProfileChrome131 {
		t.Fatalf("nil auth: got %s", got.Name)
	}
}

func TestCachedChromeRoundTripperKeysByProxyAndProfile(t *testing.T) {
	proxy := "socks5://127.0.0.1:1080"
	a := cachedChromeRoundTripperForProfile(proxy, browserFingerprintChrome131)
	b := cachedChromeRoundTripperForProfile(proxy, browserFingerprintChrome131)
	if a != b {
		t.Fatal("same proxy+profile should hit cache")
	}
	c := cachedChromeRoundTripperForProfile(proxy, browserFingerprintSafari17)
	if a == c {
		t.Fatal("different fingerprint_profile must not share RoundTripper")
	}
	d := cachedChromeRoundTripperForProfile("socks5://127.0.0.1:1081", browserFingerprintChrome131)
	if a == d {
		t.Fatal("different proxy must not share RoundTripper")
	}
	if chromeRoundTripperCacheKey(proxy, BrowserFingerprintProfileChrome131) == chromeRoundTripperCacheKey(proxy, BrowserFingerprintProfileSafari17) {
		t.Fatal("cache keys collided")
	}
}
