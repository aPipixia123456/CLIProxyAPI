package helps

import (
	"fmt"
	"strings"
	"sync"

	tls "github.com/refraction-networking/utls"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// Browser fingerprint_profile values for the chatgpt.com / Codex Chrome path.
// These are distinct from Claude's fingerprint_profile=claude-code-cli (request
// wire identity). Unknown or Claude-only values fall back to chrome_131.
//
// Each profile pairs one uTLS ClientHelloID with matching HTTP/2 Akamai
// SETTINGS / WINDOW_UPDATE / pseudo-header order (bogdanfinn/tls-client tables).
// Do not mix a Chrome ClientHello with Safari H2 (or vice versa).
const (
	BrowserFingerprintProfileChrome131 = "chrome_131"
	BrowserFingerprintProfileChrome120 = "chrome_120"
	BrowserFingerprintProfileSafari17  = "safari_17"

	browserFingerprintProfileAttr = "fingerprint_profile"
)

// browserFingerprintProfile is one matched TLS+H2 browser identity.
type browserFingerprintProfile struct {
	Name             string
	ClientHello      tls.ClientHelloID
	Settings         []http2.Setting
	ConnWindowUpdate uint32
	PseudoOrder      []string
	SuggestedUA      string
}

var (
	browserFingerprintChrome131 = &browserFingerprintProfile{
		Name:        BrowserFingerprintProfileChrome131,
		ClientHello: tls.HelloChrome_131,
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		},
		ConnWindowUpdate: 15663105,
		PseudoOrder:      []string{":method", ":authority", ":scheme", ":path"},
		SuggestedUA:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	}

	// Chrome_120 shares Chrome's current Akamai H2 SETTINGS with 131; JA3/JA4
	// differ via HelloChrome_120. utls v1.8.2 has no HelloChrome_124 — use
	// chrome_120 when a second Chrome identity is needed.
	browserFingerprintChrome120 = &browserFingerprintProfile{
		Name:        BrowserFingerprintProfileChrome120,
		ClientHello: tls.HelloChrome_120,
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		},
		ConnWindowUpdate: 15663105,
		PseudoOrder:      []string{":method", ":authority", ":scheme", ":path"},
		SuggestedUA:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}

	// safari_17 uses HelloSafari_16_0 (desktop Safari ceiling in utls v1.8.2)
	// with Safari Akamai H2 from tls-client Safari_16_0 / Safari 17 family.
	browserFingerprintSafari17 = &browserFingerprintProfile{
		Name:        BrowserFingerprintProfileSafari17,
		ClientHello: tls.HelloSafari_16_0,
		Settings: []http2.Setting{
			{ID: http2.SettingInitialWindowSize, Val: 4194304},
			{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		},
		ConnWindowUpdate: 10485760,
		PseudoOrder:      []string{":method", ":scheme", ":path", ":authority"},
		SuggestedUA:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	}
)

var browserFingerprintByName = map[string]*browserFingerprintProfile{
	BrowserFingerprintProfileChrome131: browserFingerprintChrome131,
	"chrome131":                        browserFingerprintChrome131,
	BrowserFingerprintProfileChrome120: browserFingerprintChrome120,
	"chrome120":                        browserFingerprintChrome120,
	BrowserFingerprintProfileSafari17:  browserFingerprintSafari17,
	"safari17":                         browserFingerprintSafari17,
	"safari_16_0":                      browserFingerprintSafari17,
	"safari_16":                        browserFingerprintSafari17,
}

// browserFingerprintProfileWarned deduplicates unrecognized-value warnings.
var browserFingerprintProfileWarned sync.Map

// DefaultBrowserFingerprintProfile returns the chatgpt.com default (chrome_131).
func DefaultBrowserFingerprintProfile() *browserFingerprintProfile {
	return browserFingerprintChrome131
}

// ResolveBrowserFingerprintProfile maps a configured name to a matched profile.
// Empty / unknown / Claude-only values fall back to chrome_131.
func ResolveBrowserFingerprintProfile(raw string) *browserFingerprintProfile {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return browserFingerprintChrome131
	}
	if profile, ok := browserFingerprintByName[trimmed]; ok {
		return profile
	}
	// Claude's claude-code-cli shares the metadata key; ignore it on this path.
	if trimmed == "claude-code-cli" || trimmed == "oauth-cli" {
		return browserFingerprintChrome131
	}
	if _, warned := browserFingerprintProfileWarned.LoadOrStore(trimmed, struct{}{}); !warned {
		log.Warnf("unrecognized browser fingerprint_profile %q (supported: chrome_131, chrome_120, safari_17); falling back to chrome_131", raw)
	}
	return browserFingerprintChrome131
}

// BrowserFingerprintProfileFromAuth reads fingerprint_profile from auth
// Attributes / Metadata the same way ProxyURL / Claude fingerprint_profile do.
func BrowserFingerprintProfileFromAuth(auth *cliproxyauth.Auth) *browserFingerprintProfile {
	return ResolveBrowserFingerprintProfile(browserFingerprintProfileNameFromAuth(auth))
}

func browserFingerprintProfileNameFromAuth(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if raw := strings.TrimSpace(auth.Attributes[browserFingerprintProfileAttr]); raw != "" {
			return raw
		}
		if raw := strings.TrimSpace(auth.Attributes["fingerprint-profile"]); raw != "" {
			return raw
		}
	}
	if auth.Metadata != nil {
		for _, key := range []string{browserFingerprintProfileAttr, "fingerprint-profile"} {
			if raw, ok := auth.Metadata[key].(string); ok && strings.TrimSpace(raw) != "" {
				return strings.TrimSpace(raw)
			}
		}
	}
	return ""
}

func (p *browserFingerprintProfile) headerTableSize() uint32 {
	if p == nil {
		return 4096
	}
	for _, s := range p.Settings {
		if s.ID == http2.SettingHeaderTableSize {
			return s.Val
		}
	}
	return 4096
}

func (p *browserFingerprintProfile) maxHeaderListSize() uint32 {
	if p == nil {
		return 262144
	}
	for _, s := range p.Settings {
		if s.ID == http2.SettingMaxHeaderListSize {
			return s.Val
		}
	}
	return 262144
}

// akamaiFingerprint returns the Akamai SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo string.
func (p *browserFingerprintProfile) akamaiFingerprint() string {
	if p == nil {
		p = browserFingerprintChrome131
	}
	parts := make([]string, 0, len(p.Settings))
	for _, s := range p.Settings {
		parts = append(parts, fmt.Sprintf("%d:%d", s.ID, s.Val))
	}
	pseudoShort := make([]string, 0, len(p.PseudoOrder))
	for _, name := range p.PseudoOrder {
		switch name {
		case ":method":
			pseudoShort = append(pseudoShort, "m")
		case ":authority":
			pseudoShort = append(pseudoShort, "a")
		case ":scheme":
			pseudoShort = append(pseudoShort, "s")
		case ":path":
			pseudoShort = append(pseudoShort, "p")
		}
	}
	return strings.Join(parts, ";") + fmt.Sprintf("|%d|0|%s", p.ConnWindowUpdate, strings.Join(pseudoShort, ","))
}

// SupportedBrowserFingerprintProfiles lists canonical profile names for docs/tests.
func SupportedBrowserFingerprintProfiles() []*browserFingerprintProfile {
	return []*browserFingerprintProfile{
		browserFingerprintChrome131,
		browserFingerprintChrome120,
		browserFingerprintSafari17,
	}
}
