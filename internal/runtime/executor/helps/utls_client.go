package helps

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	internalcache "github.com/router-for-me/CLIProxyAPI/v8/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/httpwire"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/httptransport"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

// chromeClientHelloID is the fixed ClientHello used for chatgpt.com.
// HelloChrome_Auto currently tracks Chrome 133 and can drift on utls upgrades;
// pin Chrome_131 so JA3/JA4 stay aligned with the Chrome_131 Akamai H2 settings
// below (see chrome_h2.go). Application User-Agent (e.g. Codex) is set by
// callers and is intentionally not rewritten here.
var chromeClientHelloID = tls.HelloChrome_131

const chromeRoundTripperCacheCapacity = 64

var chromeRoundTripperCache = internalcache.NewBoundedLRU[string, http.RoundTripper](
	chromeRoundTripperCacheCapacity,
	func(_ string, roundTripper http.RoundTripper) {
		if transport, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	},
)

func cachedChromeRoundTripper(proxyURL string) http.RoundTripper {
	return chromeRoundTripperCache.GetOrAdd(proxyURL, func() http.RoundTripper {
		return newUtlsRoundTripper(proxyURL)
	})
}

// utlsRoundTripper implements http.RoundTripper using a Chrome TLS + HTTP/2
// Akamai fingerprint for providers that require browser-like wire identity.
// The HTTP version follows ALPN. Idle HTTP/2 connections are pooled per
// RoundTripper (keyed by proxy URL via chromeRoundTripperCache); an open
// response body (including SSE) holds its connection exclusively until Close.
type utlsRoundTripper struct {
	dialer proxy.Dialer

	mu    sync.Mutex
	idle  []*chromeH2Conn
}

type closeConnectionBody struct {
	io.ReadCloser
	closeConnection func() error
	once            sync.Once
	err             error
}

func (b *closeConnectionBody) Close() error {
	if b == nil {
		return nil
	}
	b.once.Do(func() {
		var errConnection error
		if b.closeConnection != nil {
			errConnection = b.closeConnection()
		}
		var errBody error
		if b.ReadCloser != nil {
			errBody = b.ReadCloser.Close()
		}
		b.err = errors.Join(errBody, errConnection)
	})
	return b.err
}

func newUtlsRoundTripper(proxyURL string) *utlsRoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("utls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}
	return &utlsRoundTripper{dialer: dialer}
}

func (t *utlsRoundTripper) CloseIdleConnections() {
	t.mu.Lock()
	idle := t.idle
	t.idle = nil
	t.mu.Unlock()
	for _, c := range idle {
		_ = c.Close()
	}
}

func (t *utlsRoundTripper) putIdle(c *chromeH2Conn) {
	if c == nil {
		return
	}
	t.mu.Lock()
	if c.isReusable() && len(t.idle) < 8 {
		t.idle = append(t.idle, c)
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()
	_ = c.Close()
}

func (t *utlsRoundTripper) takeIdle() *chromeH2Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(t.idle) > 0 {
		c := t.idle[len(t.idle)-1]
		t.idle = t.idle[:len(t.idle)-1]
		if c.isReusable() {
			return c
		}
		_ = c.Close()
	}
	return nil
}

func (t *utlsRoundTripper) createConnection(ctx context.Context, host, addr string) (*tls.UConn, error) {
	contextDialer, ok := t.dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("utls: dialer does not support context cancellation")
	}
	conn, errDial := contextDialer.DialContext(ctx, "tcp", addr)
	if errDial != nil {
		return nil, fmt.Errorf("utls: dial upstream: %w", errDial)
	}

	tlsConfig := &tls.Config{ServerName: host}
	tlsConn := tls.UClient(conn, tlsConfig, chromeClientHelloID)

	handshakeCtx, cancelHandshake := handshakeContext(ctx)
	defer cancelHandshake()
	if errHandshake := tlsConn.HandshakeContext(handshakeCtx); errHandshake != nil {
		errHandshake = classifyHandshakeError(ctx, handshakeCtx, errHandshake)
		if errors.Is(errHandshake, context.Canceled) || errors.Is(errHandshake, context.DeadlineExceeded) {
			return nil, fmt.Errorf("utls: TLS handshake: %w", errHandshake)
		}
		if errClose := conn.Close(); errClose != nil {
			return nil, fmt.Errorf("utls: TLS handshake: %w; close connection: %v", errHandshake, errClose)
		}
		return nil, fmt.Errorf("utls: TLS handshake: %w", errHandshake)
	}

	return tlsConn, nil
}

func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		if idle := t.takeIdle(); idle != nil {
			resp, err := idle.roundTrip(req)
			if err == nil {
				if body, ok := resp.Body.(*chromeH2Body); ok {
					body.readCtx = req.Context()
					body.onClose = func(reusable bool) {
						if reusable {
							t.putIdle(idle)
						} else {
							_ = idle.Close()
						}
					}
				}
				return resp, nil
			}
			_ = idle.Close()
			// Fall through to a fresh dial on idle failure.
		}
	}

	hostname := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(hostname, port)

	tlsConn, err := t.createConnection(req.Context(), hostname, addr)
	if err != nil {
		return nil, err
	}
	return t.roundTripFresh(req, tlsConn)
}

func (t *utlsRoundTripper) roundTripFresh(req *http.Request, tlsConn *tls.UConn) (*http.Response, error) {
	return roundTripUtlsConnection(req, tlsConn, t)
}

// roundTripUtlsConnection selects the HTTP protocol before sending the request.
// Empty ALPN is HTTP/1.1, including when a TLS-inspecting proxy omits ALPN.
// pool may be nil in tests; when set, successful h2 responses can return the
// chromeH2Conn to the RoundTripper idle list after Body.Close.
func roundTripUtlsConnection(req *http.Request, tlsConn *tls.UConn, pool *utlsRoundTripper) (*http.Response, error) {
	closeConnection := func() error {
		// The HTTP/1.1 transport may already have closed its non-pooled
		// connection after reading the response or canceling the request.
		if errClose := tlsConn.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) {
			return errClose
		}
		return nil
	}
	var resp *http.Response
	var err error
	switch protocol := tlsConn.ConnectionState().NegotiatedProtocol; protocol {
	case "h2":
		chromeConn, errChrome := newChromeH2Conn(tlsConn)
		if errChrome != nil {
			err = fmt.Errorf("utls: initialize Chrome HTTP/2 connection: %w", errChrome)
			break
		}
		resp, err = chromeConn.roundTrip(req)
		if err != nil {
			_ = chromeConn.Close()
			break
		}
		if body, ok := resp.Body.(*chromeH2Body); ok {
			body.readCtx = req.Context()
			body.onClose = func(reusable bool) {
				if pool != nil && reusable {
					pool.putIdle(chromeConn)
					return
				}
				_ = chromeConn.Close()
			}
		} else {
			closeConnection = chromeConn.Close
		}
		// Successful h2 path: do not wrap with closeConnectionBody that would
		// tear down a pooled chrome connection while the stream body is open.
		return resp, nil
	case "", "http/1.1":
		// Reuse the already-handshaken uTLS connection. A fresh, non-pooling
		// transport retains net/http's cancellation and request-body handling
		// without changing the TLS fingerprint or redialing through another path.
		transport := &http.Transport{
			DisableKeepAlives: true,
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				return tlsConn, nil
			},
		}
		resp, err = transport.RoundTrip(req)
		transport.CloseIdleConnections()
	default:
		err = fmt.Errorf("utls: unsupported negotiated protocol %q", protocol)
	}
	if err != nil {
		if errClose := closeConnection(); errClose != nil {
			log.Debugf("utls: close connection after round trip failure: %v", errClose)
		}
		return nil, err
	}
	if resp == nil {
		if errClose := closeConnection(); errClose != nil {
			log.Debugf("utls: close connection after empty response: %v", errClose)
		}
		return nil, fmt.Errorf("utls: upstream returned an empty response")
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	resp.Body = &closeConnectionBody{
		ReadCloser:      resp.Body,
		closeConnection: closeConnection,
	}
	return resp, nil
}

// claudeCodeSessionCacheCapacity bounds the per-transport TLS session cache for
// the Anthropic inference plane.
const claudeCodeSessionCacheCapacity = 32

// newClaudeCodeTLSConfig builds the uTLS config for one inference-plane dial.
//
// OmitEmptyPsk keeps the pre_shared_key extension silent until a session is
// cached, so an unresumed ClientHello stays byte-identical to the captured
// native handshake. PreferSkipResumptionOnNilExtension turns uTLS's HelloCustom
// "resume without the matching extension" panic into a skipped resumption.
func newClaudeCodeTLSConfig(host string, sessionCache tls.ClientSessionCache) *tls.Config {
	return newClaudeCodeTLSConfigWithRoots(host, sessionCache, nil)
}

func newClaudeCodeTLSConfigWithRoots(host string, sessionCache tls.ClientSessionCache, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		ServerName:                         host,
		RootCAs:                            roots,
		ClientSessionCache:                 sessionCache,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
}

// claudeCodeTLSClientHelloSpec reproduces the deterministic Node/OpenSSL
// ClientHello emitted by Claude Code 2.1.220 on macOS arm64. Keep this spec in
// sync with a fresh native capture whenever the advertised Claude Code version
// changes.
func claudeCodeTLSClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
			// pre_shared_key MUST be the final extension (RFC 8446 4.2.11), after
			// padding. It contributes zero bytes until a cached session exists.
			&tls.UtlsPreSharedKeyExtension{},
		},
	}
}

const claudeCodeRoundTripperCacheCapacity = 64

var claudeCodeRoundTripperCache = internalcache.NewBoundedLRU[string, http.RoundTripper](
	claudeCodeRoundTripperCacheCapacity,
	func(_ string, roundTripper http.RoundTripper) {
		if transport, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	},
)

var claudeCodeMessagesHeaderOrder = []string{
	"Accept",
	"Authorization",
	"Content-Type",
	"User-Agent",
	"X-Claude-Code-Session-Id",
	"X-Stainless-Arch",
	"X-Stainless-Lang",
	"X-Stainless-OS",
	"X-Stainless-Package-Version",
	"X-Stainless-Retry-Count",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"X-Stainless-Timeout",
	"anthropic-beta",
	"anthropic-dangerous-direct-browser-access",
	"anthropic-version",
	"x-app",
	"x-client-request-id",
	"Connection",
	"Host",
	"Accept-Encoding",
	"Content-Length",
}

var claudeCodeCountTokensHeaderOrder = []string{
	"Accept",
	"Authorization",
	"Content-Type",
	"User-Agent",
	"X-Claude-Code-Session-Id",
	"X-Stainless-Arch",
	"X-Stainless-Lang",
	"X-Stainless-OS",
	"X-Stainless-Package-Version",
	"X-Stainless-Retry-Count",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"anthropic-beta",
	"anthropic-dangerous-direct-browser-access",
	"anthropic-version",
	"x-app",
	"x-client-request-id",
	"Connection",
	"Host",
	"Accept-Encoding",
	"Content-Length",
}

func claudeCodeRequestHeaderOrder(_, requestTarget string) []string {
	if strings.HasPrefix(requestTarget, "/v1/messages/count_tokens") {
		return claudeCodeCountTokensHeaderOrder
	}
	return claudeCodeMessagesHeaderOrder
}

func cachedClaudeCodeRoundTripper(proxyURL string) http.RoundTripper {
	return claudeCodeRoundTripperCache.GetOrAdd(proxyURL, func() http.RoundTripper {
		return newClaudeCodeRoundTripper(proxyURL)
	})
}

func newClaudeCodeRoundTripper(proxyURL string) http.RoundTripper {
	return newClaudeCodeRoundTripperForDialer(claudeCodeDialer(proxyURL))
}

// claudeCodeDialer resolves the dialer the Claude Code transport uses for one proxy
// setting. It is shared by the cached transport and the per-credential pooled one so
// both keep the same proxy semantics.
func claudeCodeDialer(proxyURL string) proxy.Dialer {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("claude tls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}
	return dialer
}

// pooledClaudeCodeTransport returns the credential-scoped Claude Code uTLS transport
// when the credential opted into pooling, or nil so the caller keeps the historical
// shared per-proxy transport. Per credential pooling matters here because this
// transport is otherwise shared by every key that uses the same proxy, which mixes
// distinct identities on one connection and ignores the key's pool settings.
func pooledClaudeCodeTransport(proxyURL string, cfg *config.Config, auth *cliproxyauth.Auth) *http.Transport {
	tr, pooled := pooledTransport(proxyPoolKindClaudeCode, proxyURL, cfg, auth, func() (*http.Transport, error) {
		return newClaudeCodeRoundTripperForDialer(claudeCodeDialer(proxyURL)), nil
	})
	if !pooled {
		return nil
	}
	return tr
}

// newClaudeCodeRoundTripperForDialer builds the Claude Code transport on top
// of an already-resolved dialer. It is split out from
// newClaudeCodeRoundTripper so tests can inject in-memory connections.
func newClaudeCodeRoundTripperForDialer(dialer proxy.Dialer) *http.Transport {
	return newClaudeCodeRoundTripperForDialerAndRoots(dialer, nil)
}

func newClaudeCodeRoundTripperForDialerAndRoots(dialer proxy.Dialer, roots *x509.CertPool) *http.Transport {
	// The cache is scoped to this round tripper, which is already keyed by proxy,
	// so resumption never crosses proxy boundaries.
	sessionCache := tls.NewLRUClientSessionCache(claudeCodeSessionCacheCapacity)

	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var (
				conn net.Conn
				err  error
			)
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				conn, err = contextDialer.DialContext(ctx, network, addr)
			} else {
				conn, err = dialer.Dial(network, addr)
			}
			if err != nil {
				return nil, fmt.Errorf("claude tls: dial upstream: %w", err)
			}
			conn = stampProxyKeepAlive(conn)

			host, _, errSplit := net.SplitHostPort(addr)
			if errSplit != nil {
				if errClose := conn.Close(); errClose != nil {
					log.Debugf("claude tls: close failed connection: %v", errClose)
				}
				return nil, fmt.Errorf("claude tls: split upstream address: %w", errSplit)
			}
			tlsConn := tls.UClient(conn, newClaudeCodeTLSConfigWithRoots(host, sessionCache, roots), tls.HelloCustom)
			if errPreset := tlsConn.ApplyPreset(claudeCodeTLSClientHelloSpec()); errPreset != nil {
				if errClose := tlsConn.Close(); errClose != nil {
					log.Debugf("claude tls: close connection after preset failure: %v", errClose)
				}
				return nil, fmt.Errorf("claude tls: apply Claude Code ClientHello: %w", errPreset)
			}
			handshakeCtx, cancelHandshake := handshakeContext(ctx)
			defer cancelHandshake()
			if errHandshake := tlsConn.HandshakeContext(handshakeCtx); errHandshake != nil {
				errHandshake = classifyHandshakeError(ctx, handshakeCtx, errHandshake)
				if errClose := tlsConn.Close(); errClose != nil {
					log.Debugf("claude tls: close connection after handshake failure: %v", errClose)
				}
				return nil, fmt.Errorf("claude tls: handshake upstream: %w", errHandshake)
			}
			return httpwire.NewOrderedRequestConn(tlsConn, claudeCodeRequestHeaderOrder), nil
		},
	}
	return transport
}

// fallbackRoundTripper uses provider-specific TLS fingerprints for protected
// HTTPS hosts and falls back to the standard transport for all other requests.
//
// Each pooled branch may be resolved lazily on first use: a single request only
// ever takes one branch, and building both pools up front would spend two cache
// slots per key (evicting live standard pools with unused Anthropic pools).
type fallbackRoundTripper struct {
	mu          sync.Mutex
	anthropic   http.RoundTripper
	anthropicFn func() http.RoundTripper
	chrome      http.RoundTripper
	fallback    http.RoundTripper
	fallbackFn  func() http.RoundTripper
}

func (f *fallbackRoundTripper) anthropicRoundTripper() http.RoundTripper {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.anthropicFn != nil {
		if rt := f.anthropicFn(); rt != nil {
			f.anthropic = rt
		}
		f.anthropicFn = nil
	}
	return f.anthropic
}

func (f *fallbackRoundTripper) fallbackRoundTripper() http.RoundTripper {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fallbackFn != nil {
		if rt := f.fallbackFn(); rt != nil {
			f.fallback = rt
		}
		f.fallbackFn = nil
	}
	return f.fallback
}

func (f *fallbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if IsAnthropicUpstreamURL(req.URL) {
		return f.anthropicRoundTripper().RoundTrip(req)
	}
	if req.URL.Scheme == "https" && strings.EqualFold(req.URL.Hostname(), "chatgpt.com") {
		return f.chrome.RoundTrip(req)
	}
	return f.fallbackRoundTripper().RoundTrip(req)
}

// NewUtlsHTTPClient creates an HTTP client using provider-specific TLS
// fingerprints for protected hosts. It uses Claude Code's Node/OpenSSL profile
// for Anthropic and a Chrome profile for ChatGPT, with a standard-transport
// fallback for other hosts.
func NewUtlsHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) (clientOut *http.Client) {
	// Carry the opt-in TLS establishment bound (requests
	// tls-handshake-timeout-seconds) on a request-scoped wrapper. This
	// client is shared, so the bound intentionally reaches both the Claude
	// Code Anthropic dial path and the Chrome ChatGPT/Codex dial path; the
	// standard fallback transport ignores the context value. The uTLS dial
	// paths read it per dial, so cached per-proxy transports need no rebuild
	// when the value changes. A disabled bound (0) leaves requests untouched.
	var handshakeTimeout time.Duration
	if cfg != nil {
		handshakeTimeout = cfg.TLSHandshakeTimeout()
	}
	defer func() {
		clientOut = httptransport.Decorate(ctx, clientOut)
		if clientOut != nil && handshakeTimeout > 0 {
			clientOut.Transport = &tlsHandshakeTimeoutRoundTripper{base: clientOut.Transport, timeout: handshakeTimeout}
		}
	}()
	proxyURL := effectiveProxyURL(ctx, cfg, auth)

	var ctxRoundTripper http.RoundTripper
	if ctx != nil {
		ctxRoundTripper, _ = ctx.Value("cliproxy.roundtripper").(http.RoundTripper)
	}

	var chromeRT http.RoundTripper = cachedChromeRoundTripper(proxyURL)
	var anthropicRT http.RoundTripper = cachedClaudeCodeRoundTripper(proxyURL)
	var standardTransport http.RoundTripper = http.DefaultTransport
	var anthropicFn, fallbackFn func() http.RoundTripper
	if proxyURL != "" {
		fallbackFn = func() http.RoundTripper {
			if transport := pooledProxyTransport(proxyURL, cfg, auth); transport != nil {
				return transport
			}
			return standardTransport
		}
		// The Anthropic path has its own TLS fingerprint, so it needs its own pool kind.
		anthropicFn = func() http.RoundTripper {
			if transport := pooledClaudeCodeTransport(proxyURL, cfg, auth); transport != nil {
				return transport
			}
			return anthropicRT
		}
	} else if ctxRoundTripper != nil {
		chromeRT = ctxRoundTripper
		anthropicRT = ctxRoundTripper
		standardTransport = ctxRoundTripper
	} else {
		// A credential opt-in applies here too; an injected RoundTripper keeps priority.
		fallbackFn = func() http.RoundTripper {
			if transport := pooledProxyTransport("", cfg, auth); transport != nil {
				return transport
			}
			return standardTransport
		}
		anthropicFn = func() http.RoundTripper {
			if transport := pooledClaudeCodeTransport("", cfg, auth); transport != nil {
				return transport
			}
			return anthropicRT
		}
	}

	client := &http.Client{
		Transport: &fallbackRoundTripper{
			anthropic:   anthropicRT,
			anthropicFn: anthropicFn,
			chrome:      chromeRT,
			fallback:    standardTransport,
			fallbackFn:  fallbackFn,
		},
	}
	if timeout > 0 {
		client.Timeout = timeout
	}
	return client
}
