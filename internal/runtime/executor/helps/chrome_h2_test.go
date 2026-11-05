package helps

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestChromeH2SettingsFingerprintMatchesChrome131(t *testing.T) {
	got := chromeH2SettingsFingerprint()
	want := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	if got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}
	if chromeClientHelloID.Client != "Chrome" || chromeClientHelloID.Version != "131" {
		t.Fatalf("chromeClientHelloID = %s/%s, want Chrome/131", chromeClientHelloID.Client, chromeClientHelloID.Version)
	}
}

func TestChromeH2ConnEmitsChromePrefaceSettingsAndPseudoOrder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type capture struct {
		settings []http2.Setting
		window   uint32
		pseudos  []string
	}
	result := make(chan capture, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		buf := make([]byte, len(chromeH2ClientPreface))
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(buf, chromeH2ClientPreface) {
			errCh <- fmt.Errorf("bad preface: %q", buf)
			return
		}
		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

		settingsFrame, err := fr.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		sf, ok := settingsFrame.(*http2.SettingsFrame)
		if !ok {
			errCh <- fmt.Errorf("want SETTINGS, got %T", settingsFrame)
			return
		}
		var settings []http2.Setting
		_ = sf.ForeachSetting(func(s http2.Setting) error {
			settings = append(settings, s)
			return nil
		})

		wuFrame, err := fr.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		wu, ok := wuFrame.(*http2.WindowUpdateFrame)
		if !ok || wu.StreamID != 0 {
			errCh <- fmt.Errorf("want conn WINDOW_UPDATE, got %T", wuFrame)
			return
		}

		hdrFrame, err := fr.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		mh, ok := hdrFrame.(*http2.MetaHeadersFrame)
		if !ok {
			errCh <- fmt.Errorf("want HEADERS, got %T", hdrFrame)
			return
		}
		var pseudos []string
		for _, f := range mh.Fields {
			if strings.HasPrefix(f.Name, ":") {
				pseudos = append(pseudos, f.Name)
			}
		}

		// Respond with headers+data only (no server SETTINGS) so the client
		// does not try to ACK SETTINGS while we still hold the write path.
		var encBuf bytes.Buffer
		enc := hpack.NewEncoder(&encBuf)
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/plain"})
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      mh.StreamID,
			BlockFragment: encBuf.Bytes(),
			EndStream:     false,
			EndHeaders:    true,
		}); err != nil {
			errCh <- err
			return
		}
		if err := fr.WriteData(mh.StreamID, true, []byte("ok")); err != nil {
			errCh <- err
			return
		}
		result <- capture{settings: settings, window: wu.Increment, pseudos: pseudos}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	_ = clientConn.SetDeadline(time.Now().Add(10 * time.Second))

	chromeConn, err := newChromeH2Conn(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://chatgpt.com/backend-api/codex/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "codex-tui/test")
	resp, err := chromeConn.roundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}

	select {
	case err := <-errCh:
		t.Fatal(err)
	case got := <-result:
		wantSettings := []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		}
		if len(got.settings) != len(wantSettings) {
			t.Fatalf("settings = %#v, want %#v", got.settings, wantSettings)
		}
		for i := range wantSettings {
			if got.settings[i] != wantSettings[i] {
				t.Fatalf("settings[%d] = %#v, want %#v", i, got.settings[i], wantSettings[i])
			}
		}
		if got.window != chromeH2ConnWindowUpdate {
			t.Fatalf("window update = %d, want %d", got.window, chromeH2ConnWindowUpdate)
		}
		wantPseudos := []string{":method", ":authority", ":scheme", ":path"}
		if strings.Join(got.pseudos, ",") != strings.Join(wantPseudos, ",") {
			t.Fatalf("pseudos = %v, want %v", got.pseudos, wantPseudos)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server capture")
	}
}

func TestChromePathDoesNotAffectAnthropicRouting(t *testing.T) {
	var saw []string
	route := func(name string) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			saw = append(saw, name)
			return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header), Request: req}, nil
		})
	}
	rt := &fallbackRoundTripper{
		anthropic: route("anthropic"),
		chrome:    route("chrome"),
		fallback:  route("fallback"),
	}
	cases := []struct {
		rawURL string
		want   string
	}{
		{"https://api.anthropic.com/v1/messages", "anthropic"},
		{"https://chatgpt.com/backend-api/codex/responses", "chrome"},
		{"https://example.com/v1/chat", "fallback"},
	}
	for _, tc := range cases {
		saw = nil
		req, err := http.NewRequest(http.MethodPost, tc.rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if len(saw) != 1 || saw[0] != tc.want {
			t.Fatalf("%s routed to %v, want %q", tc.rawURL, saw, tc.want)
		}
	}
}

func TestCachedChromeRoundTripperReusesInstance(t *testing.T) {
	a := cachedChromeRoundTripper("socks5://127.0.0.1:1")
	b := cachedChromeRoundTripper("socks5://127.0.0.1:1")
	if a != b {
		t.Fatal("expected chrome RoundTripper cache hit for same proxy")
	}
	c := cachedChromeRoundTripper("socks5://127.0.0.1:2")
	if a == c {
		t.Fatal("expected distinct RoundTripper for different proxy")
	}
}

func TestChromeH2WorksAgainstNetHTTP2Server(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("proto = %s", r.Proto)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: one\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = io.WriteString(w, "data: two\n\n")
	})
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	// Dial with standard TLS to the test server, then speak Chrome H2 on top.
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsConn := tlsClientForTestServer(t, conn, server)
	chromeConn, err := newChromeH2Conn(tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := chromeConn.roundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "data: one") || !strings.Contains(string(body), "data: two") {
		t.Fatalf("sse body = %q", body)
	}
}

func tlsClientForTestServer(t *testing.T, conn net.Conn, server *httptest.Server) *stdtls.Conn {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tlsConn := stdtls.Client(conn, &stdtls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    roots,
		NextProtos: []string{"h2"},
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tlsConn
}
