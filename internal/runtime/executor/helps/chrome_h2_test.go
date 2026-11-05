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

// TestChromeH2SendFlowControlRespectsConnAndStreamWindows verifies that a large
// request body is split across DATA frames and never exceeds the peer's
// connection or stream send windows — the bug that produced
// FLOW_CONTROL_ERROR against chatgpt.com (SETTINGS_INITIAL_WINDOW_SIZE was
// incorrectly applied as the connection window).
func TestChromeH2SendFlowControlRespectsConnAndStreamWindows(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	const (
		peerConnWin    = 65535
		peerStreamInit = 1024 * 1024 // large SETTINGS_INITIAL_WINDOW_SIZE (stream only)
		bodySize       = 200000      // > 65535 so conn window must throttle
	)
	body := bytes.Repeat([]byte("x"), bodySize)

	type result struct {
		dataBytes int
		maxFrame  int
		frames    int
		sawRST    bool
	}
	resCh := make(chan result, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

		buf := make([]byte, len(chromeH2ClientPreface))
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}
		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

		// Consume client SETTINGS + WINDOW_UPDATE.
		if _, err := fr.ReadFrame(); err != nil {
			errCh <- err
			return
		}
		if _, err := fr.ReadFrame(); err != nil {
			errCh <- err
			return
		}

		// Peer SETTINGS: large stream window MUST NOT enlarge connection window.
		if err := fr.WriteSettings(http2.Setting{
			ID: http2.SettingInitialWindowSize, Val: peerStreamInit,
		}); err != nil {
			errCh <- err
			return
		}

		var (
			got         result
			connLeft    = peerConnWin
			streamLeft  = 65535 // until SETTINGS ACK applied on client; we track what client may legally send
			streamID    uint32
			headersDone bool
		)
		// After client ACKs SETTINGS, stream window becomes peerStreamInit.
		// We apply the same rule the client should: conn stays at 65535 (+ our WU).
		streamLeft = peerStreamInit

		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			frame, err := fr.ReadFrame()
			if err != nil {
				if got.dataBytes == bodySize {
					break
				}
				errCh <- err
				return
			}
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				// client ACK — ignore
			case *http2.MetaHeadersFrame:
				streamID = f.StreamID
				headersDone = true
				if f.StreamEnded() {
					errCh <- fmt.Errorf("headers ended stream but body expected")
					return
				}
			case *http2.DataFrame:
				if !headersDone || f.StreamID != streamID {
					errCh <- fmt.Errorf("unexpected DATA stream=%d", f.StreamID)
					return
				}
				n := len(f.Data())
				got.frames++
				if n > got.maxFrame {
					got.maxFrame = n
				}
				if n > connLeft {
					_ = fr.WriteRSTStream(streamID, http2.ErrCodeFlowControl)
					got.sawRST = true
					resCh <- got
					return
				}
				if n > streamLeft {
					_ = fr.WriteRSTStream(streamID, http2.ErrCodeFlowControl)
					got.sawRST = true
					resCh <- got
					return
				}
				connLeft -= n
				streamLeft -= n
				got.dataBytes += n

				// Replenish windows like a real peer so the client can finish.
				if connLeft < 16*1024 && got.dataBytes < bodySize {
					inc := uint32(32 * 1024)
					if err := fr.WriteWindowUpdate(0, inc); err != nil {
						errCh <- err
						return
					}
					connLeft += int(inc)
				}
				if streamLeft < 16*1024 && got.dataBytes < bodySize {
					inc := uint32(64 * 1024)
					if err := fr.WriteWindowUpdate(streamID, inc); err != nil {
						errCh <- err
						return
					}
					streamLeft += int(inc)
				}
				if f.StreamEnded() {
					// Respond so roundTrip can complete.
					var encBuf bytes.Buffer
					enc := hpack.NewEncoder(&encBuf)
					_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					_ = fr.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      streamID,
						BlockFragment: encBuf.Bytes(),
						EndStream:     true,
						EndHeaders:    true,
					})
					resCh <- got
					return
				}
			case *http2.RSTStreamFrame:
				got.sawRST = true
				resCh <- got
				return
			}
		}
		errCh <- fmt.Errorf("timeout: got %d/%d body bytes", got.dataBytes, bodySize)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))

	chromeConn, err := newChromeH2Conn(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := chromeConn.roundTrip(req)
	if err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case err := <-errCh:
		t.Fatal(err)
	case got := <-resCh:
		if got.sawRST {
			t.Fatalf("peer sent FLOW_CONTROL RST after %d bytes (client overshot window)", got.dataBytes)
		}
		if got.dataBytes != bodySize {
			t.Fatalf("data bytes = %d, want %d", got.dataBytes, bodySize)
		}
		if got.maxFrame > int(chromeH2DefaultMaxFrame) {
			t.Fatalf("max DATA frame %d > maxFrame %d", got.maxFrame, chromeH2DefaultMaxFrame)
		}
		if got.frames < 2 {
			t.Fatalf("expected multi-frame DATA, got %d frames", got.frames)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("timed out waiting for peer result")
	}
}

// TestChromeH2SettingsInitialWindowDoesNotExpandConnWindow ensures a large
// peer SETTINGS_INITIAL_WINDOW_SIZE only grows the stream window. A body
// bigger than the still-65535 connection window must block until a
// connection-level WINDOW_UPDATE arrives (otherwise peer would RST with
// FLOW_CONTROL_ERROR).
func TestChromeH2SettingsInitialWindowDoesNotExpandConnWindow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	const bodySize = 70000 // just over default conn window
	body := bytes.Repeat([]byte("y"), bodySize)

	progress := make(chan int, 8)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

		buf := make([]byte, len(chromeH2ClientPreface))
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}
		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		if _, err := fr.ReadFrame(); err != nil { // SETTINGS
			errCh <- err
			return
		}
		if _, err := fr.ReadFrame(); err != nil { // WU
			errCh <- err
			return
		}
		// Advertise a huge stream window — buggy clients treat this as conn win.
		if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6 << 20}); err != nil {
			errCh <- err
			return
		}

		var (
			streamID   uint32
			got        int
			connCredit = 65535
		)
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				// ACK
			case *http2.MetaHeadersFrame:
				streamID = f.StreamID
			case *http2.DataFrame:
				n := len(f.Data())
				if n > connCredit {
					_ = fr.WriteRSTStream(f.StreamID, http2.ErrCodeFlowControl)
					errCh <- fmt.Errorf("client sent %d bytes with only %d conn credit left (FLOW_CONTROL)", n, connCredit)
					return
				}
				connCredit -= n
				got += n
				progress <- got
				if got == 65535 {
					// Client must stop here until we grant more conn window.
					time.Sleep(200 * time.Millisecond)
					if err := fr.WriteWindowUpdate(0, uint32(bodySize)); err != nil {
						errCh <- err
						return
					}
					connCredit += bodySize
					// Also top up stream window (already large via SETTINGS).
					if err := fr.WriteWindowUpdate(streamID, uint32(bodySize)); err != nil {
						errCh <- err
						return
					}
				}
				if f.StreamEnded() {
					var encBuf bytes.Buffer
					enc := hpack.NewEncoder(&encBuf)
					_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "204"})
					_ = fr.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      streamID,
						BlockFragment: encBuf.Bytes(),
						EndStream:     true,
						EndHeaders:    true,
					})
					return
				}
			}
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))

	chromeConn, err := newChromeH2Conn(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://chatgpt.com/upload", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := chromeConn.roundTrip(req)
	if err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
	// Ensure we observed the stall at the conn window boundary.
	saw65535 := false
	timeout := time.After(2 * time.Second)
	for !saw65535 {
		select {
		case n := <-progress:
			if n == 65535 {
				saw65535 = true
			}
			if n == bodySize {
				saw65535 = true
			}
		case err := <-errCh:
			t.Fatal(err)
		case <-timeout:
			t.Fatal("did not observe progress through conn window")
		}
	}
}

// TestChromeH2ReceiveWindowUpdateOnSSEData ensures reading a multi-frame SSE
// body returns WINDOW_UPDATE on both connection and stream (long responses).
func TestChromeH2ReceiveWindowUpdateOnSSEData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	wuCh := make(chan []http2.WindowUpdateFrame, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

		buf := make([]byte, len(chromeH2ClientPreface))
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}
		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		if _, err := fr.ReadFrame(); err != nil {
			errCh <- err
			return
		}
		clientWU, err := fr.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if _, ok := clientWU.(*http2.WindowUpdateFrame); !ok {
			errCh <- fmt.Errorf("want preface WINDOW_UPDATE, got %T", clientWU)
			return
		}
		hdr, err := fr.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		mh, ok := hdr.(*http2.MetaHeadersFrame)
		if !ok {
			errCh <- fmt.Errorf("want HEADERS, got %T", hdr)
			return
		}
		var encBuf bytes.Buffer
		enc := hpack.NewEncoder(&encBuf)
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/event-stream"})
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      mh.StreamID,
			BlockFragment: encBuf.Bytes(),
			EndHeaders:    true,
		}); err != nil {
			errCh <- err
			return
		}
		chunk1 := []byte("data: aaa\n\n")
		chunk2 := []byte("data: bbb\n\n")
		if err := fr.WriteData(mh.StreamID, false, chunk1); err != nil {
			errCh <- err
			return
		}
		if err := fr.WriteData(mh.StreamID, true, chunk2); err != nil {
			errCh <- err
			return
		}

		var wus []http2.WindowUpdateFrame
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && len(wus) < 4 {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			frame, err := fr.ReadFrame()
			if err != nil {
				break
			}
			if wu, ok := frame.(*http2.WindowUpdateFrame); ok {
				wus = append(wus, *wu)
			}
		}
		wuCh <- wus
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))

	chromeConn, err := newChromeH2Conn(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://chatgpt.com/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := chromeConn.roundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !strings.Contains(string(gotBody), "data: aaa") || !strings.Contains(string(gotBody), "data: bbb") {
		t.Fatalf("body = %q", gotBody)
	}

	select {
	case err := <-errCh:
		t.Fatal(err)
	case wus := <-wuCh:
		var connWU, streamWU int
		for _, wu := range wus {
			if wu.StreamID == 0 {
				connWU++
			} else {
				streamWU++
			}
		}
		if connWU < 2 || streamWU < 2 {
			t.Fatalf("WINDOW_UPDATE counts conn=%d stream=%d (want >=2 each) frames=%v", connWU, streamWU, wus)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("timed out waiting for WINDOW_UPDATE capture")
	}
}

// TestChromeH2StreamWindowUpdateIsRequired verifies stream-level WINDOW_UPDATE
// is honored independently of the connection window.
func TestChromeH2StreamWindowUpdateIsRequired(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	const bodySize = 80000 // force drain after default 65535 so SETTINGS is applied mid-body
	body := bytes.Repeat([]byte("z"), bodySize)
	errCh := make(chan error, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

		buf := make([]byte, len(chromeH2ClientPreface))
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}
		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		_, _ = fr.ReadFrame()
		_, _ = fr.ReadFrame()
		// Shrink stream window via SETTINGS. Client applies on read (mid-body drain).
		if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1000}); err != nil {
			errCh <- err
			return
		}

		var (
			streamID      uint32
			got           int
			connCredit    = 65535
			settingsAcked bool
			postAckData   int
		)
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				if f.IsAck() && !settingsAcked {
					settingsAcked = true
					// After ACK, client stream window is negative (sent 65535, init now 1000).
					// Grant stream + conn credit so the remainder can flow.
					if err := fr.WriteWindowUpdate(0, uint32(bodySize)); err != nil {
						errCh <- err
						return
					}
					connCredit += bodySize
					if err := fr.WriteWindowUpdate(streamID, uint32(bodySize)); err != nil {
						errCh <- err
						return
					}
				}
			case *http2.MetaHeadersFrame:
				streamID = f.StreamID
			case *http2.DataFrame:
				n := len(f.Data())
				if n > connCredit {
					_ = fr.WriteRSTStream(f.StreamID, http2.ErrCodeFlowControl)
					errCh <- fmt.Errorf("conn FLOW_CONTROL: sent %d credit %d", n, connCredit)
					return
				}
				connCredit -= n
				got += n
				if settingsAcked {
					postAckData += n
				}
				if f.StreamEnded() {
					if got != bodySize {
						errCh <- fmt.Errorf("got %d want %d", got, bodySize)
						return
					}
					if postAckData == 0 {
						errCh <- fmt.Errorf("expected DATA after SETTINGS ACK (stream WU path)")
						return
					}
					var encBuf bytes.Buffer
					enc := hpack.NewEncoder(&encBuf)
					_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					_ = fr.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      streamID,
						BlockFragment: encBuf.Bytes(),
						EndStream:     true,
						EndHeaders:    true,
					})
					return
				}
			}
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))

	chromeConn, err := newChromeH2Conn(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://chatgpt.com/x", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := chromeConn.roundTrip(req)
	if err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	_ = resp.Body.Close()
	<-done
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}
