package helps

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Browser-shaped HTTP/2 (SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo) for the
// chatgpt.com uTLS path. Profile values live in browser_fingerprint.go and match
// bogdanfinn/tls-client tables so TLS ClientHello and H2 Akamai stay paired.
//
// golang.org/x/net/http2.Transport cannot emit browser fingerprints: it hard-codes
// SETTINGS order (ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, …), always
// advertises MAX_FRAME_SIZE, and EncodeHeaders emits a,m,p,s. Scheme A therefore
// drives this path with Framer+hpack instead of Transport.NewClientConn.
//
// TODO(scheme-B): expose TLSClientProfile on HTTPWireProfile so pluginhost can
// opt into this client without forking the chatgpt.com host check.
const (
	chromeH2DefaultStreamSendWin int64  = 65535
	chromeH2DefaultMaxFrame      uint32 = 16384
)

var chromeH2ClientPreface = []byte(http2.ClientPreface)

// Legacy aliases kept for tests that assert the chrome_131 defaults.
var (
	chromeH2Settings          = browserFingerprintChrome131.Settings
	chromeH2PseudoHeaderOrder = browserFingerprintChrome131.PseudoOrder
	chromeH2ConnWindowUpdate  = browserFingerprintChrome131.ConnWindowUpdate
	chromeH2HeaderTableSize   = browserFingerprintChrome131.headerTableSize()
)

// chromeH2Conn is a single TCP/TLS connection speaking Chrome-shaped HTTP/2.
// Requests are serialized; at most one response body may be open at a time so
// SSE streams are not torn down by a sibling RoundTrip on the same conn.
type chromeH2Conn struct {
	conn    net.Conn
	fr      *http2.Framer
	henc    *hpack.Encoder
	hbuf    bytes.Buffer
	profile *browserFingerprintProfile

	mu     sync.Mutex
	nextID uint32
	// Separate connection-level and stream-level outbound windows (RFC 7540 §6.9).
	// SETTINGS_INITIAL_WINDOW_SIZE only affects stream windows; the connection
	// window starts at 65535 and grows only via WINDOW_UPDATE(stream=0).
	connSendWin          int64
	streamSendWin        int64 // active request stream; single-stream client
	peerInitialStreamWin int64 // last SETTINGS_INITIAL_WINDOW_SIZE from peer
	maxFrame             uint32
	broken               bool
	busy                 bool // response body outstanding
	closeOnce            sync.Once
	closeErr             error
}

func newChromeH2Conn(conn net.Conn) (*chromeH2Conn, error) {
	return newChromeH2ConnWithProfile(conn, browserFingerprintChrome131)
}

func newChromeH2ConnWithProfile(conn net.Conn, profile *browserFingerprintProfile) (*chromeH2Conn, error) {
	if profile == nil {
		profile = browserFingerprintChrome131
	}
	c := &chromeH2Conn{
		conn:                 conn,
		profile:              profile,
		nextID:               1,
		connSendWin:          chromeH2DefaultStreamSendWin,
		streamSendWin:        chromeH2DefaultStreamSendWin,
		peerInitialStreamWin: chromeH2DefaultStreamSendWin,
		maxFrame:             chromeH2DefaultMaxFrame,
	}
	c.henc = hpack.NewEncoder(&c.hbuf)
	c.fr = http2.NewFramer(conn, conn)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(profile.headerTableSize(), nil)
	c.fr.MaxHeaderListSize = profile.maxHeaderListSize()

	if _, err := conn.Write(chromeH2ClientPreface); err != nil {
		return nil, fmt.Errorf("chrome h2: write preface: %w", err)
	}
	if err := c.fr.WriteSettings(profile.Settings...); err != nil {
		return nil, fmt.Errorf("chrome h2: write settings: %w", err)
	}
	if err := c.fr.WriteWindowUpdate(0, profile.ConnWindowUpdate); err != nil {
		return nil, fmt.Errorf("chrome h2: write window update: %w", err)
	}
	return c, nil
}

func (c *chromeH2Conn) markBroken() {
	c.broken = true
}

func (c *chromeH2Conn) isReusable() bool {
	return !c.broken && !c.busy
}

func (c *chromeH2Conn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.broken = true
		c.mu.Unlock()
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}

// roundTrip writes one request and returns a response whose Body streams DATA
// frames. The connection stays owned by the body until Body.Close.
func (c *chromeH2Conn) roundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	if c.broken {
		c.mu.Unlock()
		return nil, errors.New("chrome h2: connection broken")
	}
	if c.busy {
		c.mu.Unlock()
		return nil, errors.New("chrome h2: connection busy")
	}
	c.busy = true

	streamID := c.nextID
	c.nextID += 2
	// New stream inherits the peer's current SETTINGS_INITIAL_WINDOW_SIZE.
	c.streamSendWin = c.peerInitialStreamWin

	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			c.busy = false
			c.markBroken()
			c.mu.Unlock()
			return nil, fmt.Errorf("chrome h2: read request body: %w", err)
		}
	}

	stopCancel := armConnCancel(req.Context(), c.conn)
	if err := c.writeHeadersLocked(streamID, req, bodyBytes); err != nil {
		stopCancel()
		c.busy = false
		c.markBroken()
		c.mu.Unlock()
		return nil, err
	}
	if len(bodyBytes) > 0 {
		if err := c.writeDataLocked(req.Context(), streamID, bodyBytes); err != nil {
			stopCancel()
			c.busy = false
			c.markBroken()
			c.mu.Unlock()
			return nil, err
		}
	}

	status, hdr, endStream, err := c.readResponseHeadersLocked(req.Context(), streamID)
	if err != nil {
		stopCancel()
		c.busy = false
		c.markBroken()
		c.mu.Unlock()
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	stopCancel()

	body := &chromeH2Body{
		conn:     c,
		streamID: streamID,
		ended:    endStream,
	}
	if endStream {
		c.busy = false
	}
	c.mu.Unlock()

	contentLength := int64(-1)
	if cl := hdr.Get("Content-Length"); cl != "" {
		if n, errParse := strconv.ParseInt(cl, 10, 64); errParse == nil {
			contentLength = n
		}
	} else if endStream {
		contentLength = 0
	}

	return &http.Response{
		StatusCode:    status,
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        hdr,
		Body:          body,
		ContentLength: contentLength,
		Request:       req,
		TLS:           nil, // filled by caller when available
	}, nil
}

func (c *chromeH2Conn) writeHeadersLocked(streamID uint32, req *http.Request, body []byte) error {
	c.hbuf.Reset()
	endStream := len(body) == 0
	authority := req.Host
	if authority == "" {
		authority = req.URL.Host
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}

	pseudo := map[string]string{
		":method":    method,
		":authority": authority,
		":scheme":    scheme,
		":path":      path,
	}
	for _, name := range c.profile.PseudoOrder {
		if err := c.henc.WriteField(hpack.HeaderField{Name: name, Value: pseudo[name]}); err != nil {
			return fmt.Errorf("chrome h2: encode %s: %w", name, err)
		}
	}

	written := map[string]bool{
		"host": true, // :authority
	}
	emit := func(key string) error {
		lower := strings.ToLower(key)
		if written[lower] || isChromeH2SkippedHeader(lower) {
			return nil
		}
		vals := req.Header.Values(key)
		if len(vals) == 0 {
			return nil
		}
		written[lower] = true
		for _, v := range vals {
			if err := c.henc.WriteField(hpack.HeaderField{Name: lower, Value: v}); err != nil {
				return err
			}
		}
		return nil
	}
	for key := range req.Header {
		if err := emit(key); err != nil {
			return fmt.Errorf("chrome h2: encode header %q: %w", key, err)
		}
	}
	if !written["content-length"] && len(body) > 0 {
		if err := c.henc.WriteField(hpack.HeaderField{
			Name:  "content-length",
			Value: strconv.Itoa(len(body)),
		}); err != nil {
			return err
		}
	}

	return c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: append([]byte(nil), c.hbuf.Bytes()...),
		EndStream:     endStream,
		EndHeaders:    true,
	})
}

func (c *chromeH2Conn) writeDataLocked(ctx context.Context, streamID uint32, body []byte) error {
	for len(body) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		avail := c.connSendWin
		if c.streamSendWin < avail {
			avail = c.streamSendWin
		}
		n := len(body)
		if int64(n) > avail {
			n = int(avail)
		}
		if n > int(c.maxFrame) {
			n = int(c.maxFrame)
		}
		if n <= 0 {
			if err := c.drainControlLocked(ctx, streamID); err != nil {
				return err
			}
			continue
		}
		end := n == len(body)
		if err := c.fr.WriteData(streamID, end, body[:n]); err != nil {
			return err
		}
		c.connSendWin -= int64(n)
		c.streamSendWin -= int64(n)
		body = body[n:]
	}
	return nil
}

func (c *chromeH2Conn) readResponseHeadersLocked(ctx context.Context, streamID uint32) (status int, hdr http.Header, endStream bool, err error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, nil, false, err
		}
		frame, errRead := c.fr.ReadFrame()
		if errRead != nil {
			return 0, nil, false, errRead
		}
		switch f := frame.(type) {
		case *http2.MetaHeadersFrame:
			if f.StreamID != streamID {
				continue
			}
			hdr = make(http.Header)
			for _, hf := range f.Fields {
				if hf.Name == ":status" {
					status, _ = strconv.Atoi(hf.Value)
					continue
				}
				if strings.HasPrefix(hf.Name, ":") {
					continue
				}
				hdr.Add(hf.Name, hf.Value)
			}
			if status == 0 {
				return 0, nil, false, errors.New("chrome h2: response missing :status")
			}
			return status, hdr, f.StreamEnded(), nil
		case *http2.DataFrame:
			// Unexpected DATA before headers for our stream.
			if f.StreamID == streamID {
				return 0, nil, false, errors.New("chrome h2: DATA before HEADERS")
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				return 0, nil, false, fmt.Errorf("chrome h2: stream reset: %v", f.ErrCode)
			}
		case *http2.GoAwayFrame:
			c.markBroken()
			if streamID > f.LastStreamID {
				return 0, nil, false, fmt.Errorf("chrome h2: GOAWAY: %v", f.ErrCode)
			}
		default:
			if err := c.handleControlLocked(f, streamID); err != nil {
				return 0, nil, false, err
			}
		}
	}
}

func (c *chromeH2Conn) drainControlLocked(ctx context.Context, streamID uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	frame, err := c.fr.ReadFrame()
	if err != nil {
		return err
	}
	return c.handleControlLocked(frame, streamID)
}

// handleControlLocked processes non-HEADERS/DATA control frames.
// streamID is the active request stream (0 if none); RST for that stream is fatal.
func (c *chromeH2Conn) handleControlLocked(frame http2.Frame, streamID uint32) error {
	switch f := frame.(type) {
	case *http2.MetaHeadersFrame:
		return fmt.Errorf("chrome h2: unexpected HEADERS on stream %d while waiting for flow control", f.StreamID)
	case *http2.DataFrame:
		return fmt.Errorf("chrome h2: unexpected DATA on stream %d while waiting for flow control", f.StreamID)
	case *http2.SettingsFrame:
		if !f.IsAck() {
			var err error
			f.ForeachSetting(func(s http2.Setting) error {
				switch s.ID {
				case http2.SettingInitialWindowSize:
					// RFC 7540 §6.9.2: adjust existing stream windows by the
					// delta; connection window is unchanged.
					if s.Val > 0x7fffffff {
						err = fmt.Errorf("chrome h2: INITIAL_WINDOW_SIZE too large: %d", s.Val)
						return err
					}
					newInit := int64(s.Val)
					delta := newInit - c.peerInitialStreamWin
					c.peerInitialStreamWin = newInit
					c.streamSendWin += delta
					if c.streamSendWin > 0x7fffffff {
						err = errors.New("chrome h2: stream flow-control window overflow")
						return err
					}
				case http2.SettingMaxFrameSize:
					if s.Val >= chromeH2DefaultMaxFrame && s.Val <= 0xffffff {
						c.maxFrame = s.Val
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			return c.fr.WriteSettingsAck()
		}
	case *http2.WindowUpdateFrame:
		if f.Increment == 0 {
			return fmt.Errorf("chrome h2: WINDOW_UPDATE increment 0 on stream %d", f.StreamID)
		}
		if f.StreamID == 0 {
			sum := c.connSendWin + int64(f.Increment)
			if sum > 0x7fffffff {
				return errors.New("chrome h2: connection flow-control window overflow")
			}
			c.connSendWin = sum
		} else if streamID != 0 && f.StreamID == streamID {
			sum := c.streamSendWin + int64(f.Increment)
			if sum > 0x7fffffff {
				return errors.New("chrome h2: stream flow-control window overflow")
			}
			c.streamSendWin = sum
		}
	case *http2.PingFrame:
		if !f.IsAck() {
			return c.fr.WritePing(true, f.Data)
		}
	case *http2.GoAwayFrame:
		c.markBroken()
		if streamID != 0 && streamID > f.LastStreamID {
			return fmt.Errorf("chrome h2: GOAWAY: %v", f.ErrCode)
		}
	case *http2.RSTStreamFrame:
		if streamID != 0 && f.StreamID == streamID {
			return fmt.Errorf("chrome h2: stream reset: %v", f.ErrCode)
		}
	}
	return nil
}

func (c *chromeH2Conn) readBodyFrameLocked(ctx context.Context, streamID uint32) (data []byte, end bool, err error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		frame, errRead := c.fr.ReadFrame()
		if errRead != nil {
			return nil, false, errRead
		}
		switch f := frame.(type) {
		case *http2.DataFrame:
			if f.StreamID != streamID {
				continue
			}
			payload := append([]byte(nil), f.Data()...)
			// Flow control is charged for the full frame length (incl. padding).
			if f.Length > 0 {
				_ = c.fr.WriteWindowUpdate(0, f.Length)
				_ = c.fr.WriteWindowUpdate(streamID, f.Length)
			}
			return payload, f.StreamEnded(), nil
		case *http2.MetaHeadersFrame:
			// Trailers; treat as end of stream.
			if f.StreamID == streamID {
				return nil, true, nil
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				return nil, false, fmt.Errorf("chrome h2: stream reset: %v", f.ErrCode)
			}
		case *http2.GoAwayFrame:
			c.markBroken()
			if streamID > f.LastStreamID {
				return nil, false, fmt.Errorf("chrome h2: GOAWAY: %v", f.ErrCode)
			}
		default:
			if err := c.handleControlLocked(f, streamID); err != nil {
				return nil, false, err
			}
		}
	}
}

// armConnCancel forces pending reads/writes to unblock when ctx is canceled
// by expiring the connection deadline. Call the returned stop func when the
// wait ends so a successful RoundTrip does not leave a stale deadline.
func armConnCancel(ctx context.Context, conn net.Conn) (stop func()) {
	if ctx == nil || conn == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() {
		select {
		case <-done:
		default:
			close(done)
		}
		_ = conn.SetDeadline(time.Time{})
	}
}

func isChromeH2SkippedHeader(lower string) bool {
	switch lower {
	case "host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
		return true
	}
	return false
}

// chromeH2Body streams DATA frames for one response. Closing releases the
// connection back to the RoundTripper idle pool (unless broken).
type chromeH2Body struct {
	conn     *chromeH2Conn
	streamID uint32
	buf      []byte
	ended    bool
	closed   atomic.Bool
	onClose  func(reusable bool)
	readCtx  context.Context
}

func (b *chromeH2Body) Read(p []byte) (int, error) {
	if b.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(b.buf) == 0 {
		if b.ended {
			return 0, io.EOF
		}
		ctx := b.readCtx
		if ctx == nil {
			ctx = context.Background()
		}
		stopCancel := armConnCancel(ctx, b.conn.conn)
		b.conn.mu.Lock()
		data, end, err := b.conn.readBodyFrameLocked(ctx, b.streamID)
		if err != nil {
			b.conn.markBroken()
			b.conn.busy = false
			b.conn.mu.Unlock()
			stopCancel()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return 0, ctxErr
			}
			return 0, err
		}
		stopCancel()
		b.buf = data
		b.ended = end
		if end {
			b.conn.busy = false
		}
		b.conn.mu.Unlock()
		if len(b.buf) == 0 && b.ended {
			return 0, io.EOF
		}
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}

func (b *chromeH2Body) Close() error {
	if !b.closed.CompareAndSwap(false, true) {
		return nil
	}
	reusable := false
	b.conn.mu.Lock()
	if !b.ended && !b.conn.broken {
		// Abort the stream so the peer stops sending; do not reuse.
		_ = b.conn.fr.WriteRSTStream(b.streamID, http2.ErrCodeCancel)
		b.conn.markBroken()
	}
	b.conn.busy = false
	reusable = b.conn.isReusable()
	b.conn.mu.Unlock()
	if b.onClose != nil {
		b.onClose(reusable)
		return nil
	}
	if !reusable {
		return b.conn.Close()
	}
	return nil
}

// chromeH2SettingsFingerprint returns the default chrome_131 Akamai fingerprint.
func chromeH2SettingsFingerprint() string {
	return browserFingerprintChrome131.akamaiFingerprint()
}
