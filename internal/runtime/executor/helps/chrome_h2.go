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

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Chrome_131 Akamai HTTP/2 fingerprint (SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo).
// Values match bogdanfinn/tls-client profiles.Chrome_131 / Chrome_133+:
//
//	1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
//
// golang.org/x/net/http2.Transport cannot emit this fingerprint: it hard-codes
// SETTINGS order (ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, …), always
// advertises MAX_FRAME_SIZE, and EncodeHeaders emits a,m,p,s. Scheme A therefore
// drives the Chrome path with Framer+hpack instead of Transport.NewClientConn.
//
// TODO(scheme-B): expose TLSClientProfile on HTTPWireProfile so pluginhost can
// opt into this client without forking the chatgpt.com host check.
const (
	chromeH2HeaderTableSize      uint32 = 65536
	chromeH2EnablePush           uint32 = 0
	chromeH2InitialWindowSize    uint32 = 6291456
	chromeH2MaxHeaderListSize    uint32 = 262144
	chromeH2ConnWindowUpdate     uint32 = 15663105
	chromeH2DefaultStreamSendWin int64  = 65535
	chromeH2DefaultMaxFrame      uint32 = 16384
)

var chromeH2ClientPreface = []byte(http2.ClientPreface)

var chromeH2Settings = []http2.Setting{
	{ID: http2.SettingHeaderTableSize, Val: chromeH2HeaderTableSize},
	{ID: http2.SettingEnablePush, Val: chromeH2EnablePush},
	{ID: http2.SettingInitialWindowSize, Val: chromeH2InitialWindowSize},
	{ID: http2.SettingMaxHeaderListSize, Val: chromeH2MaxHeaderListSize},
}

// chromeH2PseudoHeaderOrder is Chrome's :method :authority :scheme :path.
var chromeH2PseudoHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}

// chromeH2Conn is a single TCP/TLS connection speaking Chrome-shaped HTTP/2.
// Requests are serialized; at most one response body may be open at a time so
// SSE streams are not torn down by a sibling RoundTrip on the same conn.
type chromeH2Conn struct {
	conn net.Conn
	fr   *http2.Framer
	henc *hpack.Encoder
	hbuf bytes.Buffer

	mu        sync.Mutex
	nextID    uint32
	sendWin   int64
	maxFrame  uint32
	broken    bool
	busy      bool // response body outstanding
	closeOnce sync.Once
	closeErr  error
}

func newChromeH2Conn(conn net.Conn) (*chromeH2Conn, error) {
	c := &chromeH2Conn{
		conn:     conn,
		nextID:   1,
		sendWin:  chromeH2DefaultStreamSendWin,
		maxFrame: chromeH2DefaultMaxFrame,
	}
	c.henc = hpack.NewEncoder(&c.hbuf)
	c.fr = http2.NewFramer(conn, conn)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(chromeH2HeaderTableSize, nil)
	c.fr.MaxHeaderListSize = chromeH2MaxHeaderListSize

	if _, err := conn.Write(chromeH2ClientPreface); err != nil {
		return nil, fmt.Errorf("chrome h2: write preface: %w", err)
	}
	if err := c.fr.WriteSettings(chromeH2Settings...); err != nil {
		return nil, fmt.Errorf("chrome h2: write settings: %w", err)
	}
	if err := c.fr.WriteWindowUpdate(0, chromeH2ConnWindowUpdate); err != nil {
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

	if err := c.writeHeadersLocked(streamID, req, bodyBytes); err != nil {
		c.busy = false
		c.markBroken()
		c.mu.Unlock()
		return nil, err
	}
	if len(bodyBytes) > 0 {
		if err := c.writeDataLocked(req.Context(), streamID, bodyBytes); err != nil {
			c.busy = false
			c.markBroken()
			c.mu.Unlock()
			return nil, err
		}
	}

	status, hdr, endStream, err := c.readResponseHeadersLocked(req.Context(), streamID)
	if err != nil {
		c.busy = false
		c.markBroken()
		c.mu.Unlock()
		return nil, err
	}

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
	for _, name := range chromeH2PseudoHeaderOrder {
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
		n := len(body)
		if int64(n) > c.sendWin {
			n = int(c.sendWin)
		}
		if n > int(c.maxFrame) {
			n = int(c.maxFrame)
		}
		if n <= 0 {
			if err := c.drainControlLocked(ctx); err != nil {
				return err
			}
			continue
		}
		end := n == len(body)
		if err := c.fr.WriteData(streamID, end, body[:n]); err != nil {
			return err
		}
		c.sendWin -= int64(n)
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
			if err := c.handleControlLocked(f); err != nil {
				return 0, nil, false, err
			}
		}
	}
}

func (c *chromeH2Conn) drainControlLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	frame, err := c.fr.ReadFrame()
	if err != nil {
		return err
	}
	return c.handleControlLocked(frame)
}

func (c *chromeH2Conn) handleControlLocked(frame http2.Frame) error {
	switch f := frame.(type) {
	case *http2.SettingsFrame:
		if !f.IsAck() {
			f.ForeachSetting(func(s http2.Setting) error {
				switch s.ID {
				case http2.SettingInitialWindowSize:
					c.sendWin = int64(s.Val)
				case http2.SettingMaxFrameSize:
					if s.Val >= chromeH2DefaultMaxFrame {
						c.maxFrame = s.Val
					}
				}
				return nil
			})
			return c.fr.WriteSettingsAck()
		}
	case *http2.WindowUpdateFrame:
		if f.StreamID == 0 {
			c.sendWin += int64(f.Increment)
		}
	case *http2.PingFrame:
		if !f.IsAck() {
			return c.fr.WritePing(true, f.Data)
		}
	case *http2.GoAwayFrame:
		c.markBroken()
	case *http2.RSTStreamFrame:
		// Ignore RST for other streams.
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
			if n := len(payload); n > 0 {
				_ = c.fr.WriteWindowUpdate(0, uint32(n))
				_ = c.fr.WriteWindowUpdate(streamID, uint32(n))
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
			if err := c.handleControlLocked(f); err != nil {
				return nil, false, err
			}
		}
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
		b.conn.mu.Lock()
		data, end, err := b.conn.readBodyFrameLocked(ctx, b.streamID)
		if err != nil {
			b.conn.markBroken()
			b.conn.busy = false
			b.conn.mu.Unlock()
			return 0, err
		}
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

// chromeH2SettingsFingerprint returns the Akamai SETTINGS|WINDOW_UPDATE portion
// expected from chromeH2Settings (no PRIORITY / pseudo — those are request-scoped).
func chromeH2SettingsFingerprint() string {
	parts := make([]string, 0, len(chromeH2Settings))
	for _, s := range chromeH2Settings {
		parts = append(parts, fmt.Sprintf("%d:%d", s.ID, s.Val))
	}
	return strings.Join(parts, ";") + fmt.Sprintf("|%d|0|m,a,s,p", chromeH2ConnWindowUpdate)
}
