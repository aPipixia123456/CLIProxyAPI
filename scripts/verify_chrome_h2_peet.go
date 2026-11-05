// Command verify_chrome_h2_peet dials https://tls.peet.ws/api/all with a
// Chrome_131 uTLS ClientHello and Chrome Akamai HTTP/2 SETTINGS, then prints
// ja3/ja4/akamai_fingerprint for PR verification.
//
// Usage (from repo root):
//
//	go run ./scripts/verify_chrome_h2_peet.go
//
// Optional COMPARE_GO=1 also prints a bare net/http baseline.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	peetURL = "https://tls.peet.ws/api/all"

	chromeH2HeaderTableSize   uint32 = 65536
	chromeH2EnablePush        uint32 = 0
	chromeH2InitialWindowSize uint32 = 6291456
	chromeH2MaxHeaderListSize uint32 = 262144
	chromeH2ConnWindowUpdate  uint32 = 15663105
)

var chromeH2Settings = []http2.Setting{
	{ID: http2.SettingHeaderTableSize, Val: chromeH2HeaderTableSize},
	{ID: http2.SettingEnablePush, Val: chromeH2EnablePush},
	{ID: http2.SettingInitialWindowSize, Val: chromeH2InitialWindowSize},
	{ID: http2.SettingMaxHeaderListSize, Val: chromeH2MaxHeaderListSize},
}

func main() {
	chromeJSON, err := fetchWithChrome()
	if err != nil {
		fmt.Fprintf(os.Stderr, "chrome path: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("=== Chrome_131 uTLS + Chrome Akamai H2 (scheme A) ===")
	printSummary(chromeJSON)

	if os.Getenv("COMPARE_GO") == "1" {
		goJSON, err := fetchWithGo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "go baseline: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("=== Go net/http baseline ===")
		printSummary(goJSON)
	}
}

func printSummary(raw []byte) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		fmt.Printf("raw: %s\n", raw)
		return
	}
	pretty, _ := json.MarshalIndent(pick(m,
		"ja3_hash", "ja3", "ja4", "akamai_fingerprint", "akamai_fingerprint_hash",
		"http_version", "tls_version_negotiated", "user_agent",
	), "", "  ")
	fmt.Println(string(pretty))
	fp, _ := m["akamai_fingerprint"].(string)
	if fp == "" {
		if h2, ok := m["http2"].(map[string]any); ok {
			fp, _ = h2["akamai_fingerprint"].(string)
		}
	}
	if fp != "" {
		want := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
		if fp == want {
			fmt.Println("akamai_fingerprint: MATCHES Chrome_131 target")
		} else {
			fmt.Printf("akamai_fingerprint: DOES NOT match\n  got:  %s\n  want: %s\n", fp, want)
		}
	}
}

func pick(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	// peet sometimes nests tls / http2
	if tlsObj, ok := m["tls"].(map[string]any); ok {
		for _, k := range []string{"ja3_hash", "ja3", "ja4"} {
			if _, have := out[k]; !have {
				if v, ok := tlsObj[k]; ok {
					out[k] = v
				}
			}
		}
	}
	if h2, ok := m["http2"].(map[string]any); ok {
		for _, k := range []string{"akamai_fingerprint", "akamai_fingerprint_hash"} {
			if _, have := out[k]; !have {
				if v, ok := h2[k]; ok {
					out[k] = v
				}
			}
		}
	}
	return out
}

func fetchWithChrome() ([]byte, error) {
	conn, err := net.DialTimeout("tcp", "tls.peet.ws:443", 15*time.Second)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(conn, &utls.Config{ServerName: "tls.peet.ws"}, utls.HelloChrome_131)
	if err := uconn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	if uconn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = uconn.Close()
		return nil, fmt.Errorf("ALPN=%q, want h2", uconn.ConnectionState().NegotiatedProtocol)
	}

	if _, err := uconn.Write([]byte(http2.ClientPreface)); err != nil {
		_ = uconn.Close()
		return nil, err
	}
	fr := http2.NewFramer(uconn, uconn)
	fr.ReadMetaHeaders = hpack.NewDecoder(chromeH2HeaderTableSize, nil)
	if err := fr.WriteSettings(chromeH2Settings...); err != nil {
		_ = uconn.Close()
		return nil, err
	}
	if err := fr.WriteWindowUpdate(0, chromeH2ConnWindowUpdate); err != nil {
		_ = uconn.Close()
		return nil, err
	}

	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "tls.peet.ws"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/api/all"},
		{Name: "user-agent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
		{Name: "accept", Value: "*/*"},
	} {
		if err := enc.WriteField(f); err != nil {
			_ = uconn.Close()
			return nil, err
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbuf.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}); err != nil {
		_ = uconn.Close()
		return nil, err
	}

	var body bytes.Buffer
	done := false
	for !done {
		f, err := fr.ReadFrame()
		if err != nil {
			_ = uconn.Close()
			return nil, err
		}
		switch frame := f.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.WindowUpdateFrame:
		case *http2.PingFrame:
			_ = fr.WritePing(true, frame.Data)
		case *http2.HeadersFrame:
			// Meta via ReadMetaHeaders when EndHeaders
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = mh
			}
			if frame.StreamEnded() {
				done = true
			}
		case *http2.MetaHeadersFrame:
			if frame.StreamEnded() {
				done = true
			}
		case *http2.DataFrame:
			body.Write(frame.Data())
			if frame.StreamEnded() {
				done = true
			}
		case *http2.RSTStreamFrame:
			_ = uconn.Close()
			return nil, fmt.Errorf("RST_STREAM: %v", frame.ErrCode)
		case *http2.GoAwayFrame:
			_ = uconn.Close()
			return nil, fmt.Errorf("GOAWAY: %v", frame.ErrCode)
		}
	}
	_ = uconn.Close()
	return body.Bytes(), nil
}

func fetchWithGo() ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "tls.peet.ws"},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	resp, err := client.Get(peetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
