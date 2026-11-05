// Command verify_chrome_h2_peet dials https://tls.peet.ws/api/all with matched
// browser TLS ClientHello + HTTP/2 Akamai SETTINGS profiles, then prints
// ja3/ja4/akamai_fingerprint for PR verification.
//
// Usage (from repo root):
//
//	go run ./scripts/verify_chrome_h2_peet.go
//	PROFILE=chrome_120 go run ./scripts/verify_chrome_h2_peet.go
//	PROFILE=all go run ./scripts/verify_chrome_h2_peet.go
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

const peetURL = "https://tls.peet.ws/api/all"

type profileSpec struct {
	Name             string
	Hello            utls.ClientHelloID
	Settings         []http2.Setting
	ConnWindowUpdate uint32
	PseudoOrder      []string
	UA               string
	WantAkamai       string
}

func profiles() []profileSpec {
	chromeSettings := []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	}
	chromeAkamai := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	return []profileSpec{
		{
			Name:             "chrome_131",
			Hello:            utls.HelloChrome_131,
			Settings:         chromeSettings,
			ConnWindowUpdate: 15663105,
			PseudoOrder:      []string{":method", ":authority", ":scheme", ":path"},
			UA:               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			WantAkamai:       chromeAkamai,
		},
		{
			Name:             "chrome_120",
			Hello:            utls.HelloChrome_120,
			Settings:         chromeSettings,
			ConnWindowUpdate: 15663105,
			PseudoOrder:      []string{":method", ":authority", ":scheme", ":path"},
			UA:               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			WantAkamai:       chromeAkamai,
		},
		{
			Name:  "safari_17",
			Hello: utls.HelloSafari_16_0,
			Settings: []http2.Setting{
				{ID: http2.SettingInitialWindowSize, Val: 4194304},
				{ID: http2.SettingMaxConcurrentStreams, Val: 100},
			},
			ConnWindowUpdate: 10485760,
			PseudoOrder:      []string{":method", ":scheme", ":path", ":authority"},
			UA:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			WantAkamai:       "4:4194304;3:100|10485760|0|m,s,p,a",
		},
	}
}

func main() {
	want := strings.ToLower(strings.TrimSpace(os.Getenv("PROFILE")))
	if want == "" {
		want = "chrome_131"
	}
	selected := make([]profileSpec, 0, 3)
	for _, p := range profiles() {
		if want == "all" || want == p.Name {
			selected = append(selected, p)
		}
	}
	if len(selected) == 0 {
		fmt.Fprintf(os.Stderr, "unknown PROFILE=%q (use chrome_131, chrome_120, safari_17, or all)\n", want)
		os.Exit(2)
	}

	summaries := make([]map[string]any, 0, len(selected))
	for _, p := range selected {
		raw, err := fetchWithProfile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s path: %v\n", p.Name, err)
			os.Exit(1)
		}
		fmt.Printf("=== %s (ClientHello %s/%s + matched H2) ===\n", p.Name, p.Hello.Client, p.Hello.Version)
		summary := printSummary(raw, p.WantAkamai)
		summary["profile"] = p.Name
		summaries = append(summaries, summary)
	}

	if len(summaries) > 1 {
		fmt.Println("=== cross-profile uniqueness ===")
		ja4s := map[string]string{}
		akamais := map[string]string{}
		for _, s := range summaries {
			name, _ := s["profile"].(string)
			if ja4, _ := s["ja4"].(string); ja4 != "" {
				if prev, ok := ja4s[ja4]; ok {
					fmt.Printf("NOTE: ja4 shared by %s and %s (%s); chrome_120/131 share JA4 family — compare ja3\n", prev, name, ja4)
				} else {
					ja4s[ja4] = name
				}
				fmt.Printf("ja4[%s]=%s\n", name, ja4)
			}
			if ja3, _ := s["ja3"].(string); ja3 != "" {
				fmt.Printf("ja3[%s]=%s\n", name, ja3)
			}
			if fp, _ := s["akamai_fingerprint"].(string); fp != "" {
				akamais[name] = fp
				fmt.Printf("akamai[%s]=%s\n", name, fp)
			}
		}
		if akamais["chrome_131"] != "" && akamais["safari_17"] != "" && akamais["chrome_131"] == akamais["safari_17"] {
			fmt.Println("ERROR: chrome_131 and safari_17 must not share akamai_fingerprint")
			os.Exit(1)
		}
	}

	if os.Getenv("COMPARE_GO") == "1" {
		goJSON, err := fetchWithGo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "go baseline: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("=== Go net/http baseline ===")
		printSummary(goJSON, "")
	}
}

func printSummary(raw []byte, wantAkamai string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		fmt.Printf("raw: %s\n", raw)
		return map[string]any{}
	}
	picked := pick(m,
		"ja3_hash", "ja3", "ja4", "akamai_fingerprint", "akamai_fingerprint_hash",
		"http_version", "tls_version_negotiated", "user_agent",
	)
	pretty, _ := json.MarshalIndent(picked, "", "  ")
	fmt.Println(string(pretty))
	fp, _ := picked["akamai_fingerprint"].(string)
	if fp != "" && wantAkamai != "" {
		if fp == wantAkamai {
			fmt.Println("akamai_fingerprint: MATCHES target")
		} else {
			fmt.Printf("akamai_fingerprint: DOES NOT match\n  got:  %s\n  want: %s\n", fp, wantAkamai)
		}
	}
	return picked
}

func pick(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
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

func headerTableSize(settings []http2.Setting) uint32 {
	for _, s := range settings {
		if s.ID == http2.SettingHeaderTableSize {
			return s.Val
		}
	}
	return 4096
}

func fetchWithProfile(p profileSpec) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", "tls.peet.ws:443", 15*time.Second)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(conn, &utls.Config{ServerName: "tls.peet.ws"}, p.Hello)
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
	fr.ReadMetaHeaders = hpack.NewDecoder(headerTableSize(p.Settings), nil)
	if err := fr.WriteSettings(p.Settings...); err != nil {
		_ = uconn.Close()
		return nil, err
	}
	if err := fr.WriteWindowUpdate(0, p.ConnWindowUpdate); err != nil {
		_ = uconn.Close()
		return nil, err
	}

	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	pseudo := map[string]string{
		":method":    "GET",
		":authority": "tls.peet.ws",
		":scheme":    "https",
		":path":      "/api/all",
	}
	for _, name := range p.PseudoOrder {
		if err := enc.WriteField(hpack.HeaderField{Name: name, Value: pseudo[name]}); err != nil {
			_ = uconn.Close()
			return nil, err
		}
	}
	for _, f := range []hpack.HeaderField{
		{Name: "user-agent", Value: p.UA},
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
	statusOK := false
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
		case *http2.MetaHeadersFrame:
			for _, hf := range frame.Fields {
				if hf.Name == ":status" && hf.Value == "200" {
					statusOK = true
				}
			}
			if frame.StreamEnded() {
				done = true
			}
		case *http2.DataFrame:
			body.Write(frame.Data())
			if frame.StreamEnded() {
				done = true
			}
		case *http2.GoAwayFrame:
			_ = uconn.Close()
			return nil, fmt.Errorf("GOAWAY: %v", frame.ErrCode)
		case *http2.RSTStreamFrame:
			_ = uconn.Close()
			return nil, fmt.Errorf("RST_STREAM: %v", frame.ErrCode)
		}
	}
	_ = uconn.Close()
	if !statusOK && body.Len() == 0 {
		return nil, fmt.Errorf("empty response")
	}
	return body.Bytes(), nil
}

func fetchWithGo() ([]byte, error) {
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}
	resp, err := client.Get(peetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
