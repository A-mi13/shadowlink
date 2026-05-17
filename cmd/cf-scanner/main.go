// CF IP Scanner — находит стабильные Cloudflare edge IP для WebSocket.
//
// Делает реальный ShadowLink handshake через каждый CF IP, затем upgrade на WS
// и считает сколько messages пройдёт до разрыва. Лучший IP = параметр cfip= в sl:// URL.
//
// Использование:
//
//	cf-scanner -import "sl://PUBKEY@domain:443?tls=1&cdn=domain" -n 15 -duration 30s
//	cf-scanner -import "sl://..." -ip 104.16.0.1,172.64.100.5 -duration 20s
//	cf-scanner -import "sl://..." -cidr 104.16.0.0/24 -n 10
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// cfRanges — Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4).
var cfRanges = []string{
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
}

type scanResult struct {
	IP        string
	Latency   time.Duration // TLS handshake latency
	Messages  int           // WS messages before disconnect
	Duration  time.Duration // how long WS stayed alive
	Error     string
	Colo      string // CF PoP
	Handshake bool   // ShadowLink handshake succeeded
}

func main() {
	importURL := flag.String("import", "", "sl:// URL (required)")
	ipList := flag.String("ip", "", "comma-separated CF IPs to test")
	cidrStr := flag.String("cidr", "", "CIDR range to sample from")
	n := flag.Int("n", 15, "number of random IPs to test")
	duration := flag.Duration("duration", 30*time.Second, "how long to keep each WS alive")
	workers := flag.Int("workers", 3, "parallel workers")
	topN := flag.Int("top", 10, "show top N results")
	flag.Parse()

	if *importURL == "" {
		fmt.Fprintln(os.Stderr, "ошибка: -import обязателен (sl:// URL)")
		flag.Usage()
		os.Exit(1)
	}

	cfg, err := client.ParseSLURL(*importURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка парсинга sl:// URL: %v\n", err)
		os.Exit(1)
	}

	domain := cfg.CDN
	if domain == "" {
		h, _, _ := net.SplitHostPort(cfg.Server)
		domain = h
	}
	if domain == "" {
		fmt.Fprintln(os.Stderr, "ошибка: не удалось определить домен из URL")
		os.Exit(1)
	}

	pubKey, err := hex.DecodeString(cfg.PubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка pubkey: %v\n", err)
		os.Exit(1)
	}

	// Collect IPs.
	var ips []string
	if *ipList != "" {
		for _, ip := range strings.Split(*ipList, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
	}
	if *cidrStr != "" {
		ips = append(ips, sampleFromCIDR(*cidrStr, *n)...)
	}
	if len(ips) == 0 {
		ips = sampleFromRanges(cfRanges, *n)
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "ошибка: нет IP для сканирования")
		os.Exit(1)
	}

	fmt.Printf("CF IP Scanner: domain=%s, IPs=%d, duration=%s, workers=%d\n\n",
		domain, len(ips), *duration, *workers)

	// Scan.
	results := make([]scanResult, len(ips))
	var wg sync.WaitGroup
	sem := make(chan struct{}, *workers)

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := testCFEdge(ip, domain, pubKey, cfg.ClientID, *duration)
			results[idx] = r

			status := "OK"
			if r.Error != "" {
				status = r.Error
			}
			emoji := " "
			if r.Messages >= 20 {
				emoji = "+"
			}
			fmt.Printf("  %s [%d/%d] %-16s lat=%-6s msgs=%-4d alive=%-8s colo=%-4s %s\n",
				emoji, idx+1, len(ips), ip,
				r.Latency.Round(time.Millisecond),
				r.Messages,
				r.Duration.Round(time.Millisecond),
				r.Colo, status)
		}(i, ip)
	}

	wg.Wait()

	// Sort: messages DESC, then latency ASC.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Messages != results[j].Messages {
			return results[i].Messages > results[j].Messages
		}
		return results[i].Latency < results[j].Latency
	})

	fmt.Printf("\n=== TOP %d CF Edge IPs ===\n", *topN)
	fmt.Printf("%-16s %-6s %-8s %-10s %-5s %s\n",
		"IP", "Msgs", "Latency", "Alive", "Colo", "Status")
	fmt.Println(strings.Repeat("-", 65))

	shown := 0
	for _, r := range results {
		if shown >= *topN {
			break
		}
		status := "OK"
		if r.Error != "" {
			status = r.Error
		}
		fmt.Printf("%-16s %-6d %-8s %-10s %-5s %s\n",
			r.IP, r.Messages,
			r.Latency.Round(time.Millisecond),
			r.Duration.Round(time.Millisecond),
			r.Colo, status)
		shown++
	}

	// Hint.
	if len(results) > 0 && results[0].Messages > 0 {
		fmt.Printf("\nЛучший IP: %s (colo=%s, msgs=%d, alive=%s)\n",
			results[0].IP, results[0].Colo, results[0].Messages,
			results[0].Duration.Round(time.Millisecond))
		fmt.Printf("Добавь в URL: &cfip=%s\n", results[0].IP)
	}
}

// testCFEdge tests a single CF edge IP: TLS latency, handshake, WS stability.
func testCFEdge(ip, domain string, serverPub []byte, clientID string, duration time.Duration) scanResult {
	r := scanResult{IP: ip}
	port := "443"
	addr := net.JoinHostPort(ip, port)

	// Step 1: TLS latency.
	start := time.Now()
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", addr,
		&tls.Config{ServerName: domain},
	)
	if err != nil {
		r.Error = "tls:" + truncErr(err)
		return r
	}
	r.Latency = time.Since(start)
	tlsConn.Close()

	// Step 2: CF PoP.
	r.Colo = getCFColo(ip, port, domain)

	// Step 3: ShadowLink handshake via this CF IP.
	hello, clientState, err := core.NewClientHello([]byte(clientID), serverPub)
	if err != nil {
		r.Error = "hello:" + truncErr(err)
		return r
	}

	handshakeBody := buildHandshakeBody(hello)
	hsResp, err := doHandshake(addr, domain, handshakeBody)
	if err != nil {
		r.Error = "hs:" + truncErr(err)
		return r
	}

	respData, _, err := browser.ParseDownloadResponse(hsResp)
	if err != nil {
		r.Error = "parse:" + truncErr(err)
		return r
	}

	var shData struct {
		EphPub    []byte `json:"eph"`
		Token     []byte `json:"tok"`
		MaxConns  uint8  `json:"mc"`
		ChunkSize uint16 `json:"cs"`
	}
	if err := json.Unmarshal(respData, &shData); err != nil {
		r.Error = "json:" + truncErr(err)
		return r
	}

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		MaxConnsPerClient:     shData.MaxConns,
		ChunkSize:             shData.ChunkSize,
	}

	session, err := core.CompleteHandshake(clientState, serverHello)
	if err != nil {
		r.Error = "session:" + truncErr(err)
		return r
	}
	defer session.Destroy()

	r.Handshake = true
	token := browser.EncodeTokenWithHint(session.ID, shData.Token)

	// Step 4: WS upgrade through this CF IP.
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		WriteBufferSize:  65536,
		ReadBufferSize:   65536,
		TLSClientConfig:  &tls.Config{ServerName: domain},
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}

	wsURL := fmt.Sprintf("wss://%s/ws", domain)
	header := http.Header{}
	header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(token))
	header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		r.Error = "ws:" + truncErr(err)
		return r
	}
	defer conn.Close()

	// Step 5: Send keepalive messages, count how many survive.
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	wsStart := time.Now()
	msgCount := 0

	for {
		select {
		case <-ctx.Done():
			r.Messages = msgCount
			r.Duration = time.Since(wsStart)
			return r
		default:
		}

		// Build and send a keepalive chunk.
		chunk := core.NewKeepaliveChunk(session.ID, session.NextSeqNum())
		enc, err := session.EncryptChunk(chunk)
		if err != nil {
			r.Messages = msgCount
			r.Duration = time.Since(wsStart)
			r.Error = "encrypt:" + truncErr(err)
			return r
		}

		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteMessage(websocket.BinaryMessage, enc); err != nil {
			r.Messages = msgCount
			r.Duration = time.Since(wsStart)
			return r
		}

		// Read response (server echoes keepalive).
		// Any error (including timeout) terminates this edge test — after a
		// failed Read gorilla/websocket marks the conn as dead and any
		// subsequent ReadMessage panics with "repeated read on failed
		// websocket connection". So we don't retry.
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _, err = conn.ReadMessage()
		if err != nil {
			r.Messages = msgCount
			r.Duration = time.Since(wsStart)
			return r
		}

		msgCount++
		// ~1 msg/sec — gentle pace. Use ctx-aware sleep so an external
		// cancel terminates within the loop's 1 s pacing instead of
		// blocking on the unconditional Sleep (T4 P3 cleanup,
		// 2026-05-03 final audit).
		select {
		case <-ctx.Done():
			r.Messages = msgCount
			r.Duration = time.Since(wsStart)
			return r
		case <-time.After(1 * time.Second):
		}
	}
}

// buildHandshakeBody creates the JSON analytics event body for ShadowLink handshake.
func buildHandshakeBody(hello *core.ClientHello) []byte {
	payload := make([]byte, 0, len(hello.EphemeralPub)+len(hello.EncryptedClientID))
	payload = append(payload, hello.EphemeralPub...)
	payload = append(payload, hello.EncryptedClientID...)

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	type evt struct {
		Type string `json:"type"`
		TS   int64  `json:"ts"`
		Data string `json:"data"`
	}
	type envelope struct {
		Events []evt `json:"events"`
	}
	body, _ := json.Marshal(envelope{Events: []evt{{
		Type: "init", TS: time.Now().UnixMilli(), Data: encoded,
	}}})
	return body
}

// doHandshake sends the ShadowLink handshake through a specific CF IP.
func doHandshake(addr, domain string, body []byte) ([]byte, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: domain},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	httpClient := &http.Client{Timeout: 15 * time.Second, Transport: transport}

	url := fmt.Sprintf("https://%s/collect", domain)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	return buf[:n], nil
}

// getCFColo fetches CF PoP code from cdn-cgi/trace.
func getCFColo(ip, port, domain string) string {
	addr := net.JoinHostPort(ip, port)
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: domain},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, addr)
			},
		},
	}

	resp, err := httpClient.Get(fmt.Sprintf("https://%s/cdn-cgi/trace", domain))
	if err != nil {
		return "?"
	}
	defer resp.Body.Close()

	buf := make([]byte, 2048)
	n, _ := resp.Body.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		if strings.HasPrefix(line, "colo=") {
			return strings.TrimPrefix(line, "colo=")
		}
	}
	return "?"
}

func sampleFromCIDR(cidrStr string, n int) []string {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil
	}
	return randomIPsFromNet(ipNet, n)
}

func sampleFromRanges(ranges []string, n int) []string {
	var nets []*net.IPNet
	for _, r := range ranges {
		_, ipNet, err := net.ParseCIDR(r)
		if err != nil {
			continue
		}
		nets = append(nets, ipNet)
	}
	if len(nets) == 0 {
		return nil
	}

	var ips []string
	perRange := max(1, n/len(nets))
	for _, ipNet := range nets {
		ips = append(ips, randomIPsFromNet(ipNet, perRange)...)
	}
	rand.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
	if len(ips) > n {
		ips = ips[:n]
	}
	return ips
}

func randomIPsFromNet(ipNet *net.IPNet, n int) []string {
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return nil
	}
	maxHosts := uint32(1) << min(hostBits, 24)

	var ips []string
	seen := make(map[string]bool)

	for attempts := 0; len(ips) < n && attempts < n*10; attempts++ {
		offset := rand.Uint32N(maxHosts)
		if offset == 0 || offset == maxHosts-1 {
			continue
		}

		ip := make(net.IP, 4)
		baseIP := ipNet.IP.To4()
		if baseIP == nil {
			return nil
		}
		copy(ip, baseIP)
		ip[3] += byte(offset & 0xFF)
		ip[2] += byte((offset >> 8) & 0xFF)
		ip[1] += byte((offset >> 16) & 0xFF)

		s := ip.String()
		if !seen[s] && ipNet.Contains(ip) {
			seen[s] = true
			ips = append(ips, s)
		}
	}
	return ips
}

func truncErr(err error) string {
	s := err.Error()
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
