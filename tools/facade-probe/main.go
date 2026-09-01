// facade-probe brings up the mobile facade exactly the way a platform VPN
// extension does — mobile.NewConfig → NewSession → SetEventHandler → Start —
// and holds its SOCKS5 listener open so you can push real traffic through it.
//
// Why this exists (requested in the 2026-08-31 integration review): when a field
// build stops working, the first question is always "is the key stale or is the
// client broken", and answering it previously meant building the whole native
// app. This binary answers it in about a minute, on a desktop, with curl.
//
// It probes the SAME code path as the shipped facade, which matters more than it
// sounds: the facade hardwires WSPool: true (mobile/config.go), so the pooled
// transport — where per-slot crypto sessions live and where the 2026-08-31 UDP
// defect hid — is what actually gets exercised. The unit tests cannot do this:
// mobile.Session has a newEngine seam that they replace with a fake, so nothing
// in `go test ./mobile/` ever starts a real engine.
//
// Usage:
//
//	facade-probe -url 'sl://PUBKEY@domain:443?tls=1&sni=domain&origin=IP'
//	facade-probe -server 1.2.3.4:443 -pubkey <64 hex> -sni example.com
//
// Then, in another shell (the probe prints the exact lines):
//
//	curl -sS --socks5-hostname user:pass@127.0.0.1:PORT https://api.ipify.org
//	curl -sS --socks5-hostname user:pass@127.0.0.1:PORT --http3 https://cloudflare.com  # UDP path
//
// Flags of note:
//
//	-check      run a built-in TCP reachability check through the tunnel and exit
//	            with a non-zero status on failure
//
// Note on -check in CI: it fetches an external URL (api.ipify.org), so a failure
// means "the tunnel did not carry a request" OR "that host was unreachable".
// That is the right trade for a human smoke gate, and the wrong one for a
// blocking CI job — an ipify outage would redden the build with no defect
// present. Use it as a manual or non-blocking check.
//	-check-udp  resolve several names over ONE UDP ASSOCIATE, each from a
//	            different local source port, and exit non-zero on failure.
//	            Distinct ports are the point: a single-socket probe cannot
//	            observe reply-misrouting, which is how the 2026-09-01 defect
//	            (8/8 by hand, 33% via sing-box) survived acceptance.
//	-resolver   resolver for -check-udp (IPv4 literal, default 1.1.1.1:53)
//	-hold       how long to stay up in interactive mode (default 10m)
//	-log        facade log level: quiet|info|debug|trace
//
// It never writes the key anywhere and never reads a config file: pass the
// sl:// URL on the command line or via SL_URL to keep it out of shell history.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/mobile"
)

// probeTarget is the URL the -check mode fetches through the tunnel. Chosen for
// being tiny, stable and plain-text so a failure is unambiguous.
const probeTarget = "https://api.ipify.org"

// checkTimeout bounds the whole -check run: pool warm-up plus one request. The
// pool reports ready as soon as the first slot is up, but a cold start on a
// long-RTT link can take a few seconds.
const checkTimeout = 45 * time.Second

type events struct {
	states chan string
}

func (e *events) OnStateChange(state string) {
	fmt.Printf("[facade] state → %s\n", state)
	select {
	case e.states <- state:
	default:
	}
}

func (e *events) OnError(msg string) {
	fmt.Printf("[facade] error: %s\n", msg)
}

func main() {
	url := flag.String("url", os.Getenv("SL_URL"), "sl:// URL (or set SL_URL)")
	server := flag.String("server", "", "server host:port (ignored when -url is set)")
	pubkey := flag.String("pubkey", "", "server X25519 public key, 64 hex chars")
	sni := flag.String("sni", "", "TLS SNI to present when dialing an IP")
	cdn := flag.String("cdn", "", "CDN domain (compat field; prod is direct to origin)")
	clientID := flag.String("client-id", "", "client ID, 32 hex chars (empty = random per start)")
	poolSize := flag.Int("pool", 0, "WS pool slots (0 = engine default)")
	noTLS := flag.Bool("no-tls", false, "disable TLS (lab stands only)")
	logLevel := flag.String("log", "info", "facade log level: quiet|info|debug|trace")
	hold := flag.Duration("hold", 10*time.Minute, "how long to stay up in interactive mode")
	check := flag.Bool("check", false, "run a reachability check through the tunnel and exit")
	checkUDP := flag.Bool("check-udp", false, "resolve several names over one UDP ASSOCIATE from DISTINCT source ports, then exit")
	resolver := flag.String("resolver", "1.1.1.1:53", "resolver used by -check-udp (IPv4 literal)")
	flag.Parse()

	cfg := mobile.NewConfig()

	if strings.TrimSpace(*url) != "" {
		fc, err := client.ParseSLURL(strings.TrimSpace(*url))
		if err != nil {
			fatalf("parse -url: %v", err)
		}
		// The facade wants the address it should actually dial. In full-direct
		// mode that is the origin IP, with the domain carried separately as SNI.
		addr := fc.Server
		if fc.Origin != "" {
			_, port, splitErr := net.SplitHostPort(fc.Server)
			if splitErr != nil {
				port = "443"
			}
			addr = net.JoinHostPort(fc.Origin, port)
		}
		cfg.ServerAddr = addr
		cfg.PubKeyHex = fc.PubKey
		cfg.UseTLS = fc.TLS
		cfg.CDN = fc.CDN
		cfg.SNI = fc.SNI
		if cfg.SNI == "" && fc.Origin != "" {
			// Dialing an IP with no SNI would present the IP as ServerName and
			// nginx would not match a server_name block.
			if host, _, err := net.SplitHostPort(fc.Server); err == nil {
				cfg.SNI = host
			}
		}
		if fc.ClientID != "" {
			cfg.ClientIDHex = fc.ClientID
		}
	} else {
		if *server == "" || *pubkey == "" {
			fatalf("need -url, or both -server and -pubkey (see -h)")
		}
		cfg.ServerAddr = *server
		cfg.PubKeyHex = *pubkey
		cfg.UseTLS = !*noTLS
		cfg.SNI = *sni
		cfg.CDN = *cdn
	}

	// Explicit flags win over anything parsed from the URL.
	if *clientID != "" {
		cfg.ClientIDHex = *clientID
	}
	if *noTLS {
		cfg.UseTLS = false
	}
	if *sni != "" {
		cfg.SNI = *sni
	}
	if *poolSize > 0 {
		cfg.WSPoolSize = int32(*poolSize)
	}

	mobile.SetLogLevel(*logLevel)

	sess, err := mobile.NewSession(cfg)
	if err != nil {
		// Config validation lives in the facade, so a bad key or ID is reported
		// here rather than as an obscure handshake failure later.
		fatalf("NewSession: %v", err)
	}

	ev := &events{states: make(chan string, 8)}
	sess.SetEventHandler(ev)

	fmt.Printf("[probe] server=%s tls=%v sni=%q pool=%d\n",
		cfg.ServerAddr, cfg.UseTLS, cfg.SNI, cfg.WSPoolSize)

	if err := sess.Start(); err != nil {
		fatalf("Start: %v", err)
	}
	defer func() {
		if err := sess.Stop(); err != nil {
			fmt.Printf("[probe] Stop: %v\n", err)
		}
	}()

	port := sess.SocksPort()
	if port == 0 {
		fatalf("facade reported SOCKS port 0 — the listener never came up")
	}
	proxy := fmt.Sprintf("127.0.0.1:%d", port)
	user, pass := sess.SocksUser(), sess.SocksPass()

	fmt.Printf("\n[probe] SOCKS5 ready on %s (state=%s)\n", proxy, sess.State())
	fmt.Printf("[probe] curl -sS --socks5-hostname %s:%s@%s %s\n", user, pass, proxy, probeTarget)
	fmt.Printf("[probe] curl -sS --socks5-hostname %s:%s@%s --http3 https://cloudflare.com   # exercises UDP\n\n",
		user, pass, proxy)

	if *check || *checkUDP {
		failed := false
		if *check {
			if err := runCheck(proxy, user, pass); err != nil {
				fmt.Printf("[probe] FAIL: %v\n", err)
				failed = true
			} else {
				fmt.Println("[probe] OK — tunnel carried a request end to end")
			}
		}
		if *checkUDP {
			if err := runUDPCheck(proxy, user, pass, *resolver); err != nil {
				fmt.Printf("[probe] FAIL (udp): %v\n", err)
				failed = true
			}
		}
		if failed {
			os.Exit(1)
		}
		return
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	fmt.Printf("[probe] holding for %s — Ctrl-C to stop\n", *hold)
	select {
	case <-stop:
		fmt.Println("\n[probe] interrupted")
	case <-time.After(*hold):
		fmt.Println("[probe] hold elapsed")
	}
}

// runCheck fetches probeTarget through the facade's SOCKS5 listener. A failure
// here separates "the tunnel is down" from "the app is misconfigured": the
// request never touches the host's default route.
func runCheck(proxy, user, pass string) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		// SOCKS5 with auth, dialed per request. No proxy env vars are consulted,
		// so a hostile HTTPS_PROXY in the environment cannot silently take over
		// and make a broken tunnel look healthy.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socks5Dial(ctx, dialer, proxy, user, pass, addr)
		},
		DisableKeepAlives: true,
	}
	httpClient := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeTarget, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request through tunnel: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	fmt.Printf("[probe] exit IP as seen by %s: %s\n", probeTarget, strings.TrimSpace(string(body)))
	return nil
}

// socks5Dial performs a minimal SOCKS5 CONNECT with username/password auth.
// Written out rather than pulled from x/net/proxy so the probe adds no
// dependency to go.mod for a 40-line handshake.
func socks5Dial(ctx context.Context, d *net.Dialer, proxyAddr, user, pass, target string) (net.Conn, error) {
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	if dl, has := ctx.Deadline(); has {
		conn.SetDeadline(dl)
	}

	// Greeting: offer username/password (0x02).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return nil, err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 0x05 || reply[1] != 0x02 {
		return nil, fmt.Errorf("proxy refused user/pass auth: %v", reply)
	}

	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := conn.Write(auth); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, err
	}
	if reply[1] != 0x00 {
		return nil, fmt.Errorf("proxy auth failed")
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil, fmt.Errorf("bad port %q", portStr)
	}

	// CONNECT with the hostname, so DNS resolves on the far side of the tunnel
	// (--socks5-hostname semantics) and a local resolver cannot mask a failure.
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, err
	}
	if head[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 CONNECT failed, REP=0x%02x", head[1])
	}
	// Consume BND.ADDR/BND.PORT so the stream starts at application bytes.
	switch head[3] {
	case 0x01:
		var skip [4 + 2]byte
		_, err = io.ReadFull(conn, skip[:])
	case 0x03:
		var l [1]byte
		if _, err = io.ReadFull(conn, l[:]); err == nil {
			skip := make([]byte, int(l[0])+2)
			_, err = io.ReadFull(conn, skip)
		}
	case 0x04:
		var skip [16 + 2]byte
		_, err = io.ReadFull(conn, skip[:])
	default:
		err = fmt.Errorf("unknown ATYP 0x%02x", head[3])
	}
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "facade-probe: "+format+"\n", args...)
	os.Exit(1)
}
