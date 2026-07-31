package server

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// minManagementKeyLen — минимальная длина ключа management API (раунд 18).
// 32 символа ≈ 128+ бит при hex/base64, что делает перебор бессмысленным.
// Проверка жёсткая при не-loopback bind, иначе WARN — см. Start().
const minManagementKeyLen = 32

// Server is the main ShadowLink server with TLS, routing, and lifecycle management.
//
// IMPORTANT: In production, deploy behind a real nginx reverse proxy:
//
//	nginx (TLS + h2 termination, port 443) → Go server (plain HTTP, unix socket)
//
// This is required because Go's net/http sends non-browser HTTP/2 SETTINGS frames.
// A real nginx handles TLS and h2 with genuine nginx fingerprint, making the server
// indistinguishable from any other nginx-hosted site. (Audit F1 fix)
type Server struct {
	config   Config
	handler  *Handler
	httpSrv  *http.Server
	mgmtSrv  *http.Server // Management API server (optional)
	listener net.Listener
	stopCh   chan struct{}

	// connIdle tracks which connections are currently counted as idle in
	// Metrics.IdleConnections. Keyed by net.Conn; value present ⇒ this conn
	// contributed a +1. Used by connStateHook for exact (non-negative)
	// accounting — see its doc-comment.
	connIdle sync.Map // map[net.Conn]struct{}
}

// New creates a ShadowLink server from config.
// serverKey can be provided directly, or loaded from config.ServerKeyFile.
func New(config Config, serverKey *core.KeyPair) (*Server, error) {
	if serverKey == nil {
		var err error
		serverKey, err = loadServerKey(config.ServerKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load server key: %w", err)
		}
	}

	handler := NewHandler(serverKey, config, config.DecoyDir)

	s := &Server{
		config:  config,
		handler: handler,
		stopCh:  make(chan struct{}),
	}

	return s, nil
}

// Start begins listening. If CertFile/KeyFile are set, uses TLS.
// Returns the actual listen address (useful when port is 0).
func (s *Server) Start() (string, error) {
	var err error

	if s.config.CertFile != "" && s.config.KeyFile != "" {
		err = s.startTLS()
	} else {
		err = s.startPlain()
	}
	if err != nil {
		return "", err
	}

	// Start session cleanup
	s.handler.StartCleanup(s.stopCh)

	// Apply DefaultMaxDevices unconditionally (A3-S-MED-4): the device-limit
	// override must be honored regardless of whether the optional management
	// API is enabled, because it shapes the per-user CheckDeviceLimit ceiling
	// at handshake time.
	if s.config.DefaultMaxDevices > 0 {
		s.handler.clientAuth.defaultMax = s.config.DefaultMaxDevices
	}

	// Start Management API (optional — only if port and key are configured)
	if s.config.ManagementPort > 0 && s.config.ManagementKey != "" {
		mgmtHandler := NewManagementHandler(s.handler.clientAuth, s.handler.metrics, s.config.ManagementKey)
		bind := s.config.ManagementBind
		if bind == "" {
			bind = "127.0.0.1"
		}
		// Раунд 18 (MEDIUM): минимальная длина ManagementKey не проверялась
		// вообще. ConstantTimeCompare защищает от timing-атаки, но не от
		// короткого ключа — его просто перебирают. Порог применяется жёстко
		// только когда порт выставлен НЕ на loopback: уронить старт из-за
		// унаследованного короткого ключа на localhost-биндe было бы хуже, чем
		// сам риск, поэтому там — громкий WARN.
		if len(s.config.ManagementKey) < minManagementKeyLen {
			if bind != "127.0.0.1" && bind != "localhost" && bind != "::1" {
				return "", fmt.Errorf(
					"management key too short: %d chars, minimum %d when -mgmt-bind is not loopback (bind=%q)",
					len(s.config.ManagementKey), minManagementKeyLen, bind)
			}
			slog.Warn("management key is shorter than recommended minimum — "+
				"brute-forceable if the port is ever exposed; rotate to a longer random key",
				"len", len(s.config.ManagementKey), "min", minManagementKeyLen, "bind", bind)
		}

		mgmtAddr := fmt.Sprintf("%s:%d", bind, s.config.ManagementPort)
		// Раунд 18 (MEDIUM): раньше здесь стоял голый
		// &http.Server{Addr, Handler} — ни одного таймаута, ни MaxHeaderBytes,
		// тогда как основной сервер их имеет (см. startTLS/startPlain).
		//
		// Ключ management API проверяется в ManagementHandler.ServeHTTP, то есть
		// ПОСЛЕ того, как net/http дочитал заголовки, — без ReadHeaderTimeout это
		// pre-auth slowloris: неаутентифицированный peer пинит горутину, посылая
		// заголовки по байту. Bind по умолчанию loopback, но -mgmt-bind позволяет
		// вывести порт наружу, поэтому «только localhost» не является защитой.
		//
		// Таймауты строже основного сервера намеренно: здесь нет ни WebSocket, ни
		// длинных стримов — только короткие JSON-запросы и scrape метрик.
		s.mgmtSrv = &http.Server{
			Addr:              mgmtAddr,
			Handler:           mgmtHandler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second, // scrape метрик может быть крупным
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 14, // 16 KB — управляющим запросам хватает
		}
		go func() {
			if err := s.mgmtSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("management API error", "error", err)
			}
		}()
		slog.Info("management API started", "addr", mgmtAddr)
	}

	addr := s.listener.Addr().String()
	slog.Info("shadowlink server started", "addr", addr,
		"tls", s.config.CertFile != "",
		"max_clients", s.config.MaxClients,
		"chunk_size", s.config.ChunkSize)

	return addr, nil
}

func (s *Server) startTLS() error {
	cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		return fmt.Errorf("load TLS cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // TLS 1.3 only — prevents downgrade attacks (Audit M8)
	}

	s.httpSrv = &http.Server{
		Handler:           s.handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		// 300s (was 60s) — Wave 2.3 (2026-05-17), raised so idle WS connections
		// survive TSPU mid-session ban transients (typically <60s). Memory cost
		// tracked via Metrics.IdleConnections, populated by the ConnState hook
		// installed below.
		IdleTimeout:    300 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64 KB
		// Disable HTTP/2: Go's h2 sends non-browser SETTINGS frames
		// (INITIAL_WINDOW_SIZE=4194304 vs Chrome's 6291456).
		// DPI matches TLS fingerprint (Chrome) + h2 SETTINGS (Go) = detection.
		// HTTP/1.1 with keepalives is safer.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	s.httpSrv.ConnState = s.connStateHook

	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return err
	}
	s.listener = tls.NewListener(ln, tlsConfig)

	go s.httpSrv.Serve(s.listener)
	return nil
}

func (s *Server) startPlain() error {
	s.httpSrv = &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		// 300s (was 60s) — see startTLS for rationale (Wave 2.3, 2026-05-17).
		IdleTimeout:    300 * time.Second,
		MaxHeaderBytes: 1 << 16,
	}
	s.httpSrv.ConnState = s.connStateHook

	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return err
	}
	s.listener = ln

	go s.httpSrv.Serve(ln)
	return nil
}

// connStateHook tracks the count of idle keep-alive TCP connections held
// by the HTTP server, exposed as Metrics.IdleConnections.
//
// Transitions emitted by net/http: New → Active → Idle → Active → Idle
// → … → Closed (or Hijacked for WS upgrades). The hook receives only the
// new state, not the previous one.
//
// Exact accounting (2026-05-29 fix): we track per-connection idle membership
// in s.connIdle so the gauge counts true transitions only:
//
//	enter Idle (not already counted)        → +1, mark counted
//	leave Idle (Active|Closed|Hijacked)     → -1, only if previously counted
//
// The earlier approximation (Idle→+1, Active|Closed|Hijacked→-1 unconditionally)
// drove the gauge deeply negative: a connection that goes New→Active→Closed
// without ever idling — the common single-handshake-POST case — emitted two -1s
// and no +1. On pl1 this accumulated to IdleConnections=-1178, masking the real
// idle pool size for ops. Tracking membership makes never-idle connections net
// zero and keeps the gauge ≥ 0.
//
// Cost: one sync.Map entry per CURRENTLY-IDLE connection (deleted on leave),
// not one per lifetime connection — bounded by the live idle keep-alive pool.
//
// Wave 2.3 (2026-05-17): introduced alongside IdleTimeout 60s→300s, so
// ops can correlate idle pool size against the wider window's RAM cost.
func (s *Server) connStateHook(conn net.Conn, st http.ConnState) {
	if s.handler == nil || s.handler.metrics == nil {
		return
	}
	switch st {
	case http.StateIdle:
		// Count this conn as idle only on the first transition into Idle.
		if _, loaded := s.connIdle.LoadOrStore(conn, struct{}{}); !loaded {
			s.handler.metrics.IdleConnections.Add(1)
		}
	case http.StateActive, http.StateClosed, http.StateHijacked:
		// Decrement only if this conn was previously counted as idle.
		if _, existed := s.connIdle.LoadAndDelete(conn); existed {
			s.handler.metrics.IdleConnections.Add(-1)
		}
	}
}

// Stop gracefully shuts down the server.
//
// Order of operations (H1 graceful shutdown):
//  1. Stop background workers via stopCh (cleanup loop etc.)
//  2. Shut down the management HTTP server (2s drain).
//  3. Disable HTTP keep-alives so in-flight responses close cleanly and new
//     requests get Connection: close rather than being held open.
//  4. Broadcast FlagFin to every active session's Outgoing channel so clients
//     reconnect immediately — without this, an active WS/SplitHTTP client
//     would sit on its read deadline (up to 60s) during a rolling deploy.
//  5. Drain the main HTTP server with a 30s timeout (enough for the broadcast
//     to flush + in-flight uploads to complete).
func (s *Server) Stop() error {
	close(s.stopCh)

	if s.mgmtSrv != nil {
		mgmtCtx, mgmtCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer mgmtCancel()
		s.mgmtSrv.Shutdown(mgmtCtx)
	}

	slog.Info("shutting down shadowlink server")

	// Disable keep-alives on the main HTTP server — new requests get
	// Connection: close, in-flight responses still complete.
	s.httpSrv.SetKeepAlivesEnabled(false)

	// Broadcast a FlagFin to every live session so clients reconnect on next
	// tick instead of waiting out their read-deadline. Bounded-parallel via
	// errgroup (T1.7, Phase 2): peak goroutines ≤ broadcastCloseConcurrency,
	// total wall-clock < broadcastCloseTotalDeadline. Always logged so ops
	// can confirm the drain happened at all on rolling deploys.
	if s.handler != nil {
		bStart := time.Now()
		enqueued := s.handler.BroadcastStreamClose("server_maintenance")
		slog.Info("graceful shutdown: broadcast complete",
			"enqueued", enqueued,
			"took", time.Since(bStart),
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.httpSrv.Shutdown(ctx)
}

// Addr returns the server's listen address.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Handler returns the underlying handler (for testing).
func (s *Server) Handler() *Handler {
	return s.handler
}

// SetSentinelEmitter attaches a SentinelEmitter to the underlying handler.
// No-op if handler not yet constructed (defensive guard — current New()
// always constructs handler before this can be called, but explicit check
// matches codebase style for nil safety).
//
// Must be called BEFORE Start() — the emitter is read by handler methods
// with no synchronisation beyond the publication point (construction
// happens-before serving begins). nil is safe: rate-limit branches degrade
// to legacy header-only path.
//
// Phase 1 (2026-05-14): called from main.go after LoadDecoySnapshots succeeds.
func (s *Server) SetSentinelEmitter(e *SentinelEmitter) {
	if s.handler == nil {
		return
	}
	s.handler.sentinelEmitter = e
}

// Metrics returns the server's metrics tracker (delegate to handler).
func (s *Server) Metrics() *Metrics {
	return s.handler.Metrics()
}

// SessionCount returns the number of active sessions.
func (s *Server) SessionCount() int {
	return s.handler.SessionCount()
}

// loadServerKey loads a 32-byte X25519 private key from file (hex encoded).
func loadServerKey(path string) (*core.KeyPair, error) {
	if path == "" {
		// Generate ephemeral key for testing
		slog.Warn("no server key file specified, generating ephemeral key")
		return core.GenerateKeyPair()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try hex decode (64 hex chars = 32 bytes)
	keyBytes, err := hex.DecodeString(string(trimBytes(data)))
	if err != nil || len(keyBytes) != 32 {
		return nil, fmt.Errorf("server key must be 64 hex characters (32 bytes), got %d bytes", len(keyBytes))
	}

	return core.KeyPairFromPrivate(keyBytes)
}

func trimBytes(b []byte) []byte {
	// Trim whitespace, newlines
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}
