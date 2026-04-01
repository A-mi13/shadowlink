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
	"time"

	"github.com/nixavpn/shadowlink/core"
)

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
	config      Config
	handler     *Handler
	httpSrv     *http.Server
	mgmtSrv     *http.Server // Management API server (optional)
	udpListener *UDPListener // Phase 2: TURN-relayed UDP traffic
	listener    net.Listener
	stopCh      chan struct{}
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

	// Start UDP listener for TURN relay (Phase 2)
	if s.config.EnableUDP {
		udpAddr := s.config.UDPListenAddr
		if udpAddr == "" {
			udpAddr = ":56000"
		}
		s.udpListener = NewUDPListener(s.handler, s.config)
		udpActual, err := s.udpListener.Start(udpAddr)
		if err != nil {
			return "", fmt.Errorf("start UDP listener: %w", err)
		}
		slog.Info("UDP listener ready", "addr", udpActual)
	}

	// Start Management API (optional — only if port and key are configured)
	if s.config.ManagementPort > 0 && s.config.ManagementKey != "" {
		mgmtHandler := NewManagementHandler(s.handler.clientAuth, s.config.ManagementKey)
		if s.config.DefaultMaxDevices > 0 {
			s.handler.clientAuth.defaultMax = s.config.DefaultMaxDevices
		}
		bind := s.config.ManagementBind
		if bind == "" {
			bind = "127.0.0.1"
		}
		mgmtAddr := fmt.Sprintf("%s:%d", bind, s.config.ManagementPort)
		s.mgmtSrv = &http.Server{Addr: mgmtAddr, Handler: mgmtHandler}
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
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KB
		// Disable HTTP/2: Go's h2 sends non-browser SETTINGS frames
		// (INITIAL_WINDOW_SIZE=4194304 vs Chrome's 6291456).
		// DPI matches TLS fingerprint (Chrome) + h2 SETTINGS (Go) = detection.
		// HTTP/1.1 with keepalives is safer.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

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
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return err
	}
	s.listener = ln

	go s.httpSrv.Serve(ln)
	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	close(s.stopCh)

	if s.udpListener != nil {
		s.udpListener.Stop()
	}

	if s.mgmtSrv != nil {
		mgmtCtx, mgmtCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer mgmtCancel()
		s.mgmtSrv.Shutdown(mgmtCtx)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	slog.Info("shutting down shadowlink server")
	return s.httpSrv.Shutdown(ctx)
}

// Addr returns the server's listen address.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// UDPAddr returns the UDP listener address (empty if not enabled).
func (s *Server) UDPAddr() string {
	if s.udpListener == nil || s.udpListener.conn == nil {
		return ""
	}
	return s.udpListener.conn.LocalAddr().String()
}

// Handler returns the underlying handler (for testing).
func (s *Server) Handler() *Handler {
	return s.handler
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
