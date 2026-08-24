package socks5

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// PerStreamWSConfig configures per-stream WebSocket mode (1 WS = 1 TCP stream).
// Used for CDN mode where multiplexing many streams over one WS causes data stalls.
// Each SOCKS5 CONNECT creates a new WS connection, like VLESS+WS.
type PerStreamWSConfig struct {
	ServerAddr string
	UseTLS     bool
	SkipVerify bool
	LockedFP   *browser.Fingerprint
	SNIHost    string // override TLS ServerName (for origin IP with domain SNI)
	CFIP       string // specific CF edge IP

	// Pool, when non-nil, is a pre-warmed WSReadyPool that HandleTCPConnectWSPerStream
	// draws from instead of creating a fresh WS (and paying the ~250ms TCP+TLS+WS
	// upgrade cost) for every SOCKS5 CONNECT. The pool itself handles replenishment
	// and keepalives; the handler just Acquires → uses → Closes.
	Pool *client.WSReadyPool

	// dispatcher is the lazily-initialized coalescing dispatcher in front of Pool.
	// Shared across all SOCKS5 CONNECTs so concurrent demand within the 50ms
	// window is batched against the same pool — without sharing, each CONNECT
	// would build its own single-request dispatcher and just add latency.
	// Initialized via dispatcherOnce on first acquire.
	dispatcher     PoolAcquirer
	dispatcherOnce sync.Once
}

// AcquireWS pulls a WS from the configured pool, optionally coalescing
// concurrent acquires via CoalescingDispatcher (default ON, opt-out via
// SHADOWLINK_SOCKS5_COALESCE=0|false|no|off). Returns a usable transport
// or an error. Callers MUST Close() the returned transport when done.
func (cfg *PerStreamWSConfig) AcquireWS(ctx context.Context) (*client.WebSocketTransport, error) {
	cfg.dispatcherOnce.Do(func() {
		var base PoolAcquirer = wsReadyPoolAdapter{pool: cfg.Pool}
		if socks5CoalesceEnabled() {
			cfg.dispatcher = NewCoalescingDispatcher(base, coalesceWindow, coalesceMaxParallel)
		} else {
			cfg.dispatcher = base
		}
	})
	acquired, err := cfg.dispatcher.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	wst, ok := acquired.(*client.WebSocketTransport)
	if !ok || wst == nil {
		return nil, errInvalidAcquireType
	}
	return wst, nil
}

var errInvalidAcquireType = errors.New("socks5: pool dispatcher returned unexpected type")

// Server is a SOCKS5 proxy that tunnels traffic through a ShadowLink client.
// If WST is non-nil, WebSocket (full-duplex) mode is used; otherwise poll mode.
// If PerStreamWS is non-nil, each SOCKS5 CONNECT gets a dedicated WS (CDN mode).
type Server struct {
	Client      *client.Client
	PerStreamWS *PerStreamWSConfig // nil = use WST; non-nil = per-stream WS (CDN mode)
	Router      *client.Router
	Addr        string // "127.0.0.1:1080"
	Username    string // если задан — требуется RFC 1929 auth
	Password    string
	ViaCDN      bool // true when traffic goes through CF CDN (shorter CONNECT timeout)
	listener    net.Listener
	mu          sync.Mutex

	// wst — активный stream-транспорт; nil = poll-mode.
	//
	// Поле СПЕЦИАЛЬНО приватное. Оно переприсваивается на лету при реконнекте
	// одиночного WS (engine.streamReaderLoop), а читается из совсем другой
	// горутины — на КАЖДЫЙ SOCKS5 CONNECT (handleConn) и на каждый dial
	// in-process диалера (inprocess.go). Пока поле было публичным, эта запись
	// была настоящей гонкой данных МЕЖДУ ПАКЕТАМИ, и мьютекс в engine/ её бы не
	// закрыл: читатели живут здесь. Поэтому синхронизация обязана стоять у
	// владельца поля — отсюда WST()/SetWST() под тем же mu, что и listener.
	//
	// Альтернатива «WSTProvider func() client.StreamTransport» отвергнута: она
	// размножает nil-семантику на два измерения (nil-функция и nil-результат),
	// и пропуск любой из проверок даёт панику на data-path основного режима.
	wst client.StreamTransport

	// connectSem limits concurrent pending CONNECT requests over WebSocket.
	// Without this, system VPN opens 80+ connections in seconds,
	// overwhelming the single WS through Cloudflare CDN → CF kills the connection.
	connectSem chan struct{}
}

// ConnectTimeout returns the CONNECT timeout based on transport mode.
// CDN: 10s — CF adds 100-200ms RTT but under burst (system VPN, 50+ CONNECTs)
// the server queues CONNECT dials and CONNECT_OK arrives in 3-8s.
// Direct origin: 10s — low RTT, plenty of headroom.
func (s *Server) ConnectTimeout() time.Duration {
	return 10 * time.Second
}

// maxConcurrentConnects limits concurrent pending WS CONNECT requests.
// With optimistic CONNECT (no round-trip wait), semaphore is a safety cap.
// Reduced from 64 to 32 to limit WS buffer pressure through CF CDN.
const maxConcurrentConnects = 32

// ListenAndServe starts the SOCKS5 listener and accepts connections until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.connectSem = make(chan struct{}, maxConcurrentConnects)
	s.mu.Unlock()

	slog.Info("SOCKS5 proxy listening", "addr", ln.Addr().String())

	var wg sync.WaitGroup

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check if context cancelled (normal shutdown).
			select {
			case <-ctx.Done():
				wg.Wait()
				return ctx.Err()
			default:
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// Close shuts down the listener.
func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

// Addr returns the actual listen address (useful when binding to :0).
func (s *Server) ListenAddr() net.Addr {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln != nil {
		return ln.Addr()
	}
	return nil
}

// WST возвращает активный stream-транспорт (nil = poll-mode).
//
// Читается на горячем пути (каждый CONNECT), поэтому под тем же mu, что и
// listener: захват короткий, сетевых операций под локом нет.
func (s *Server) WST() client.StreamTransport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wst
}

// SetWST переставляет активный stream-транспорт. Зовётся при реконнекте
// одиночного WS из горутины streamReaderLoop, то есть параллельно с читателями.
func (s *Server) SetWST(t client.StreamTransport) {
	s.mu.Lock()
	s.wst = t
	s.mu.Unlock()
}

// AcquireConnect acquires a slot for a pending WS CONNECT.
// Returns true if acquired, false if timed out.
func (s *Server) AcquireConnect(timeout time.Duration) bool {
	if s.connectSem == nil {
		return true
	}
	select {
	case s.connectSem <- struct{}{}:
		return true
	case <-time.After(timeout):
		return false
	}
}

// ReleaseConnect releases a pending WS CONNECT slot.
func (s *Server) ReleaseConnect() {
	if s.connectSem == nil {
		return
	}
	select {
	case <-s.connectSem:
	default:
	}
}

// handleConn performs SOCKS5 handshake and dispatches to the appropriate handler.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 513)

	// SOCKS5 greeting: version(1) + nmethods(1) + methods(n)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	if s.Username != "" {
		// Требуем USERNAME/PASSWORD auth (RFC 1929, method 0x02)
		conn.Write([]byte{0x05, 0x02})

		// Читаем auth request: ver(1) + ulen(1) + user(ulen) + plen(1) + pass(plen)
		n, err = conn.Read(buf)
		if err != nil || n < 3 || buf[0] != 0x01 {
			conn.Write([]byte{0x01, 0x01}) // auth failed
			return
		}
		ulen := int(buf[1])
		if n < 2+ulen+1 {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		user := string(buf[2 : 2+ulen])
		plen := int(buf[2+ulen])
		if n < 2+ulen+1+plen {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		pass := string(buf[2+ulen+1 : 2+ulen+1+plen])

		if user != s.Username || pass != s.Password {
			conn.Write([]byte{0x01, 0x01}) // auth failed
			return
		}
		conn.Write([]byte{0x01, 0x00}) // auth success
	} else {
		// No auth
		conn.Write([]byte{0x05, 0x00})
	}

	// MED-7 fix: use ReadAtLeast to handle TCP fragmentation.
	// SOCKS5 request minimum: ver(1) + cmd(1) + rsv(1) + atyp(1) + addr(1+) + port(2) = 7 bytes
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = io.ReadAtLeast(conn, buf, 7)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n < 7 {
		return
	}

	// Снимок транспорта делается ОДИН раз на соединение: раньше здесь стояли два
	// чтения поля (проверка на nil и передача в хендлер), и между ними реконнект
	// мог переставить транспорт — тогда проверенный на nil и переданный были
	// разными объектами.
	wst := s.WST()

	switch buf[1] {
	case CmdConnect:
		destAddr := ParseDestAddr(buf, n)
		if destAddr == "" {
			conn.Write(ReplyAddrNotSupported)
			return
		}
		if s.PerStreamWS != nil {
			HandleTCPConnectWSPerStream(ctx, conn, s.Client, s.Router, destAddr, s.PerStreamWS)
		} else if wst != nil {
			HandleTCPConnectWS(ctx, conn, s.Client, wst, s.Router, destAddr, s)
		} else {
			HandleTCPConnect(ctx, conn, s.Client, s.Router, destAddr)
		}
	case CmdUDPAssociate:
		if wst != nil {
			HandleUDPAssociateWS(ctx, conn, s.Client, wst, s.Router)
		} else {
			HandleUDPAssociate(ctx, conn, s.Client, s.Router)
		}
	default:
		conn.Write(ReplyCmdNotSupported)
	}
}
