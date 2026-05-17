package testutil

import (
	"log/slog"
	"math"
	"net"
	"sync"
	"sync/atomic"
)

// DPIEmulator is a TCP proxy that emulates TSPU behavior for testing.
// Sits between client and server, applying configurable blocking rules.
type DPIEmulator struct {
	listenAddr string
	targetAddr string
	listener   net.Listener

	// ByteLimit: freeze connection after this many bytes from server to client.
	// 0 = no limit. Set to 16384 to emulate TSPU 16KB threshold.
	ByteLimit int64

	// Stats
	TotalConns     atomic.Int64
	TotalBytesUp   atomic.Int64
	TotalBytesDown atomic.Int64
	FrozenConns    atomic.Int64

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewDPIEmulator creates a DPI emulator proxying from listenAddr to targetAddr.
func NewDPIEmulator(listenAddr, targetAddr string) *DPIEmulator {
	return &DPIEmulator{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		stopCh:     make(chan struct{}),
	}
}

// Start begins listening and proxying connections.
// Returns the actual listen address.
func (d *DPIEmulator) Start() (string, error) {
	ln, err := net.Listen("tcp", d.listenAddr)
	if err != nil {
		return "", err
	}
	d.listener = ln

	d.wg.Add(1)
	go d.acceptLoop()

	return ln.Addr().String(), nil
}

// Stop shuts down the emulator.
func (d *DPIEmulator) Stop() {
	close(d.stopCh)
	if d.listener != nil {
		d.listener.Close()
	}
	d.wg.Wait()
}

func (d *DPIEmulator) acceptLoop() {
	defer d.wg.Done()
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-d.stopCh:
				return
			default:
				continue
			}
		}
		d.TotalConns.Add(1)
		d.wg.Add(1)
		go d.handleConn(conn)
	}
}

func (d *DPIEmulator) handleConn(clientConn net.Conn) {
	defer d.wg.Done()
	defer clientConn.Close()

	serverConn, err := net.Dial("tcp", d.targetAddr)
	if err != nil {
		slog.Debug("DPI emulator: can't connect to target", "error", err)
		return
	}
	defer serverConn.Close()

	var wg sync.WaitGroup

	// Client → Server (upload, no byte limit)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				d.TotalBytesUp.Add(int64(n))
				serverConn.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Server → Client (download, with byte limit)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var totalDown int64
		buf := make([]byte, 32768)
		for {
			n, err := serverConn.Read(buf)
			if n > 0 {
				d.TotalBytesDown.Add(int64(n))
				totalDown += int64(n)

				// Check byte limit (emulate TSPU freeze)
				if d.ByteLimit > 0 && totalDown > d.ByteLimit {
					d.FrozenConns.Add(1)
					slog.Debug("DPI emulator: freezing connection",
						"bytes_sent", totalDown, "limit", d.ByteLimit)
					// Freeze: stop relaying without sending RST
					// Just stop reading from server — connection appears frozen to client
					return
				}

				clientConn.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for either direction to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-d.stopCh:
	}
}

// TrafficCapture records traffic passing through the emulator for analysis.
type TrafficCapture struct {
	mu       sync.Mutex
	Requests []CapturedPacket
}

// CapturedPacket holds metadata about one packet.
type CapturedPacket struct {
	Direction string // "up" or "down"
	Size      int
}

// AnalyzeEntropy calculates the Shannon entropy of data (bits per byte).
// Real HTTP traffic ~4-5 bits/byte, base64 ~6 bits/byte, random ~8 bits/byte.
func AnalyzeEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}

	n := float64(len(data))
	var entropy float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// AnalyzeSizeDistribution returns stats about packet sizes.
type SizeStats struct {
	Min   int
	Max   int
	Mean  float64
	Count int
}

// ComputeSizeStats analyzes a slice of packet sizes.
func ComputeSizeStats(sizes []int) SizeStats {
	if len(sizes) == 0 {
		return SizeStats{}
	}

	stats := SizeStats{
		Min:   sizes[0],
		Max:   sizes[0],
		Count: len(sizes),
	}

	total := 0
	for _, s := range sizes {
		total += s
		if s < stats.Min {
			stats.Min = s
		}
		if s > stats.Max {
			stats.Max = s
		}
	}
	stats.Mean = float64(total) / float64(len(sizes))
	return stats
}
