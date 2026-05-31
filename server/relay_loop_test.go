package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// fakeWSConnWriter is a test double for core.WSConnWriter (the minimal subset
// of *gorilla/websocket.Conn the WSAsyncWriter needs). It captures every frame
// passed to WriteMessage onto a buffered channel so the test can assert on the
// exact bytes the relay-loop enqueued. This keeps the production binding.writer
// type as *core.WSAsyncWriter — the seam lives entirely below it.
type fakeWSConnWriter struct {
	frames chan []byte
}

func newFakeWSConnWriter() *fakeWSConnWriter {
	return &fakeWSConnWriter{frames: make(chan []byte, 64)}
}

func (f *fakeWSConnWriter) WriteMessage(_ int, data []byte) error {
	cp := append([]byte(nil), data...)
	f.frames <- cp
	return nil
}

func (f *fakeWSConnWriter) SetWriteDeadline(_ time.Time) error { return nil }

// testWriterSink wraps a real *core.WSAsyncWriter driven by a fakeWSConnWriter.
// asWriter returns the production-typed writer for binding.writer; waitFrame
// pulls the next captured (encrypted) frame.
type testWriterSink struct {
	sink   *fakeWSConnWriter
	writer *core.WSAsyncWriter
	once   sync.Once
}

func newTestWriterSink() *testWriterSink {
	sink := newFakeWSConnWriter()
	w := core.NewWSAsyncWriter(sink, 64)
	go func() { _ = w.Run() }()
	return &testWriterSink{sink: sink, writer: w}
}

func (s *testWriterSink) asWriter() *core.WSAsyncWriter { return s.writer }

func (s *testWriterSink) waitFrame(t *testing.T, d time.Duration) []byte {
	t.Helper()
	select {
	case f := <-s.sink.frames:
		return f
	case <-time.After(d):
		t.Fatalf("no frame captured within %s", d)
		return nil
	}
}

func (s *testWriterSink) close() {
	s.once.Do(func() { s.writer.Close() })
}

// newSelfSession returns a session whose send and recv keys are identical, so
// the same session both EncryptChunk's and DecryptChunkSafe's its own frames
// (the nonce is carried on the wire, so no decrypt-side counter is needed).
func newSelfSession(t *testing.T) *core.Session {
	t.Helper()
	sm := core.NewSessionManager(5 * time.Minute)
	key := make([]byte, 32)
	key[0] = 0x5A
	key[7] = 0xC3
	sess, err := sm.Create(key, key)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess
}

// TestRelayLoop_SwitchBindingReencryptsUnderNewSession is the core F4 contract:
// relayLoop reads e.bound dynamically and encrypts each downlink frame under the
// CURRENTLY bound session, assigning a per-stream monotonic downSeq. Here the
// entry is bound to session B before the loop starts; the captured frame must
// decrypt under B and carry downSeq==1 in the seq-format payload.
func TestRelayLoop_SwitchBindingReencryptsUnderNewSession(t *testing.T) {
	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	sessB := newSelfSession(t)

	e := &relayEntry{
		globalStreamID: 7,
		tc:             egress,
		downBuffer:     newBoundedBuffer(1 << 20),
		unackedTail:    newBoundedBuffer(1 << 20),
		credit:         newStreamCredit(1 << 20),
	}
	e.state.Store(stActive)

	sink := newTestWriterSink()
	defer sink.close()
	e.bound.Store(&binding{session: sessB, writer: sink.asWriter()})

	closeCh := make(chan struct{})
	defer close(closeCh)
	go e.relayLoop(true /*migrateEnabled*/, closeCh)

	if _, err := srvSide.Write([]byte("DATA-B")); err != nil {
		t.Fatalf("write to egress pipe: %v", err)
	}

	frame := sink.waitFrame(t, time.Second)
	chunk, err := sessB.DecryptChunkSafe(frame)
	if err != nil {
		t.Fatalf("frame did not decrypt under session B: %v", err)
	}
	streamID, seq, data, perr := core.ParseStreamDataSeq(chunk.Payload)
	if perr != nil {
		t.Fatalf("parse seq payload: %v", perr)
	}
	if streamID != 7 {
		t.Fatalf("streamID=%d, want 7", streamID)
	}
	if seq != 1 {
		t.Fatalf("downSeq=%d, want 1 (first frame)", seq)
	}
	if string(data) != "DATA-B" {
		t.Fatalf("data=%q, want %q", data, "DATA-B")
	}
}
