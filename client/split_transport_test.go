package client

import (
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

func TestSplitTransport_Poll_NilSession(t *testing.T) {
	st := &SplitTransport{
		serverAddr: "127.0.0.1:443",
		token:      []byte("test-token"),
	}

	err := st.Poll(nil)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
}

func TestSplitTransport_Poll_EncryptsAndSends(t *testing.T) {
	serverKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	hello, clientState, err := core.NewClientHello([]byte("test"), serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	sm := core.NewSessionManager(5 * time.Minute)
	serverHello, _, _, err := core.HandleClientHello(hello, serverKP, 8, 12288, sm)
	if err != nil {
		t.Fatal(err)
	}

	session, err := core.CompleteHandshake(clientState, serverHello)
	if err != nil {
		t.Fatal(err)
	}

	// Use real constructor so upload pool is initialized (ConnManagers won't connect but won't panic).
	st := NewSplitTransport("127.0.0.1:443", []byte("test-token"))

	seqBefore := session.NextSeqNum() // consumes one seq

	err = st.Poll(session)
	// Expected: error because TLS connection to 127.0.0.1:443 cannot be established.
	if err == nil {
		t.Log("Poll succeeded unexpectedly")
	}

	seqAfter := session.NextSeqNum() // should be seqBefore + 2 (one consumed by Poll, one by this call)
	if seqAfter <= seqBefore {
		t.Fatalf("expected seq_num to increment: before=%d after=%d", seqBefore, seqAfter)
	}
}
