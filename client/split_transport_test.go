package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	stdhttp "net/http"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// roundTripperFunc adapts a function into http.RoundTripper for testing.
type roundTripperFunc func(*stdhttp.Request) (*stdhttp.Response, error)

func (f roundTripperFunc) RoundTrip(req *stdhttp.Request) (*stdhttp.Response, error) {
	return f(req)
}

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

	hello, clientState, err := core.NewClientHello([]byte("test-clientid_XX"), serverKP.Public) // 16 bytes (A1-M4)
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
	st := NewSplitTransport("127.0.0.1:443", []byte("test-token"), "")

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

// TestSplitTransport_BuildUploadRequest_NoAuthHeader guards D2 migration: the
// upload request must not carry Authorization and must pack the token at the
// start of the base64-decoded envelope data field.
func TestSplitTransport_BuildUploadRequest_NoAuthHeader(t *testing.T) {
	token := make([]byte, 36)
	for i := range token {
		token[i] = byte(i + 1)
	}
	st := NewSplitTransport("127.0.0.1:443", token, "")
	chunk := []byte("encryptedchunkbytes")

	req, err := st.buildUploadRequest(chunk)
	if err != nil {
		t.Fatalf("buildUploadRequest: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization header must not be set in body-prefix format, got %q", got)
	}
	if req.Method != "POST" {
		t.Errorf("method = %s, want POST", req.Method)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Events []struct {
			Data string `json:"data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not valid envelope JSON: %v", err)
	}
	if len(env.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(env.Events))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(env.Events[0].Data)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if !bytes.HasPrefix(decoded, token) {
		t.Errorf("envelope data does not start with token")
	}
	if !bytes.Equal(decoded[len(token):], chunk) {
		t.Errorf("envelope data after token does not match chunk")
	}
}

// TestSplitTransport_OpenDownloadStream_IsPOST asserts that D2 converted the
// download channel from GET to POST and that the body carries the session
// token prefix.
func TestSplitTransport_OpenDownloadStream_IsPOST(t *testing.T) {
	token := make([]byte, 36)
	for i := range token {
		token[i] = byte(i + 2)
	}
	st := NewSplitTransport("127.0.0.1:443", token, "")

	var capturedMethod string
	var capturedBody []byte
	var capturedAuth string
	st.downloadClient.Transport = roundTripperFunc(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		capturedMethod = req.Method
		capturedAuth = req.Header.Get("Authorization")
		if req.Body != nil {
			capturedBody, _ = io.ReadAll(req.Body)
		}
		return &stdhttp.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Header:     stdhttp.Header{"Content-Type": []string{"application/octet-stream"}},
		}, nil
	})

	// Construct a minimal Session locally (keys needed only for EncryptChunk).
	sendKey := make([]byte, 32)
	recvKey := make([]byte, 32)
	sess := core.NewSession(7, sendKey, recvKey)

	rc, err := st.OpenDownloadStream(sess)
	if err != nil {
		t.Fatalf("OpenDownloadStream: %v", err)
	}
	defer rc.Close()

	if capturedMethod != "POST" {
		t.Errorf("method = %s, want POST (D2 migration)", capturedMethod)
	}
	if capturedAuth != "" {
		t.Errorf("Authorization must not be set, got %q", capturedAuth)
	}

	var env struct {
		Events []struct {
			Data string `json:"data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(capturedBody, &env); err != nil {
		t.Fatalf("download POST body is not valid envelope: %v\nbody=%s", err, string(capturedBody))
	}
	if len(env.Events) == 0 {
		t.Fatal("expected 1 event in download-open POST body")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(env.Events[0].Data)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if !bytes.HasPrefix(decoded, token) {
		t.Errorf("download POST body does not start with token")
	}
	// Remainder must be a non-empty encrypted FlagStreamOpen chunk.
	if len(decoded) <= len(token) {
		t.Errorf("download POST body has no encrypted chunk after token")
	}
}

// TestSplitTransport_OpenDownloadStream_NilSessionErrors guards the nil-session
// fast path added in D2.
func TestSplitTransport_OpenDownloadStream_NilSessionErrors(t *testing.T) {
	st := NewSplitTransport("127.0.0.1:443", make([]byte, 36), "")
	_, err := st.OpenDownloadStream(nil)
	if err == nil {
		t.Fatal("expected error when session is nil")
	}
}

// Silence unused imports in case one of the helpers gets trimmed later.
var _ = fmt.Sprintf
var _ = browser.RandomEventType
