package client

import "github.com/nixavpn/shadowlink/core"

// NewTestClientWithSession builds a Client carrying only a session, for tests in
// OTHER packages that reach production code through client.Client.
//
// It exists because the pool's UDP path lives in package socks5 while the
// session it must NOT use (the global handshake session) is a private field
// here. An in-package export_test.go cannot serve a test in another package,
// and NewClient would pull in fingerprint resolution and disk state the test
// has no use for.
//
// Deliberately NOT behind a build tag: CI runs `go test ./...` with no tags
// (.github/workflows/release.yml), so tagging this file would silently exclude
// the UDP session guards that depend on it — a guard that never runs is worse
// than an exported symbol. The cost is one unused function in the binary.
//
// Everything else is left zero-valued: the stream maps build themselves lazily
// (RegisterStream, NextStreamID), so a bare Client is safe for stream
// bookkeeping. It has no transport, no token and no fingerprint — do not reach
// for it in production code.
func NewTestClientWithSession(session *core.Session) *Client {
	c := &Client{}
	c.session = session
	return c
}
