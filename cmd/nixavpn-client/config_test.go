package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseSLURL_MapsCDNs verifies that the cmd-level parseSLURL bridge copies
// CDNs from client.ClientFileConfig into ShadowLinkConfig — without this the
// engine wire-up DomainPool would silently no-op for SLURL imports.
func TestParseSLURL_MapsCDNs(t *testing.T) {
	const testPubkey = "0000000000000000000000000000000000000000000000000000000000000001"
	url := "sl://" + testPubkey + "@example.com:443?tls=1&ws=1&cdns=a.com,b.com,c.com"
	sl, err := parseSLURL(url)
	require.NoError(t, err)
	assert.Equal(t, []string{"a.com", "b.com", "c.com"}, sl.CDNs)
}
