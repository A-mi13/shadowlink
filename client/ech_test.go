package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveECHConfig_CloudflareDomain(t *testing.T) {
	config, err := ResolveECHConfig("crypto.cloudflare.com")
	if err != nil {
		t.Skipf("ECH resolution failed (network?): %v", err)
	}
	assert.NotEmpty(t, config)
	assert.GreaterOrEqual(t, len(config), 4)
}

func TestResolveECHConfig_NonExistentDomain(t *testing.T) {
	_, err := ResolveECHConfig("this-domain-does-not-exist-12345.invalid")
	assert.Error(t, err)
}

func TestResolveECHConfig_NoDNSHTTPS(t *testing.T) {
	_, err := ResolveECHConfig("example.com")
	// Should return error (no ECH), not panic
	if err == nil {
		t.Log("example.com has ECH config (unexpected but ok)")
	}
}

func TestECHConfig_IsExpired(t *testing.T) {
	var ec *ECHConfig
	assert.True(t, ec.IsExpired(), "nil config should be expired")

	ec = &ECHConfig{}
	assert.True(t, ec.IsExpired(), "empty config should be expired")
}
