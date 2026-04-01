package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsPrivateIP(t *testing.T) {
	privateIPs := []string{
		"127.0.0.1", "127.0.0.2", "10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255", "192.168.0.1", "192.168.1.100",
		"169.254.1.1", "0.0.0.0", "100.64.0.1",
	}
	for _, ip := range privateIPs {
		assert.True(t, isPrivateIP(net.ParseIP(ip)), "should be private: %s", ip)
	}

	publicIPs := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "203.0.113.1",
		"172.32.0.1", "100.63.255.255",
	}
	for _, ip := range publicIPs {
		assert.False(t, isPrivateIP(net.ParseIP(ip)), "should be public: %s", ip)
	}
}

func TestSafeDialBlocksLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := SafeDial(ctx, "127.0.0.1:8080", 2*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private")
}

func TestSafeDialBlocksPrivateNetworks(t *testing.T) {
	targets := []string{
		"10.0.0.1:80", "172.16.0.1:443", "192.168.1.1:22",
		"169.254.169.254:80", "0.0.0.0:80",
	}
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_, err := SafeDial(ctx, target, 1*time.Second)
		cancel()
		assert.Error(t, err, "should block: %s", target)
	}
}

func TestSafeDialAllowsPublicIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := SafeDial(ctx, "93.184.216.34:80", 2*time.Second)
	if err != nil {
		assert.NotContains(t, err.Error(), "private", "public IP should not be blocked by SSRF filter")
	}
}

func TestSafeDialInvalidTarget(t *testing.T) {
	ctx := context.Background()
	_, err := SafeDial(ctx, "not-valid", 1*time.Second)
	assert.Error(t, err)
}

func TestSafeDialBlocksIPv6Loopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err := SafeDial(ctx, "[::1]:80", 1*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private")
}
