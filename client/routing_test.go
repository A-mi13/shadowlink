package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouter_Decide(t *testing.T) {
	r := NewRouter(RoutingConfig{
		Bypass: []string{"*.ru", "*.рф", "10.0.0.0/8", "192.168.0.0/16", "vk.com"},
		Force:  []string{"youtube.com", "blocked-in-ru.com"},
		Block:  []string{"illegal.com", "*.illegal.org"},
	})
	tests := []struct {
		host   string
		expect Action
	}{
		{"mail.ru", ActionDirect},
		{"api.vk.ru", ActionDirect},
		{"vk.com", ActionDirect},
		{"sub.vk.com", ActionDirect},
		{"youtube.com", ActionTunnel},
		{"www.youtube.com", ActionTunnel},
		{"illegal.com", ActionBlock},
		{"sub.illegal.org", ActionBlock},
		{"google.com", ActionTunnel},
		{"10.0.1.1", ActionDirect},
		{"192.168.1.100", ActionDirect},
		{"8.8.8.8", ActionTunnel},
		{"notvk.com", ActionTunnel},
		{"fakeru.com", ActionTunnel},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expect, r.Decide(tt.host), "host=%s", tt.host)
	}
}

func TestRouter_Empty(t *testing.T) {
	r := NewRouter(RoutingConfig{})
	assert.Equal(t, ActionTunnel, r.Decide("anything.com"))
}

func TestRouter_WithPort(t *testing.T) {
	r := NewRouter(RoutingConfig{Bypass: []string{"*.ru"}})
	assert.Equal(t, ActionDirect, r.Decide("mail.ru:443"))
}
