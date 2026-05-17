package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// VLESSEngine запускает xray-core как встроенную библиотеку для VLESS+Reality.
// xray-core сам создаёт SOCKS5 inbound — отдельный SOCKS5-сервер не нужен.
type VLESSEngine struct {
	instance  *core.Instance
	socksAddr string
	cfg       *Config
}

// NewVLESSEngine создаёт VLESSEngine из конфига. Требует cfg.VLESS != nil.
func NewVLESSEngine(cfg *Config) (*VLESSEngine, error) {
	if cfg.VLESS == nil {
		return nil, fmt.Errorf("конфиг VLESS не задан")
	}
	return &VLESSEngine{
		socksAddr: cfg.SOCKS,
		cfg:       cfg,
	}, nil
}

// Connect строит JSON-конфиг xray-core и запускает экземпляр.
// После возврата SOCKS5 прокси доступен на cfg.SOCKS.
func (e *VLESSEngine) Connect(_ context.Context) error {
	vc := e.cfg.VLESS
	socksHost, socksPort := parseSOCKSAddr(e.socksAddr)

	// Строим JSON-конфиг xray-core программно через анонимные структуры,
	// чтобы не тащить зависимость от infra/conf напрямую.
	cfg := map[string]any{
		"dns": map[string]any{
			"servers": []string{"1.1.1.1", "8.8.8.8"},
		},
		"inbounds": []map[string]any{
			{
				"tag":      "socks-in",
				"protocol": "socks",
				"listen":   socksHost,
				"port":     socksPort,
				"settings": map[string]any{
					"auth": "password",
					"accounts": []map[string]any{
						{"user": e.cfg.ProxyUser, "pass": e.cfg.ProxyPass},
					},
					"udp": true,
				},
				"sniffing": map[string]any{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
				},
			},
		},
		"outbounds": []map[string]any{
			{
				"tag":      "vless-out",
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []map[string]any{
						{
							"address": vc.Address,
							"port":    vc.Port,
							"users": []map[string]any{
								func() map[string]any {
									enc := vc.Encryption
									if enc == "" {
										enc = "none"
									}
									return map[string]any{
										"id":         vc.UUID,
										"encryption": enc,
										"flow":       vc.Flow,
									}
								}(),
							},
						},
					},
				},
				"streamSettings": map[string]any{
					"network":  "tcp",
					"security": "reality",
					"realitySettings": func() map[string]any {
						rs := map[string]any{
							"fingerprint": vc.Fingerprint,
							"serverName":  vc.SNI,
							"publicKey":   vc.PublicKey,
							"shortId":     vc.ShortID,
							"spiderX":     "/",
						}
						if vc.Mldsa65Verify != "" {
							rs["mldsa65Verify"] = vc.Mldsa65Verify
						}
						return rs
					}(),
				},
			},
			{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]any{},
			},
		},
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"rules": []map[string]any{
				// RU-домены и RU-IP — напрямую, без VPN.
				{
					"type":        "field",
					"domain":      []string{"regexp:\\.ru$", "regexp:\\.рф$", "regexp:\\.su$"},
					"outboundTag": "direct",
				},
				{
					"type":        "field",
					"ip":          []string{"geoip:ru"},
					"outboundTag": "direct",
				},
				// Приватные сети — напрямую (localhost, LAN).
				{
					"type":        "field",
					"ip":          []string{"geoip:private"},
					"outboundTag": "direct",
				},
				// IP и домен VPN-сервера — напрямую (иначе петля через туннель).
				{
					"type":        "field",
					"ip":          []string{vc.Address},
					"outboundTag": "direct",
				},
				{
					"type":        "field",
					"domain":      []string{"domain:" + vc.SNI},
					"outboundTag": "direct",
				},
				// Всё остальное — через VPN.
				{
					"type":        "field",
					"inboundTag":  []string{"socks-in"},
					"outboundTag": "vless-out",
				},
			},
		},
	}

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal xray config: %w", err)
	}

	instance, err := core.StartInstance("json", configJSON)
	if err != nil {
		return fmt.Errorf("запуск xray-core: %w", err)
	}

	e.instance = instance
	return nil
}

// SOCKSAddr возвращает адрес SOCKS5 прокси, который запустил xray-core.
func (e *VLESSEngine) SOCKSAddr() string { return e.socksAddr }

// Name возвращает имя протокола.
func (e *VLESSEngine) Name() string { return "vless" }

// Close останавливает экземпляр xray-core.
func (e *VLESSEngine) Close() error {
	if e.instance != nil {
		return e.instance.Close()
	}
	return nil
}

// parseSOCKSAddr разбивает строку "host:port" на host string и port int.
// При ошибке разбора порта возвращает порт 1080 по умолчанию.
func parseSOCKSAddr(addr string) (string, int) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, 1080
	}
	host := addr[:idx]
	port, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return host, 1080
	}
	return host, port
}
