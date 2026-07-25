package main

import "testing"

// realRoutePrintRU воспроизводит вывод `route print 0.0.0.0` из бага 2026-06-13:
// поднят сторонний sing-tun туннель (172.19.0.2, метрика 0) поверх физического
// Wi-Fi (192.168.1.1, метрика 30). Наш TUN (198.18.0.1) даёт half-default
// 128.0.0.0/1 (On-link) — он НЕ должен попасть в default-маршруты.
const realRoutePrintRU = `===========================================================================
Активные маршруты:
Сетевой адрес           Маска сети      Адрес шлюза       Интерфейс  Метрика
          0.0.0.0          0.0.0.0       172.19.0.2       172.19.0.1      0
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.137     30
          0.0.0.0        128.0.0.0         On-link        198.18.0.1      2
===========================================================================`

func TestParseWindowsDefaultRoutes(t *testing.T) {
	got := parseWindowsDefaultRoutes(realRoutePrintRU)
	want := []winDefaultRoute{
		{gateway: "172.19.0.2", ifaceIP: "172.19.0.1"},
		{gateway: "192.168.1.1", ifaceIP: "192.168.1.137"},
	}
	if len(got) != len(want) {
		t.Fatalf("маршрутов: got %d (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("маршрут %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseWindowsDefaultRoutes_OnLinkExcluded(t *testing.T) {
	// Только half-default нашего TUN (маска 128.0.0.0, On-link) — не default.
	const onlyOnLink = `          0.0.0.0        128.0.0.0         On-link        198.18.0.1      2`
	if got := parseWindowsDefaultRoutes(onlyOnLink); len(got) != 0 {
		t.Fatalf("On-link half-default не должен считаться default-маршрутом, got %v", got)
	}
}

func TestParseWindowsDefaultRoutes_Empty(t *testing.T) {
	if got := parseWindowsDefaultRoutes("мусор\nбез маршрутов\n"); len(got) != 0 {
		t.Fatalf("ожидался пустой результат, got %v", got)
	}
}

func TestPickPhysicalGateway(t *testing.T) {
	// Мапа интерфейсного IP → имя адаптера, как его вернул бы net.Interfaces.
	names := map[string]string{
		"172.19.0.1":   "sing-tun Tunnel", // содержит "tun" → виртуальный
		"192.168.1.137": "Intel(R) Wi-Fi 6E AX210 160MHz",
	}
	nameForIP := func(ip string) string { return names[ip] }

	tests := []struct {
		name   string
		routes []winDefaultRoute
		want   string
	}{
		{
			name: "туннель первым (метрика 0), физика второй — выбираем физический",
			routes: []winDefaultRoute{
				{gateway: "172.19.0.2", ifaceIP: "172.19.0.1"},
				{gateway: "192.168.1.1", ifaceIP: "192.168.1.137"},
			},
			want: "192.168.1.1",
		},
		{
			name: "только физический маршрут",
			routes: []winDefaultRoute{
				{gateway: "192.168.1.1", ifaceIP: "192.168.1.137"},
			},
			want: "192.168.1.1",
		},
		{
			name: "только туннель (нет физики) — graceful fallback на первый",
			routes: []winDefaultRoute{
				{gateway: "172.19.0.2", ifaceIP: "172.19.0.1"},
			},
			want: "172.19.0.2",
		},
		{
			name: "интерфейс не опознан — предпочитаем unknown явно виртуальному",
			routes: []winDefaultRoute{
				{gateway: "172.19.0.2", ifaceIP: "172.19.0.1"}, // virtual
				{gateway: "10.0.0.1", ifaceIP: "10.0.0.2"},     // unknown (нет в мапе)
			},
			want: "10.0.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pickPhysicalGateway(tt.routes, nameForIP); got != tt.want {
				t.Errorf("pickPhysicalGateway = %q, want %q", got, tt.want)
			}
		})
	}
}
