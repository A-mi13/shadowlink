package engine

// Сторож удаления мёртвой ECH-ветки (2026-08-26) на стороне движка.
//
// Поле ShadowLinkConfig.ECH было единственным способом дотянуть `ech=1` из
// sl://-ключа до client.ClientConfig.ECHEnabled, откуда включался резолв
// ECHConfigList в ConnManager. Резолв делал DoH-запрос на каждом подключении и
// никогда не применял результат в TLS; достижим он был только в чистом
// CDN-режиме, запрещённом hard rule 1 (прод = DIRECT к голому origin IP).
//
// Пара этому сторожу — client.TestECHFields_RemovedFromConfigs.

import (
	"reflect"
	"strings"
	"testing"
)

// TestShadowLinkConfig_HasNoECHField — власть проверена порчей: возврат поля
// `ECH bool` в ShadowLinkConfig немедленно красит тест.
func TestShadowLinkConfig_HasNoECHField(t *testing.T) {
	typ := reflect.TypeOf(ShadowLinkConfig{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if strings.Contains(strings.ToUpper(name), "ECH") {
			t.Errorf("ShadowLinkConfig.%s: ECH-поле вернулось — ветка резолва "+
				"ECHConfigList удалена, включать её нечем и незачем", name)
		}
	}
}
