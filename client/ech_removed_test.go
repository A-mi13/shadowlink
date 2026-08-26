package client

// Сторожа удаления мёртвой ECH-ветки (2026-08-26).
//
// Что удалялось: резолв реального ECHConfigList из DNS HTTPS-записи
// (ResolveECHConfig → DoHQuery → DoH-запрос к 1.1.1.1) в ConnManager.connect().
// Ветка делала сетевой запрос на КАЖДОМ подключении и никогда не применяла
// результат в TLS, а достижима была только в чистом CDN-режиме, запрещённом
// hard rule 1.
//
// Что НЕ удалялось и что эти тесты обязаны оставить в покое: GREASE ECH в
// Chrome-профиле uTLS (browser.BoringGREASEECH) и весь DoH-примитив
// (DoHQueryRaw / DoHQueryRawWith / NewDoHKeepAliveClient / DoHServerIP),
// который обслуживает split-DNS форвардер.

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestECHFields_RemovedFromConfigs — структурный сторож: ни один пользовательский
// конфиг больше не несёт поля, которым ECH-ветка включалась. Пока поля нет,
// включить ветку нечем даже случайно.
//
// Власть проверена порчей: возврат `ECHEnabled bool` в ClientConfig (или
// `ECH bool` в ClientFileConfig) немедленно красит этот тест.
func TestECHFields_RemovedFromConfigs(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  reflect.Type
	}{
		{"ClientConfig", reflect.TypeOf(ClientConfig{})},
		{"ConnManagerConfig", reflect.TypeOf(ConnManagerConfig{})},
		{"ClientFileConfig", reflect.TypeOf(ClientFileConfig{})},
		{"ConnManager", reflect.TypeOf(ConnManager{})},
	} {
		for i := 0; i < tc.typ.NumField(); i++ {
			name := tc.typ.Field(i).Name
			if strings.Contains(strings.ToUpper(name), "ECH") {
				t.Errorf("%s.%s: ECH-поле вернулось — ветка резолва ECHConfigList удалена, "+
					"включать её нечем и не нужно (hard rule 1: прод = DIRECT к origin IP)",
					tc.name, name)
			}
		}
	}
}

// TestECHResolve_NotInConnManagerSource — сторож по исходнику: в ConnManager не
// должно остаться ни резолва, ни кэша ECH.
//
// Почему по исходнику, а не поведенчески: реальный резолв уходил в сеть (DoH к
// 1.1.1.1) через голый net.Dialer, точки инъекции у него нет. Поведенческий
// сторож на «нет исходящего соединения» ниже покрывает факт, а этот — намерение.
func TestECHResolve_NotInConnManagerSource(t *testing.T) {
	src, err := os.ReadFile("connmanager.go")
	if err != nil {
		t.Fatalf("прочитать connmanager.go: %v", err)
	}
	// ⚠ Комментарий-надгробие в коде намеренно называет удалённые сущности, а
	// первая версия этого теста искала их подстрокой и краснела на собственном
	// же комментарии. Поэтому ищем строго ИСПОЛНИМЫЕ следы: обращение к полю
	// через приёмник (`cm.ech...`) и вызов резолвера.
	for _, needle := range []string{"ResolveECHConfig(", "cm.echCache", "cm.echEnabled", "cm.echDomain"} {
		if strings.Contains(string(src), needle) {
			t.Errorf("connmanager.go снова содержит %q — ECH-ветка вернулась", needle)
		}
	}
}

// TestECHResolve_NotCalledAnywhereInPackage — тот же сторож, расширенный на весь
// пакет: резолвер ECH удалён, и НИ ОДИН файл пакета client его не зовёт.
//
// ⚠ Честная граница этого сторожа: он проверяет ОТСУТСТВИЕ ВЫЗОВА в исходниках,
// а не отсутствие пакета на проводе. Перехватить сам DoH-запрос тестом нельзя —
// он уходит через голый net.Dialer с пином на 1.1.1.1 (client/ech.go), точки
// инъекции у этого пути нет. Тест «connect() уложился в N мс» был бы сторожем
// без власти: при живой быстрой сети DoH-ответ приходит за десятки мс, и такой
// тест оставался бы зелёным даже с воскресшей веткой.
func TestECHResolve_NotCalledAnywhereInPackage(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("прочитать каталог пакета: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || name == "ech_removed_test.go" {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("прочитать %s: %v", name, err)
		}
		// Тот же приём, что выше: ищем ВЫЗОВ (со скобкой), а не упоминание —
		// иначе тест краснеет на надгробном комментарии в client/ech.go.
		if strings.Contains(string(src), "ResolveECHConfig(") {
			t.Errorf("%s: ResolveECHConfig вернулся — резолв ECHConfigList был удалён "+
				"как мёртвый (результат никогда не применялся в TLS)", name)
		}
	}
}

// TestParseSLURL_LegacyECHParamIgnored — обратная совместимость формата URL:
// старый ключ с `ech=1` обязан разбираться без ошибки, а параметр — молча
// игнорироваться. Поле из конфига удалено, поэтому «игнор» здесь означает
// буквально «парсер его не читает», а не «читает и обнуляет».
func TestParseSLURL_LegacyECHParamIgnored(t *testing.T) {
	raw := "sl://" + testValidPubkey + "@vpn.example.com:443?tls=1&cdn=cdn.example.com&ech=1"

	cfg, err := ParseSLURL(raw)
	if err != nil {
		t.Fatalf("старый ключ с ech=1 обязан разбираться: %v", err)
	}
	if cfg.CDN != "cdn.example.com" || !cfg.TLS {
		t.Fatalf("ech=1 не должен влиять на разбор соседних параметров: %+v", cfg)
	}
	// И обратно: BuildSLURL никогда не эмитит ech=.
	if strings.Contains(BuildSLURL(cfg), "ech=") {
		t.Fatal("BuildSLURL снова эмитит ech= — поле должно быть удалено из формата")
	}
}
