package main

import (
	"encoding/hex"
	"testing"
)

// Поддержка 802.11 (Wi-Fi) кадров с LLC/SNAP.
//
// Мотив — полевой захват 2026-08-19: pktmon на беспроводном адаптере пишет
// LinkType 1 (Ethernet) в IDB, но КАДРЫ при этом 802.11, а не Ethernet II.
// Парсер читал байты [12:14] как EtherType, получал мусор (0x7DE4), пакет
// отбрасывался — и утилита сообщила «Событий SYN/FIN к origin в захвате нет»
// на захвате из 1 603 467 пакетов. Молчаливая потеря 100 % данных.
//
// Структура кадра (проверено на реальном захвате, 1.6 млн кадров, два вида):
//
//	FrameControl 0x08 (Data)     → MAC-заголовок 24 байта, SNAP на 24
//	FrameControl 0x88 (QoS Data) → +2 байта QoS Control, SNAP на 26
//
// Далее LLC/SNAP: aa aa 03 00 00 00 <ethertype:2>, то есть IP начинается через
// 8 байт от начала SNAP.
//
// Байты в тестах — настоящие, из C:\...\shadowlink-phase.pcapng.

func TestParseDot11_QoSDataFrame(t *testing.T) {
	// FrameControl 0x88 0x02 — QoS Data, от origin к нам.
	raw, err := hex.DecodeString(
		"8802240064497de4313052ff208cc14150ff20fcc141e0ad0000" + // 802.11 QoS hdr (26)
			"aaaa030000000800" + // LLC/SNAP, ethertype IPv4
			"450000280000000040060000" + // IP: ihl=5, proto=6 (TCP)
			"68deb143" + // src 104.222.177.67
			"c0a80189" + // dst 192.168.1.137
			"01bb04d2000000000000000050120000000000000000") // TCP: sport 443, SYN+ACK
	if err != nil {
		t.Fatalf("hex: %v", err)
	}

	p, ok := parseEthernetIPv4TCP(raw, 12345)
	if !ok {
		t.Fatal("QoS Data кадр не разобран — вернулось ok=false")
	}
	if got := ipToString(p.srcIP); got != "104.222.177.67" {
		t.Errorf("srcIP = %s, ожидалось 104.222.177.67", got)
	}
	if got := ipToString(p.dstIP); got != "192.168.1.137" {
		t.Errorf("dstIP = %s, ожидалось 192.168.1.137", got)
	}
	if p.srcPort != 443 {
		t.Errorf("srcPort = %d, ожидалось 443", p.srcPort)
	}
	if !p.syn {
		t.Error("флаг SYN не распознан")
	}
}

func TestParseDot11_PlainDataFrame(t *testing.T) {
	// FrameControl 0x08 0x01 — Data (без QoS), от нас к origin. Заголовок на
	// 2 байта короче, поэтому SNAP на 24 — именно эту разницу парсер обязан
	// определять по типу кадра, а не по фиксированному смещению.
	raw, err := hex.DecodeString(
		"0801008052ff208cc14164497de4313050ff20fcc1410000" + // 802.11 Data hdr (24)
			"aaaa030000000800" +
			"450000280000000040060000" +
			"c0a80189" + // src 192.168.1.137
			"68deb143" + // dst 104.222.177.67
			"04d201bb000000000000000050020000000000000000") // TCP: dport 443, SYN
	if err != nil {
		t.Fatalf("hex: %v", err)
	}

	p, ok := parseEthernetIPv4TCP(raw, 999)
	if !ok {
		t.Fatal("Data кадр не разобран — вернулось ok=false")
	}
	if got := ipToString(p.dstIP); got != "104.222.177.67" {
		t.Errorf("dstIP = %s, ожидалось 104.222.177.67", got)
	}
	if p.dstPort != 443 {
		t.Errorf("dstPort = %d, ожидалось 443", p.dstPort)
	}
	if !p.syn {
		t.Error("флаг SYN не распознан")
	}
	if p.fin || p.rst {
		t.Error("ложные флаги FIN/RST на чистом SYN")
	}
}

// Обычный Ethernet II обязан продолжать работать — 802.11 не должен его
// вытеснить. Это тот путь, на котором держатся все прежние тесты парсера.
func TestParseDot11_EthernetStillWorks(t *testing.T) {
	local := [4]byte{192, 168, 1, 137}
	frame := buildTCPFrame(local, testOrigin, 50001, 443, tcpFlagSYN)
	p, ok := parseEthernetIPv4TCP(frame, 1)
	if !ok {
		t.Fatal("Ethernet II кадр перестал разбираться")
	}
	if ipToString(p.dstIP) != "104.222.177.67" || p.dstPort != 443 || !p.syn {
		t.Errorf("Ethernet II разобран неверно: dst=%s port=%d syn=%v",
			ipToString(p.dstIP), p.dstPort, p.syn)
	}
}

// Кадр 802.11 без SNAP (например management/beacon) не должен приниматься за
// TCP: лучше отбросить, чем разобрать мусор как пакет.
func TestParseDot11_NoSnapRejected(t *testing.T) {
	raw, err := hex.DecodeString(
		"8000000000000000000000000000000000000000000000000000" +
			"00000000000000000000000000000000")
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	if _, ok := parseEthernetIPv4TCP(raw, 1); ok {
		t.Error("кадр без LLC/SNAP принят за IPv4/TCP")
	}
}

func ipToString(ip [4]byte) string {
	const digits = "0123456789"
	buf := make([]byte, 0, 15)
	for i, b := range ip {
		if i > 0 {
			buf = append(buf, '.')
		}
		switch {
		case b >= 100:
			buf = append(buf, digits[b/100], digits[b/10%10], digits[b%10])
		case b >= 10:
			buf = append(buf, digits[b/10], digits[b%10])
		default:
			buf = append(buf, digits[b])
		}
	}
	return string(buf)
}
