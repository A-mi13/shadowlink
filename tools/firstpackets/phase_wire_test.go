package main

import (
	"encoding/binary"
	"testing"
)

// End-to-end проверка режима -phase: синтетический pcapng собирается в тех же
// байтах, что пишет pktmon, и прогоняется через НАСТОЯЩИЙ parsePcapng +
// collectPhaseSeries. Тесты на vectorStrength сами по себе этого не покрывают:
// они работают на готовых []float64 и не поймают ошибку в разборе кадра или в
// выборе направления пакета — а именно там ошибка стоила бы неверного вердикта
// о фазе.
//
// Мотив отдельного файла: main.go парсер уже был написан и не имел тестов
// вовсе; проверять его целиком здесь не задача, покрывается только путь фазы.

var testOrigin = [4]byte{104, 222, 177, 67}

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
)

// buildTCPFrame собирает Ethernet+IPv4+TCP кадр без payload.
func buildTCPFrame(src, dst [4]byte, srcPort, dstPort uint16, flags byte) []byte {
	frame := make([]byte, 14+20+20)

	// Ethernet: MAC'и нулевые, EtherType IPv4.
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ip := frame[14:]
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[9] = 6 // TCP
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])

	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4 // data offset 5 words
	tcp[13] = flags

	return frame
}

// pcapngBuilder собирает минимальный поток блоков: SHB, IDB, затем EPB.
type pcapngBuilder struct {
	buf []byte
}

func newPcapngBuilder() *pcapngBuilder {
	b := &pcapngBuilder{}

	// SHB: little-endian, длина 28.
	shb := make([]byte, 28)
	binary.LittleEndian.PutUint32(shb[0:4], 0x0A0D0D0A)
	binary.LittleEndian.PutUint32(shb[4:8], 28)
	binary.LittleEndian.PutUint32(shb[8:12], 0x1A2B3C4D)
	binary.LittleEndian.PutUint16(shb[12:14], 1) // version major
	binary.LittleEndian.PutUint16(shb[14:16], 0)
	for i := 16; i < 24; i++ {
		shb[i] = 0xFF // section length = -1
	}
	binary.LittleEndian.PutUint32(shb[24:28], 28)
	b.buf = append(b.buf, shb...)

	// IDB: LinkType 1 (Ethernet), без опций → tsresol по умолчанию 10^-6.
	idb := make([]byte, 20)
	binary.LittleEndian.PutUint32(idb[0:4], 0x00000001)
	binary.LittleEndian.PutUint32(idb[4:8], 20)
	binary.LittleEndian.PutUint16(idb[8:10], 1)
	binary.LittleEndian.PutUint32(idb[12:16], 0xFFFF)
	binary.LittleEndian.PutUint32(idb[16:20], 20)
	b.buf = append(b.buf, idb...)

	return b
}

// addPacket добавляет EPB с таймстампом в микросекундах.
func (b *pcapngBuilder) addPacket(tsMicros uint64, frame []byte) {
	padded := (len(frame) + 3) / 4 * 4
	blockLen := 32 + padded

	epb := make([]byte, blockLen)
	binary.LittleEndian.PutUint32(epb[0:4], 0x00000006)
	binary.LittleEndian.PutUint32(epb[4:8], uint32(blockLen))
	binary.LittleEndian.PutUint32(epb[8:12], 0) // interface ID
	binary.LittleEndian.PutUint32(epb[12:16], uint32(tsMicros>>32))
	binary.LittleEndian.PutUint32(epb[16:20], uint32(tsMicros&0xFFFFFFFF))
	binary.LittleEndian.PutUint32(epb[20:24], uint32(len(frame))) // captured
	binary.LittleEndian.PutUint32(epb[24:28], uint32(len(frame))) // original
	copy(epb[28:], frame)
	binary.LittleEndian.PutUint32(epb[blockLen-4:], uint32(blockLen))

	b.buf = append(b.buf, epb...)
}

func (b *pcapngBuilder) bytes() []byte { return b.buf }

// Захват с идеальной решёткой SYN 500 мс обязан дать R = 1 через полный путь
// парсер → серии → vectorStrength.
func TestWirePhase_GridCaptureIsDetected(t *testing.T) {
	local := [4]byte{192, 168, 1, 137}
	b := newPcapngBuilder()
	for i := 0; i < 100; i++ {
		ts := uint64(1_000_000 + i*500_000) // ровно 500 мс
		frame := buildTCPFrame(local, testOrigin, uint16(50000+i), 443, tcpFlagSYN)
		b.addPacket(ts, frame)
	}

	packets, err := parsePcapng(b.bytes())
	if err != nil {
		t.Fatalf("parsePcapng: %v", err)
	}
	if len(packets) != 100 {
		t.Fatalf("разобрано %d пакетов, ожидалось 100", len(packets))
	}

	series := collectPhaseSeries(packets, testOrigin)
	syn := series[0]
	if len(syn.ts) != 100 {
		t.Fatalf("SYN-серия: n = %d, ожидалось 100", len(syn.ts))
	}
	if r := vectorStrength(syn.ts, 0.5); r < 0.999 {
		t.Fatalf("решётка 500 мс на проводе: R = %.4f, ожидалось ~1.0", r)
	}
}

// Направление обязано учитываться: SYN-ACK от origk НЕ является нашим
// открытием соединения и в серию попадать не должен.
func TestWirePhase_IgnoresPacketsFromOrigin(t *testing.T) {
	local := [4]byte{192, 168, 1, 137}
	b := newPcapngBuilder()
	// 10 наших SYN к origin + 10 SYN-ACK обратно (те же флаги SYN).
	for i := 0; i < 10; i++ {
		ts := uint64(1_000_000 + i*500_000)
		b.addPacket(ts, buildTCPFrame(local, testOrigin, uint16(50000+i), 443, tcpFlagSYN))
		b.addPacket(ts+1000, buildTCPFrame(testOrigin, local, 443, uint16(50000+i), tcpFlagSYN))
	}

	packets, err := parsePcapng(b.bytes())
	if err != nil {
		t.Fatalf("parsePcapng: %v", err)
	}
	if len(packets) != 20 {
		t.Fatalf("разобрано %d пакетов, ожидалось 20", len(packets))
	}

	series := collectPhaseSeries(packets, testOrigin)
	if got := len(series[0].ts); got != 10 {
		t.Fatalf("SYN к origin: n = %d, ожидалось 10 (обратные SYN-ACK не считаются)", got)
	}
}

// FIN и RST — оба момента закрытия, и оба обязаны попадать в серию закрытий:
// рез посредника приходит именно RST/FIN, и потерять его значит не увидеть
// фазу закрытий там, где она важнее всего.
func TestWirePhase_FinAndRstBothCount(t *testing.T) {
	local := [4]byte{192, 168, 1, 137}
	b := newPcapngBuilder()
	for i := 0; i < 6; i++ {
		ts := uint64(1_000_000 + i*250_000)
		flags := byte(tcpFlagFIN)
		if i%2 == 1 {
			flags = tcpFlagRST
		}
		b.addPacket(ts, buildTCPFrame(local, testOrigin, uint16(50000+i), 443, flags))
	}

	packets, err := parsePcapng(b.bytes())
	if err != nil {
		t.Fatalf("parsePcapng: %v", err)
	}
	series := collectPhaseSeries(packets, testOrigin)
	if got := len(series[1].ts); got != 6 {
		t.Fatalf("FIN/RST серия: n = %d, ожидалось 6 (3 FIN + 3 RST)", got)
	}
	if got := len(series[0].ts); got != 0 {
		t.Fatalf("SYN-серия: n = %d, ожидалось 0", got)
	}
}

// SYN+FIN в одном пакете обязан попасть в ОБЕ серии. При switch по флагам он
// учитывался только как открытие, и момент закрытия исчезал молча (P2-3, ревью
// 2026-08-18). В серии закрытий ищут рез посредника — терять там нельзя.
// Дубль в "SYN+FIN вместе" при этом не появляется: событие одно.
func TestWirePhase_SynFinCountsInBothSeries(t *testing.T) {
	local := [4]byte{192, 168, 1, 137}
	b := newPcapngBuilder()
	b.addPacket(1_000_000, buildTCPFrame(local, testOrigin, 50001, 443, tcpFlagSYN))
	b.addPacket(2_000_000, buildTCPFrame(local, testOrigin, 50002, 443, tcpFlagSYN|tcpFlagFIN))
	b.addPacket(3_000_000, buildTCPFrame(local, testOrigin, 50003, 443, tcpFlagFIN))

	packets, err := parsePcapng(b.bytes())
	if err != nil {
		t.Fatalf("parsePcapng: %v", err)
	}
	series := collectPhaseSeries(packets, testOrigin)
	if got := len(series[0].ts); got != 2 {
		t.Fatalf("SYN-серия: n = %d, ожидалось 2 (чистый SYN + SYN|FIN)", got)
	}
	if got := len(series[1].ts); got != 2 {
		t.Fatalf("FIN-серия: n = %d, ожидалось 2 (SYN|FIN + чистый FIN)", got)
	}
	if got := len(series[2].ts); got != 3 {
		t.Fatalf("серия «вместе»: n = %d, ожидалось 3 события без дублей", got)
	}
}

// Нулевой таймстамп не должен ломать нормировку. `t0 == 0` использовался и как
// sentinel «не найдено», и как валидное значение: пакет с ts = 0 сбрасывал t0,
// следующий безусловно перезаписывал его своим значением, и `ts - t0` на uint64
// уходил в underflow — вместо секунд получалось ~1.8e13 БЕЗ признака ошибки.
// Найдено ревью 2026-08-18. pktmon пишет абсолютные времена от эпохи, так что
// в живом захвате ts = 0 маловероятен, но молчаливый мусор в замере хуже паники.
func TestWirePhase_ZeroTimestampDoesNotUnderflow(t *testing.T) {
	local := [4]byte{192, 168, 1, 137}
	b := newPcapngBuilder()
	for i, ts := range []uint64{3_000_000, 0, 9_000_000} {
		b.addPacket(ts, buildTCPFrame(local, testOrigin, uint16(50000+i), 443, tcpFlagSYN))
	}

	packets, err := parsePcapng(b.bytes())
	if err != nil {
		t.Fatalf("parsePcapng: %v", err)
	}
	series := collectPhaseSeries(packets, testOrigin)
	syn := series[0]
	if len(syn.ts) != 3 {
		t.Fatalf("n = %d, ожидалось 3", len(syn.ts))
	}
	// t0 обязан быть 0 (минимум), значит времена — 0, 3, 9 с в возрастающем
	// порядке, и ни одно не должно быть астрономическим.
	for i, v := range syn.ts {
		if v < 0 || v > 3600 {
			t.Fatalf("ts[%d] = %.3f — вне разумных границ (underflow?)", i, v)
		}
	}
	if syn.ts[0] != 0 {
		t.Fatalf("минимальный ts = %.3f, ожидался 0", syn.ts[0])
	}
	if syn.ts[2] < 8.999 || syn.ts[2] > 9.001 {
		t.Fatalf("максимальный ts = %.3f, ожидалось 9.0", syn.ts[2])
	}
}

// Время отсчитывается от первого пакета захвата: абсолютные таймстампы
// pktmon — это unix-микросекунды, и без нормировки фаза считалась бы от
// эпохи. На решётке это незаметно, а на реальном захвате сдвинуло бы фазу.
func TestWirePhase_TimestampsAreRelativeToFirstPacket(t *testing.T) {
	local := [4]byte{192, 168, 1, 137}
	b := newPcapngBuilder()
	base := uint64(1_755_500_000_000_000) // ~2025 год в микросекундах
	for i := 0; i < 5; i++ {
		b.addPacket(base+uint64(i)*100_000,
			buildTCPFrame(local, testOrigin, uint16(50000+i), 443, tcpFlagSYN))
	}

	packets, err := parsePcapng(b.bytes())
	if err != nil {
		t.Fatalf("parsePcapng: %v", err)
	}
	series := collectPhaseSeries(packets, testOrigin)
	if len(series[0].ts) != 5 {
		t.Fatalf("n = %d, ожидалось 5", len(series[0].ts))
	}
	if first := series[0].ts[0]; first != 0 {
		t.Fatalf("первый SYN на t = %.6f, ожидался 0 (нормировка от начала захвата)", first)
	}
	if last := series[0].ts[4]; last < 0.3999 || last > 0.4001 {
		t.Fatalf("последний SYN на t = %.6f, ожидалось 0.4 с", last)
	}
}
