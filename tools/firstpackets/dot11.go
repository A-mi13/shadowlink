package main

// Разбор кадров 802.11 (Wi-Fi) с инкапсуляцией LLC/SNAP.
//
// Зачем это здесь. pktmon на БЕСПРОВОДНОМ адаптере объявляет в IDB
// LinkType 1 (Ethernet), а кадры пишет 802.11. Парсер читал байты [12:14] как
// EtherType, получал мусор и отбрасывал пакет — на полевом захвате 2026-08-19
// это дало «событий SYN/FIN к origin в захвате нет» при 1 603 467 пакетах в
// файле. Потеря была стопроцентной и молчаливой, поэтому распознавание идёт
// по СТРУКТУРЕ кадра, а не по LinkType, которому верить нельзя.
//
// Смещение до полезной нагрузки переменное, и это главное, что здесь считается:
//
//	Data (FC type=2, subtype 0-3)      → MAC-заголовок 24 байта
//	QoS Data (subtype 8-15)            → +2 байта QoS Control = 26
//	ToDS+FromDS (мост, Address4)       → +6 байт = 30/32
//
// В полевом захвате встретились ровно два вида: 0x08 (Data, SNAP на 24) и
// 0x88 (QoS Data, SNAP на 26) — 731 998 и 871 469 кадров соответственно.
// Остальные варианты обрабатываются по стандарту, а не подгонкой под замер.

import "encoding/binary"

// LLC/SNAP заголовок: DSAP=AA SSAP=AA Control=03, затем OUI 00:00:00 и
// EtherType. Итого 8 байт до полезной нагрузки.
var llcSnapPrefix = []byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00}

const (
	dot11FrameTypeData = 2 // FC bits 2-3
	dot11MinHeaderLen  = 24
	dot11QoSControlLen = 2
	dot11Address4Len   = 6
	llcSnapHeaderLen   = 8
	etherTypeIPv4      = 0x0800
)

// dot11PayloadOffset возвращает смещение начала IPv4 внутри кадра 802.11.
//
// Возвращает false, если это не data-кадр 802.11 с IPv4 в LLC/SNAP: для
// management/control кадров, шифрованных data-кадров и прочего лучше отдать
// «не наш пакет», чем разобрать произвольные байты как TCP.
func dot11PayloadOffset(d []byte) (int, bool) {
	if len(d) < dot11MinHeaderLen {
		return 0, false
	}

	fc0 := d[0]
	// Protocol Version (биты 0-1) обязан быть 0; иное — не 802.11 или мусор.
	if fc0&0x03 != 0 {
		return 0, false
	}
	frameType := (fc0 >> 2) & 0x03
	if frameType != dot11FrameTypeData {
		return 0, false
	}
	subtype := (fc0 >> 4) & 0x0F

	hdrLen := dot11MinHeaderLen
	// Subtype с установленным старшим битом — QoS-варианты, у них есть
	// дополнительное поле QoS Control.
	if subtype&0x08 != 0 {
		hdrLen += dot11QoSControlLen
	}
	// ToDS и FromDS одновременно (кадр между точками доступа) добавляют
	// Address4 в MAC-заголовок.
	fc1 := d[1]
	if fc1&0x01 != 0 && fc1&0x02 != 0 {
		hdrLen += dot11Address4Len
	}

	if len(d) < hdrLen+llcSnapHeaderLen {
		return 0, false
	}

	// Проверяем SNAP по вычисленному смещению, а НЕ поиском по всему кадру:
	// байты aa aa 03 00 00 00 могут случайно встретиться в payload, и поиск
	// дал бы ложное смещение на произвольном пакете.
	snap := d[hdrLen : hdrLen+llcSnapHeaderLen]
	for i, b := range llcSnapPrefix {
		if snap[i] != b {
			return 0, false
		}
	}
	if binary.BigEndian.Uint16(snap[6:8]) != etherTypeIPv4 {
		return 0, false
	}

	return hdrLen + llcSnapHeaderLen, true
}
