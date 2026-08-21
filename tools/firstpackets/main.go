// Command firstpackets анализирует pcapng-захват на попадание под пассивные
// правила классификации потока.
//
// Мотив (research 2026-08-08): основная угроза в РФ — не активное зондирование
// (peer-review не подтверждает его для ТСПУ), а пассивная классификация по
// форме начала потока. Два конкретных правила:
//
//  1. Правило апреля 2024 (net4people/bbs#363, цитируется в NDSS 2025):
//     клиент шлёт >=3 пакета, каждый >=411 байт, И сервер шлёт пакеты чаще
//     клиента. Цель правила — вложенный в туннель TLS-хендшейк, а не сам
//     обфусцированный протокол. Наблюдалось на Tele2/Megafon/MTS/Beeline/Yota.
//
//  2. USENIX Sec 2024 (encapsulated TLS handshakes): вложенное рукопожатие
//     опознаётся по размерам и таймингам записей В НАЧАЛЕ потока. Отсюда
//     контрмера NaiveProxy — паддинг первых N записей каждого потока.
//
// Утилита НЕ выносит вердикт «нас заблокируют». Она отвечает на один
// проверяемый вопрос: попадает ли наш трафик под опубликованные признаки.
//
// Парсер pcapng — минимальный, только то, что пишет pktmon: SHB, IDB, EPB.
// Внешних зависимостей нет намеренно (в go.mod нет pcap-библиотек).
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"sort"
)

// Пороги из правила апреля 2024.
const (
	ruleMinPacketSize = 411 // байт, payload
	ruleMinBigPackets = 3   // столько крупных пакетов от клиента подряд
)

// firstN — сколько первых пакетов потока считать «началом» для целей
// USENIX'24. NaiveProxy паддит первые 8 записей; берём с запасом.
const firstN = 20

type packet struct {
	tsMicros uint64
	srcIP    [4]byte
	dstIP    [4]byte
	srcPort  uint16
	dstPort  uint16
	payload  int // байт TCP payload (без заголовков)
	syn, fin bool
	rst      bool
}

type flowKey struct {
	localPort uint16
}

type flow struct {
	key       flowKey
	packets   []packet
	firstSeen uint64
}

func main() {
	var (
		pcapPath = flag.String("pcap", "", "путь к pcapng от pktmon")
		originIP = flag.String("origin", "104.222.177.67", "IP сервера")
		verbose  = flag.Bool("v", false, "печатать каждый поток подробно")
		phase    = flag.Bool("phase", false, "замер периодичности на проводе по SYN/FIN (vector strength)")
		tick     = flag.Float64("tick", 0.5, "период тика для критерия R < 0.2, секунды")
	)
	flag.Parse()

	if *pcapPath == "" {
		fmt.Fprintln(os.Stderr, "нужен -pcap <файл>")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*pcapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "чтение %s: %v\n", *pcapPath, err)
		os.Exit(1)
	}

	var origin [4]byte
	if _, err := fmt.Sscanf(*originIP, "%d.%d.%d.%d",
		ptrByte(&origin[0]), ptrByte(&origin[1]),
		ptrByte(&origin[2]), ptrByte(&origin[3])); err != nil {
		fmt.Fprintf(os.Stderr, "неразборный origin %q: %v\n", *originIP, err)
		os.Exit(2)
	}

	packets, err := parsePcapng(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "разбор pcapng: %v\n", err)
		os.Exit(1)
	}

	// Режим фазы работает на СЫРЫХ пакетах, а не на потоках: SYN/FIN нужны
	// все, включая соединения, которые groupFlows отбросил бы как неполные
	// (например срезанные посредником — именно они и интересны).
	if *phase {
		reportPhase(packets, origin, *tick)
		return
	}

	flows := groupFlows(packets, origin)
	if len(flows) == 0 {
		fmt.Println("Потоков к origin не найдено.")
		fmt.Println("Проверьте: клиент запущен? -origin совпадает с адресом из лога?")
		return
	}

	report(flows, origin, *verbose)
}

func ptrByte(b *byte) *byte { return b }

// --- pcapng ---

func parsePcapng(b []byte) ([]packet, error) {
	var out []packet
	// Порядок байт определяется по Byte-Order Magic в SHB.
	bo := binary.ByteOrder(binary.LittleEndian)
	// Разрешение таймстампа по интерфейсам (if_tsresol); по умолчанию 10^-6.
	tsDiv := uint64(1)

	off := 0
	for off+8 <= len(b) {
		blockType := bo.Uint32(b[off:])
		blockLen := bo.Uint32(b[off+4:])

		// SHB встречается первым и задаёт порядок байт.
		if blockType == 0x0A0D0D0A {
			if off+12 > len(b) {
				break
			}
			magic := binary.LittleEndian.Uint32(b[off+8:])
			if magic != 0x1A2B3C4D {
				bo = binary.BigEndian
				blockLen = bo.Uint32(b[off+4:])
			}
		}

		if blockLen < 12 || off+int(blockLen) > len(b) {
			break
		}
		body := b[off+8 : off+int(blockLen)-4]

		switch blockType {
		case 0x00000001: // IDB
			// LinkType в первых 2 байтах; нас интересует только Ethernet(1)
			// и Raw IP(101/228). Разрешение таймстампа — опция 9.
			_ = body
		case 0x00000006: // EPB — Enhanced Packet Block
			if len(body) < 20 {
				break
			}
			tsHigh := uint64(bo.Uint32(body[4:]))
			tsLow := uint64(bo.Uint32(body[8:]))
			capLen := bo.Uint32(body[12:])
			ts := (tsHigh<<32 | tsLow)
			if tsDiv > 1 {
				ts /= tsDiv
			}
			if int(capLen)+20 > len(body) {
				break
			}
			data := body[20 : 20+capLen]
			if p, ok := parseEthernetIPv4TCP(data, ts); ok {
				out = append(out, p)
			}
		}

		off += int(blockLen)
		if blockLen == 0 {
			break
		}
	}
	return out, nil
}

// parseEthernetIPv4TCP разбирает кадр. pktmon пишет Ethernet-кадры; на всякий
// случай пробуем и сырой IPv4 (первый нибл == 4).
func parseEthernetIPv4TCP(d []byte, ts uint64) (packet, bool) {
	var p packet
	p.tsMicros = ts

	ipOff := 0
	if len(d) >= 14 {
		etherType := binary.BigEndian.Uint16(d[12:14])
		switch etherType {
		case 0x0800:
			ipOff = 14
		case 0x8100: // VLAN
			if len(d) >= 18 && binary.BigEndian.Uint16(d[16:18]) == 0x0800 {
				ipOff = 18
			} else {
				return p, false
			}
		default:
			// Возможно, сырой IPv4 без Ethernet-заголовка.
			if d[0]>>4 == 4 {
				ipOff = 0
			} else if off, ok := dot11PayloadOffset(d); ok {
				// 802.11 (Wi-Fi). pktmon на беспроводном адаптере пишет в IDB
				// LinkType 1 (Ethernet), но кадры отдаёт 802.11 — поэтому
				// попадаем сюда, а не в отдельную ветку по LinkType.
				ipOff = off
			} else {
				return p, false
			}
		}
	} else {
		return p, false
	}

	if len(d) < ipOff+20 {
		return p, false
	}
	ip := d[ipOff:]
	if ip[0]>>4 != 4 {
		return p, false
	}
	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 || len(ip) < ihl {
		return p, false
	}
	if ip[9] != 6 { // не TCP
		return p, false
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	copy(p.srcIP[:], ip[12:16])
	copy(p.dstIP[:], ip[16:20])

	tcp := ip[ihl:]
	if len(tcp) < 20 {
		return p, false
	}
	p.srcPort = binary.BigEndian.Uint16(tcp[0:2])
	p.dstPort = binary.BigEndian.Uint16(tcp[2:4])
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 {
		return p, false
	}
	flags := tcp[13]
	p.syn = flags&0x02 != 0
	p.fin = flags&0x01 != 0
	p.rst = flags&0x04 != 0

	// totalLen берётся из IP-заголовка; при усечённом захвате может дать
	// отрицательную длину — клампим.
	p.payload = max(totalLen-ihl-dataOff, 0)
	return p, true
}

// --- анализ ---

func groupFlows(packets []packet, origin [4]byte) []*flow {
	byPort := map[uint16]*flow{}
	for _, p := range packets {
		var localPort uint16
		switch {
		case p.dstIP == origin && p.dstPort == 443:
			localPort = p.srcPort
		case p.srcIP == origin && p.srcPort == 443:
			localPort = p.dstPort
		default:
			continue
		}
		f, ok := byPort[localPort]
		if !ok {
			f = &flow{key: flowKey{localPort: localPort}, firstSeen: p.tsMicros}
			byPort[localPort] = f
		}
		f.packets = append(f.packets, p)
	}

	out := make([]*flow, 0, len(byPort))
	for _, f := range byPort {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].firstSeen < out[j].firstSeen })
	return out
}

type flowVerdict struct {
	port            uint16
	clientPkts      int
	serverPkts      int
	bigClientRun    int // максимальная серия подряд идущих клиентских пакетов >=411
	bigClientTotal  int
	serverMoreOften bool
	triggers        bool
	firstSizes      []int // размеры первых непустых пакетов, со знаком: + клиент, - сервер
}

func analyze(f *flow, origin [4]byte) flowVerdict {
	v := flowVerdict{port: f.key.localPort}
	run := 0
	for _, p := range f.packets {
		fromClient := p.dstIP == origin
		if p.payload == 0 {
			continue // чистые ACK/SYN/FIN не участвуют в правиле длин
		}
		if fromClient {
			v.clientPkts++
			if p.payload >= ruleMinPacketSize {
				run++
				v.bigClientTotal++
				if run > v.bigClientRun {
					v.bigClientRun = run
				}
			} else {
				run = 0
			}
		} else {
			v.serverPkts++
		}
		if len(v.firstSizes) < firstN {
			if fromClient {
				v.firstSizes = append(v.firstSizes, p.payload)
			} else {
				v.firstSizes = append(v.firstSizes, -p.payload)
			}
		}
	}
	v.serverMoreOften = v.serverPkts > v.clientPkts
	v.triggers = v.bigClientRun >= ruleMinBigPackets && v.serverMoreOften
	return v
}

func report(flows []*flow, origin [4]byte, verbose bool) {
	fmt.Println("=== ShadowLink: анализ формы начала потоков ===")
	fmt.Printf("origin=%d.%d.%d.%d:443  потоков=%d\n\n",
		origin[0], origin[1], origin[2], origin[3], len(flows))

	triggering := 0
	var bigRuns []int
	var firstPktSizes []int

	for _, f := range flows {
		v := analyze(f, origin)
		if v.clientPkts == 0 && v.serverPkts == 0 {
			continue
		}
		bigRuns = append(bigRuns, v.bigClientRun)
		for _, s := range v.firstSizes {
			if s > 0 {
				firstPktSizes = append(firstPktSizes, s)
			}
		}
		if v.triggers {
			triggering++
		}
		if verbose {
			mark := "  "
			if v.triggers {
				mark = "!!"
			}
			fmt.Printf("%s порт=%-6d клиент=%-4d сервер=%-4d серия>=411=%-2d сервер_чаще=%-5v => %s\n",
				mark, v.port, v.clientPkts, v.serverPkts, v.bigClientRun,
				v.serverMoreOften, verdictWord(v.triggers))
			fmt.Printf("     первые: %v\n", v.firstSizes)
		}
	}

	fmt.Println("--- Правило апреля 2024 (net4people#363) ---")
	fmt.Println("Условие: клиент шлёт >=3 пакета подряд по >=411 байт И сервер шлёт чаще.")
	fmt.Printf("Потоков под правило: %d из %d", triggering, len(flows))
	if len(flows) > 0 {
		fmt.Printf("  (%.1f%%)", 100*float64(triggering)/float64(len(flows)))
	}
	fmt.Println()

	if len(bigRuns) > 0 {
		sort.Ints(bigRuns)
		fmt.Printf("Серия крупных клиентских пакетов: p50=%d p90=%d max=%d\n",
			pct(bigRuns, 50), pct(bigRuns, 90), bigRuns[len(bigRuns)-1])
	}

	fmt.Println()
	fmt.Println("--- Размеры первых пакетов клиента (USENIX Sec 2024) ---")
	if len(firstPktSizes) > 0 {
		sort.Ints(firstPktSizes)
		fmt.Printf("n=%d  min=%d p10=%d p50=%d p90=%d max=%d\n",
			len(firstPktSizes), firstPktSizes[0],
			pct(firstPktSizes, 10), pct(firstPktSizes, 50),
			pct(firstPktSizes, 90), firstPktSizes[len(firstPktSizes)-1])
		over := 0
		for _, s := range firstPktSizes {
			if s >= ruleMinPacketSize {
				over++
			}
		}
		fmt.Printf("доля >=%d байт: %.1f%%\n", ruleMinPacketSize,
			100*float64(over)/float64(len(firstPktSizes)))
	} else {
		fmt.Println("нет данных")
	}

	fmt.Println()
	fmt.Println("--- Как читать ---")
	fmt.Println("Попадание под правило НЕ означает, что нас блокируют: правило")
	fmt.Println("наблюдалось в апреле 2024 на конкретных ISP и могло измениться.")
	fmt.Println("Оно означает, что признак, по которому УЖЕ блокировали чужие")
	fmt.Println("протоколы, у нас присутствует. Непопадание — что этот конкретный")
	fmt.Println("вектор нас не касается, и приоритет надо отдать другим.")
}

func verdictWord(t bool) string {
	if t {
		return "ПОПАДАЕТ"
	}
	return "чисто"
}

func pct(sorted []int, p int) int {
	if len(sorted) == 0 {
		return 0
	}
	idx := (len(sorted) - 1) * p / 100
	return sorted[idx]
}
