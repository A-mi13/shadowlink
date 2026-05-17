package main

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// ParseRIPELines reads RIPE delegated stats lines from r and returns the
// list of CIDR prefixes for the given country code, IPv4 only.
func ParseRIPELines(r io.Reader, country string) ([]netip.Prefix, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var out []netip.Prefix
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 7 {
			continue
		}
		// parts: registry|cc|type|start|count|date|status|...
		if parts[1] != country || parts[2] != "ipv4" {
			continue
		}
		startIP, err := netip.ParseAddr(parts[3])
		if err != nil || !startIP.Is4() {
			continue
		}
		count, err := strconv.ParseUint(parts[4], 10, 32)
		if err != nil || count == 0 {
			continue
		}
		out = append(out, rangeToCIDRs(startIP, uint32(count))...)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}
	return out, nil
}

// rangeToCIDRs converts [start, start+count) to minimum set of CIDRs.
func rangeToCIDRs(start netip.Addr, count uint32) []netip.Prefix {
	startU := addrToU32(start)
	endU := startU + count // exclusive
	var out []netip.Prefix
	for startU < endU {
		var size uint32 = 1
		var prefix int = 32
		for size*2 <= endU-startU && (startU%(size*2)) == 0 {
			size *= 2
			prefix--
			if size == 0 { // overflow guard
				break
			}
		}
		out = append(out, netip.PrefixFrom(u32ToAddr(startU), prefix))
		startU += size
	}
	return out
}

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32ToAddr(u uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}
