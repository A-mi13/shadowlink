// Package socks5 implements a SOCKS5 proxy server for ShadowLink.
// It handles CONNECT (TCP) and UDP ASSOCIATE commands, routing traffic
// through the ShadowLink tunnel (poll or WebSocket mode) or directly
// for bypass domains.
package socks5

import (
	"fmt"
	"net"
)

// SOCKS5 reply constants (RFC 1928).
var (
	ReplySuccess          = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	ReplyGeneralFailure   = []byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	ReplyNotAllowed       = []byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	ReplyNetUnreachable   = []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	ReplyHostUnreachable  = []byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	ReplyConnRefused      = []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	ReplyCmdNotSupported  = []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	ReplyAddrNotSupported = []byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
)

// SOCKS5 address types.
const (
	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04
)

// SOCKS5 commands.
const (
	CmdConnect      = 0x01
	CmdUDPAssociate = 0x03
)

// ParseDestAddr parses the destination address from a SOCKS5 request buffer.
// buf must contain everything after the SOCKS5 version/cmd/rsv bytes,
// starting at ATYP. n is the total number of bytes read.
// Returns the parsed "host:port" string or empty string on failure.
func ParseDestAddr(buf []byte, n int) string {
	if n < 4 {
		return ""
	}
	switch buf[3] {
	case AtypIPv4:
		if n < 10 {
			return ""
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8|int(buf[9]))
	case AtypDomain:
		if n < 5 {
			return ""
		}
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return ""
		}
		domain := string(buf[5 : 5+domainLen])
		port := int(buf[5+domainLen])<<8 | int(buf[5+domainLen+1])
		return fmt.Sprintf("%s:%d", domain, port)
	case AtypIPv6:
		if n < 22 {
			return ""
		}
		ip := net.IP(buf[4:20])
		port := int(buf[20])<<8 | int(buf[21])
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		return ""
	}
}

// ParseSOCKS5UDPHeader parses the SOCKS5 UDP request header from a datagram.
// Returns the target address, data payload offset, and whether parsing succeeded.
func ParseSOCKS5UDPHeader(buf []byte, n int) (targetAddr string, dataOffset int, ok bool) {
	if n < 4 {
		return "", 0, false
	}
	// RSV(2) + FRAG(1)
	frag := buf[2]
	if frag != 0 {
		return "", 0, false // fragmentation not supported
	}
	atyp := buf[3]
	switch atyp {
	case AtypIPv4:
		if n < 10 {
			return "", 0, false
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8|int(buf[9]))
		return targetAddr, 10, true
	case AtypDomain:
		if n < 5 {
			return "", 0, false
		}
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return "", 0, false
		}
		domain := string(buf[5 : 5+domainLen])
		port := int(buf[5+domainLen])<<8 | int(buf[5+domainLen+1])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
		return targetAddr, 5 + domainLen + 2, true
	case AtypIPv6:
		if n < 22 {
			return "", 0, false
		}
		ip := net.IP(buf[4:20])
		port := int(buf[20])<<8 | int(buf[21])
		targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
		return targetAddr, 22, true
	default:
		return "", 0, false
	}
}

// BuildSOCKS5UDPHeader builds a SOCKS5 UDP response: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT(2) + DATA.
func BuildSOCKS5UDPHeader(addr string, data []byte) []byte {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}

	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	ip := net.ParseIP(host)

	var hdr []byte
	if ip != nil && ip.To4() != nil {
		// IPv4
		ip4 := ip.To4()
		hdr = make([]byte, 10+len(data))
		hdr[0], hdr[1], hdr[2] = 0, 0, 0
		hdr[3] = AtypIPv4
		copy(hdr[4:8], ip4)
		hdr[8] = byte(port >> 8)
		hdr[9] = byte(port & 0xff)
		copy(hdr[10:], data)
	} else if ip != nil {
		// IPv6
		ip6 := ip.To16()
		hdr = make([]byte, 22+len(data))
		hdr[0], hdr[1], hdr[2] = 0, 0, 0
		hdr[3] = AtypIPv6
		copy(hdr[4:20], ip6)
		hdr[20] = byte(port >> 8)
		hdr[21] = byte(port & 0xff)
		copy(hdr[22:], data)
	} else {
		// Domain
		domainBytes := []byte(host)
		hdr = make([]byte, 5+len(domainBytes)+2+len(data))
		hdr[0], hdr[1], hdr[2] = 0, 0, 0
		hdr[3] = AtypDomain
		hdr[4] = byte(len(domainBytes))
		copy(hdr[5:5+len(domainBytes)], domainBytes)
		hdr[5+len(domainBytes)] = byte(port >> 8)
		hdr[5+len(domainBytes)+1] = byte(port & 0xff)
		copy(hdr[5+len(domainBytes)+2:], data)
	}
	return hdr
}
