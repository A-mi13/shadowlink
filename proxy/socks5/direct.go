package socks5

import (
	"io"
	"net"
	"time"
)

// DirectDial connects directly to destAddr with SSRF protection.
// SEC-H1 fix: resolves and checks for private IPs before dialing.
// On success, relays data bidirectionally between conn and the target.
func DirectDial(conn net.Conn, destAddr string) {
	host, _, _ := net.SplitHostPort(destAddr)
	if host == "" {
		host = destAddr
	}
	if ips, lookupErr := net.LookupIP(host); lookupErr == nil {
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				conn.Write(ReplyNotAllowed)
				return
			}
		}
	}
	target, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		conn.Write(ReplyHostUnreachable)
		return
	}
	defer target.Close()
	conn.Write(ReplySuccess)
	go io.Copy(target, conn)
	io.Copy(conn, target)
}
