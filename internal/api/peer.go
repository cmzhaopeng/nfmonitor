package api

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// peerUID 查回环连接对端（客户端套接字）属于哪个用户：客户端也在本机，
// 它那一端会出现在 /proc/net/tcp(6) 里，local_address 就是请求的 RemoteAddr。
func peerUID(remoteAddr string) (int, error) {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return 0, err
	}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		want := procHex(ap, strings.HasSuffix(f, "6"))
		if want == "" {
			continue
		}
		for _, l := range strings.Split(string(b), "\n")[1:] {
			fs := strings.Fields(l)
			if len(fs) < 8 || !strings.EqualFold(fs[1], want) {
				continue
			}
			return strconv.Atoi(fs[7])
		}
	}
	return 0, fmt.Errorf("找不到连接 %s 的属主", remoteAddr)
}

// procHex 把地址编码成 /proc/net/tcp 的格式：每 32 位按主机字节序（小端）打印成 %08X，再接 :%04X 端口。
func procHex(ap netip.AddrPort, v6 bool) string {
	a := ap.Addr()
	var raw []byte
	switch {
	case v6:
		b := a.As16() // IPv4 连到 [::] 监听时显示成 ::ffff:a.b.c.d
		raw = b[:]
	case a.Is4() || a.Is4In6():
		b := a.Unmap().As4()
		raw = b[:]
	default:
		return ""
	}
	var sb strings.Builder
	for i := 0; i < len(raw); i += 4 {
		fmt.Fprintf(&sb, "%08X", binary.LittleEndian.Uint32(raw[i:i+4]))
	}
	fmt.Fprintf(&sb, ":%04X", ap.Port())
	return sb.String()
}
