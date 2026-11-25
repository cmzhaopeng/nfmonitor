package netinfo

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Socket struct {
	Proto     string `json:"proto"` // tcp | udp
	State     string `json:"state"` // LISTEN ESTAB UNCONN ...
	Local     string `json:"local"`
	LocalPort string `json:"localPort"`
	Peer      string `json:"peer"`
	PeerPort  string `json:"peerPort"`
	Iface     string `json:"iface"` // 绑定的设备（addr%dev）
	Dev       string `json:"dev"`   // 本地地址所在的网卡（EnrichSockets 填）
	Process   string `json:"process"`
	App       string `json:"app"` // 可执行文件名（EnrichSockets 填）
	PID       int    `json:"pid"`
	BytesSent uint64 `json:"bytesSent"` // 仅 TCP
	BytesRecv uint64 `json:"bytesRecv"`
}

// SsArgs 是采集套接字用的 ss 参数；提权 helper 复用同一组参数。
var SsArgs = []string{"-H", "-O", "-t", "-u", "-n", "-a", "-p", "-i"}

var (
	ssProc  = regexp.MustCompile(`users:\(\("([^"]*)",pid=(\d+)`)
	ssSent  = regexp.MustCompile(`\bbytes_sent:(\d+)`)
	ssRecvd = regexp.MustCompile(`\bbytes_received:(\d+)`)
)

// Sockets 列出本机 TCP/UDP 套接字。非 root 时看不到其他用户进程的归属。
func Sockets() ([]Socket, error) { return SocketsOn(Local) }

// SocketsOn 以普通权限列出 sys 上的套接字。
func SocketsOn(sys Sys) ([]Socket, error) {
	out, err := orLocal(sys).Run(8*time.Second, "ss", SsArgs...)
	if err != nil {
		return nil, err
	}
	return ParseSs(out), nil
}

func ParseSs(out string) []Socket {
	socks := []Socket{}
	for _, ln := range strings.Split(out, "\n") {
		fs := strings.Fields(ln)
		if len(fs) < 6 || (fs[0] != "tcp" && fs[0] != "udp") {
			continue
		}
		s := Socket{Proto: fs[0], State: fs[1]}
		s.Local, s.LocalPort, s.Iface = splitHostPort(fs[4])
		s.Peer, s.PeerPort, _ = splitHostPort(fs[5])
		rest := strings.Join(fs[6:], " ")
		if m := ssProc.FindStringSubmatch(rest); m != nil {
			s.Process = m[1]
			s.PID, _ = strconv.Atoi(m[2])
		}
		if m := ssSent.FindStringSubmatch(rest); m != nil {
			s.BytesSent, _ = strconv.ParseUint(m[1], 10, 64)
		}
		if m := ssRecvd.FindStringSubmatch(rest); m != nil {
			s.BytesRecv, _ = strconv.ParseUint(m[1], 10, 64)
		}
		socks = append(socks, s)
	}
	return socks
}

// splitHostPort 处理 ss 的地址写法：1.2.3.4:80、[::1]:80、*:80、10.0.0.1%eth0:80。
func splitHostPort(s string) (host, port, iface string) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, "", ""
	}
	host, port = s[:i], s[i+1:]
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	host = strings.TrimPrefix(host, "::ffff:") // 双栈套接字上的 IPv4 连接，按 IPv4 显示
	if j := strings.Index(host, "%"); j >= 0 {
		host, iface = host[:j], host[j+1:]
	}
	return
}
