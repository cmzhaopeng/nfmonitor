package netinfo

import (
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ProxySetting 是一条代理配置（环境变量、GNOME 设置、/etc/environment）。
type ProxySetting struct {
	Source  string `json:"source"` // env | gnome | /etc/environment
	Key     string `json:"key"`
	Value   string `json:"value"`
	Host    string `json:"host"`
	Port    string `json:"port"`
	Process string `json:"process"` // 监听该端口的本机进程（若能识别）
	PID     int    `json:"pid"`
	Listen  bool   `json:"listen"` // 本机确有套接字在监听该端口
}

// ProxyProcess 是本机正在运行的已知代理 / VPN 程序。
type ProxyProcess struct {
	PID     int      `json:"pid"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"` // proxy | vpn
	User    string   `json:"user"`
	Cmdline string   `json:"cmdline"`
	Listens []string `json:"listens"`
}

// Tunnel 描述一个隧道设备以及把流量导向它的策略路由。
type Tunnel struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Up         bool     `json:"up"`
	Addrs      []string `json:"addrs"`
	MTU        int      `json:"mtu"`
	Tables     []string `json:"tables"`     // 含有经此设备路由的表
	RouteCount int      `json:"routeCount"` // 这些表里经此设备的路由条数
	Rules      []Rule   `json:"rules"`      // 指向上述表的规则
	Default    bool     `json:"default"`    // 是否承接了默认路由（或等价的大段覆盖）
}

type ProxyInfo struct {
	Settings  []ProxySetting `json:"settings"`
	NoProxy   string         `json:"noProxy"`
	GnomeMode string         `json:"gnomeMode"` // none | manual | auto | ""(不可用)
	Processes []ProxyProcess `json:"processes"`
	Tunnels   []Tunnel       `json:"tunnels"`
}

var knownProcs = map[string]string{
	"sing-box": "proxy", "clash": "proxy", "mihomo": "proxy", "clash-meta": "proxy", "verge-mihomo": "proxy",
	"v2ray": "proxy", "xray": "proxy", "ss-local": "proxy", "sslocal": "proxy", "ssservice": "proxy",
	"trojan": "proxy", "trojan-go": "proxy", "hysteria": "proxy", "naive": "proxy", "gost": "proxy",
	"tun2socks": "proxy", "dae": "proxy", "daed": "proxy", "privoxy": "proxy", "squid": "proxy",
	"tinyproxy": "proxy", "3proxy": "proxy", "redsocks": "proxy", "brook": "proxy", "tuic-client": "proxy",
	"tailscaled": "vpn", "openvpn": "vpn", "wg-quick": "vpn", "wireguard-go": "vpn", "zerotier-one": "vpn",
	"openconnect": "vpn", "charon": "vpn", "nebula": "vpn", "netbird": "vpn", "warp-svc": "vpn", "pppd": "vpn",
}

// CollectProxy 汇总本机的代理配置、代理进程和隧道设备。
func CollectProxy(links []Link, routing Routing, socks []Socket) ProxyInfo {
	return CollectProxyOn(Local, links, routing, socks)
}

// CollectProxyOn 汇总 sys 上的代理配置、代理进程和隧道设备。远程主机没有「本程序的环境变量」
// 和桌面会话，只看 /etc/environment、进程和隧道。
func CollectProxyOn(sys Sys, links []Link, routing Routing, socks []Socket) ProxyInfo {
	sys = orLocal(sys)
	info := ProxyInfo{Settings: []ProxySetting{}, Processes: []ProxyProcess{}, Tunnels: []Tunnel{}}
	remote := sys.Remote()

	seen := map[string]bool{}
	for _, k := range []string{"http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		v := os.Getenv(k)
		lk := strings.ToLower(k)
		if remote || v == "" || seen[lk+v] {
			continue
		}
		seen[lk+v] = true
		info.Settings = append(info.Settings, newSetting("env", lk, v))
	}
	if !remote {
		info.NoProxy = os.Getenv("no_proxy")
		if info.NoProxy == "" {
			info.NoProxy = os.Getenv("NO_PROXY")
		}
	}
	if b, err := sys.ReadFile("/etc/environment"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
			if ok && strings.HasSuffix(strings.ToLower(k), "_proxy") && !strings.EqualFold(k, "no_proxy") {
				info.Settings = append(info.Settings, newSetting("/etc/environment", k, strings.Trim(v, `"'`)))
			}
		}
	}
	if remote {
		// 远程主机没有本程序的桌面会话，gsettings 读不到有意义的值。
	} else if mode, err := run("gsettings", "get", "org.gnome.system.proxy", "mode"); err == nil {
		info.GnomeMode = strings.Trim(strings.TrimSpace(mode), "'")
		if info.GnomeMode == "manual" {
			for _, sch := range []string{"http", "https", "socks"} {
				h, _ := run("gsettings", "get", "org.gnome.system.proxy."+sch, "host")
				p, _ := run("gsettings", "get", "org.gnome.system.proxy."+sch, "port")
				h, p = strings.Trim(strings.TrimSpace(h), "'"), strings.TrimSpace(p)
				if h != "" && p != "" && p != "0" {
					info.Settings = append(info.Settings, ProxySetting{Source: "gnome", Key: sch, Value: h + ":" + p, Host: h, Port: p})
				}
			}
		} else if info.GnomeMode == "auto" {
			if u, err := run("gsettings", "get", "org.gnome.system.proxy", "autoconfig-url"); err == nil {
				info.Settings = append(info.Settings, ProxySetting{Source: "gnome", Key: "pac", Value: strings.Trim(strings.TrimSpace(u), "'")})
			}
		}
	}
	for i := range info.Settings {
		s := &info.Settings[i]
		if s.Port == "" || !isLocalHost(s.Host) {
			continue
		}
		for _, sk := range socks {
			if sk.State == "LISTEN" && sk.LocalPort == s.Port {
				s.Listen = true
				if sk.Process != "" {
					s.Process, s.PID = sk.Process, sk.PID
					break
				}
			}
		}
	}

	procs := newProcTable(sys)
	info.Processes = scanProcs(procs, socks)
	// 监听了代理端口但不在已知名单里的进程也算上。
	for _, s := range info.Settings {
		if s.PID == 0 {
			continue
		}
		found := false
		for _, p := range info.Processes {
			if p.PID == s.PID {
				found = true
			}
		}
		if !found {
			info.Processes = append(info.Processes, procInfo(procs, s.PID, s.Process, "proxy", socks))
		}
	}

	for _, l := range links {
		if l.Class != "tunnel" {
			continue
		}
		t := Tunnel{Name: l.Name, Kind: l.Kind, Up: l.Up, MTU: l.MTU, Addrs: []string{}, Tables: []string{}, Rules: []Rule{}}
		for _, a := range l.Addrs {
			if a.Scope != "link" {
				t.Addrs = append(t.Addrs, a.Local+"/"+strconv.Itoa(a.Prefix))
			}
		}
		for _, tb := range routing.Tables {
			if tb.ID == "local" {
				continue
			}
			n, wide := 0, false
			for _, r := range tb.Routes {
				if r.Dev != l.Name {
					continue
				}
				n++
				if r.Dst == "default" || strings.HasSuffix(r.Dst, "/1") || strings.HasSuffix(r.Dst, "/2") || strings.HasSuffix(r.Dst, "/3") {
					wide = true
				}
			}
			// main 表里每个设备都有自己网段的直连路由，那不算"接管"；
			// 只有默认路由 / 大段路由落在 main 里（如 OpenVPN 的 0.0.0.0/1）才算。
			if n == 0 || (tb.ID == "main" && !wide) {
				continue
			}
			t.Tables = append(t.Tables, tb.ID)
			t.RouteCount += n
			t.Default = t.Default || wide
			if tb.ID == "main" || tb.ID == "default" {
				continue // 指向 main 的规则人人都有，列出来没有信息量
			}
			for _, ru := range routing.Rules {
				if ru.Action != "lookup" || ru.Table != tb.ID {
					continue
				}
				dup := false
				for _, x := range t.Rules {
					dup = dup || (x.Priority == ru.Priority && x.Text == ru.Text)
				}
				if !dup {
					t.Rules = append(t.Rules, ru)
				}
			}
		}
		info.Tunnels = append(info.Tunnels, t)
	}
	return info
}

func newSetting(src, key, val string) ProxySetting {
	s := ProxySetting{Source: src, Key: key, Value: val}
	raw := val
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	if u, err := url.Parse(raw); err == nil {
		s.Host, s.Port = u.Hostname(), u.Port()
		if u.User != nil { // 不把代理口令带到界面上
			u.User = url.User("***")
			s.Value = u.String()
		}
	}
	return s
}

func isLocalHost(h string) bool {
	return h == "localhost" || h == "::1" || strings.HasPrefix(h, "127.")
}

func scanProcs(procs *procTable, socks []Socket) []ProxyProcess {
	out := []ProxyProcess{}
	all := procs.all()
	pids := make([]int, 0, len(all))
	for pid := range all {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	for _, pid := range pids {
		comm := all[pid]
		kind, ok := knownProcs[comm]
		if !ok {
			continue
		}
		out = append(out, procInfo(procs, pid, comm, kind, socks))
	}
	return out
}

func procInfo(procs *procTable, pid int, name, kind string, socks []Socket) ProxyProcess {
	p := ProxyProcess{PID: pid, Name: name, Kind: kind, Listens: []string{}}
	if e, ok := procs.get(pid); ok {
		p.Cmdline, p.User = e.cmdline, e.user
	}
	for _, s := range socks {
		if s.PID == pid && (s.State == "LISTEN" || (s.Proto == "udp" && s.State == "UNCONN")) {
			a := s.Proto + " " + s.Local + ":" + s.LocalPort
			if !contains(p.Listens, a) {
				p.Listens = append(p.Listens, a)
			}
		}
	}
	return p
}
