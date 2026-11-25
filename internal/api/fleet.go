package api

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nfmonitor/internal/netinfo"
	"nfmonitor/internal/remote"
)

// 「所有主机」总览：一次采集所有纳管主机的网络与安全策略摘要，并给出需要注意的问题。
//
// GET /api/fleet 返回 FleetReport。结果缓存 fleetTTL，多人同时看也只采一次；手动断开的主机不采集。

const (
	fleetTTL         = 15 * time.Second
	fleetHostTimeout = 30 * time.Second
	fleetParallel    = 8
)

// FleetHost 是一台主机的摘要。
type FleetHost struct {
	ID       string `json:"id"` // 本机为 "local"
	Name     string `json:"name"`
	Addr     string `json:"addr"`
	State    string `json:"state"` // ok | error | disconnected | timeout
	Error    string `json:"error,omitempty"`
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel,omitempty"`
	Priv     string `json:"priv"` // root | sudo | helper | none

	Net   *FleetNet   `json:"net,omitempty"`
	Fw    *FleetFw    `json:"fw,omitempty"`
	Finds []Finding   `json:"findings"`
	Took  int64       `json:"tookMs"`
	Time  int64       `json:"time"` // unix 毫秒
	stats *statSample `json:"-"`
}

// FleetNet 是网络摘要。速率是与上一次采集的差值（第一次采集为 -1）。
type FleetNet struct {
	Ifaces    int            `json:"ifaces"`
	UpIfaces  int            `json:"upIfaces"`
	Addrs     []string       `json:"addrs"` // 非回环的 IP 地址
	RxRate    float64        `json:"rxRate"`
	TxRate    float64        `json:"txRate"`
	Estab     int            `json:"estab"`  // 已建立的 TCP 连接
	Listens   int            `json:"listens"` // 监听中的 TCP 端口 + 绑定的 UDP 端口
	Exposed   []ExposedPort  `json:"exposed"` // 监听在非回环地址上的端口
	TopPeers  []PeerCount    `json:"topPeers"`
}

// ExposedPort 是一个对外监听的端口。
type ExposedPort struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process"`
}

// PeerCount 是连接最多的对端。
type PeerCount struct {
	Peer  string `json:"peer"`
	Conns int    `json:"conns"`
}

// FleetFw 是防火墙 / 安全策略摘要。
type FleetFw struct {
	Privileged     bool   `json:"privileged"` // 拿到了 root 数据（规则完整）
	Ufw            string `json:"ufw"`        // active | inactive | ""(未安装)
	UfwIncoming    string `json:"ufwIncoming,omitempty"`
	UfwRules       int    `json:"ufwRules"`
	Firewalld      string `json:"firewalld"` // running | not running | ""(未安装)
	FirewalldZone  string `json:"firewalldZone,omitempty"`
	Backend        string `json:"backend"` // nft | iptables-legacy | ""
	Tables         int    `json:"tables"`
	Rules          int    `json:"rules"`
	InputPolicy    string `json:"inputPolicy"`    // 入站基链的默认策略：drop | accept | mixed | ""
	InputFiltering bool   `json:"inputFiltering"` // 入站方向有丢弃 / 拒绝（策略或规则）
}

// Finding 是一条需要注意的问题。
type Finding struct {
	Level string `json:"level"` // crit | warn | info
	Text  string `json:"text"`
}

// FleetReport 是总览结果。
type FleetReport struct {
	Time  int64       `json:"time"`
	Hosts []FleetHost `json:"hosts"`
	Error string      `json:"error,omitempty"`
}

type statSample struct {
	at     time.Time
	rx, tx uint64
}

type fleetState struct {
	cached  *FleetReport
	at      time.Time
	samples map[string]statSample
}

func (s *Server) fleet() (FleetReport, error) {
	s.fleetMu.Lock()
	defer s.fleetMu.Unlock()
	st := &s.fleetSt
	if st.cached != nil && time.Since(st.at) < fleetTTL {
		return *st.cached, nil
	}
	if st.samples == nil {
		st.samples = map[string]statSample{}
	}
	type job struct {
		fh FleetHost
		t  *target
	}
	var jobs []job
	if !s.NoLocal {
		host := localHostname()
		jobs = append(jobs, job{FleetHost{ID: "local", Name: "本机", Addr: host}, &target{sys: netinfo.Local, runPriv: s.Priv.Run}})
	}
	if s.Hosts != nil {
		for _, cfg := range s.Hosts.Configs() {
			fh := FleetHost{ID: cfg.ID, Name: cfg.Name, Addr: cfg.Addr}
			h, err := s.Hosts.Get(cfg.ID)
			if err != nil {
				fh.State, fh.Error = "error", err.Error()
				jobs = append(jobs, job{fh, nil})
				continue
			}
			if h.Manual() {
				fh.State = "disconnected"
				fh.Error = remote.ErrDisconnected.Error()
				jobs = append(jobs, job{fh, nil})
				continue
			}
			jobs = append(jobs, job{fh, &target{sys: h, host: h, runPriv: h.RunPriv}})
		}
	}
	out := make([]FleetHost, len(jobs))
	sem := make(chan struct{}, fleetParallel)
	var wg sync.WaitGroup
	for i, j := range jobs {
		if j.t == nil {
			j.fh.Finds = []Finding{}
			j.fh.Time = time.Now().UnixMilli()
			out[i] = j.fh
			continue
		}
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			done := make(chan FleetHost, 1)
			go func() { done <- s.collectFleetHost(j.fh, *j.t) }()
			select {
			case fh := <-done:
				out[i] = fh
			case <-time.After(fleetHostTimeout):
				fh := j.fh
				fh.State, fh.Error, fh.Finds = "timeout", "采集超时", []Finding{{"crit", "采集超时：主机无响应或网络很慢"}}
				fh.Time = time.Now().UnixMilli()
				out[i] = fh
			}
		}(i, j)
	}
	wg.Wait()
	now := time.Now()
	for i := range out {
		fh := &out[i]
		if fh.stats != nil && fh.Net != nil {
			prev, ok := st.samples[fh.ID]
			fh.Net.RxRate, fh.Net.TxRate = -1, -1
			if dt := fh.stats.at.Sub(prev.at).Seconds(); ok && dt > 0.5 && fh.stats.rx >= prev.rx && fh.stats.tx >= prev.tx {
				fh.Net.RxRate = float64(fh.stats.rx-prev.rx) / dt
				fh.Net.TxRate = float64(fh.stats.tx-prev.tx) / dt
			}
			st.samples[fh.ID] = *fh.stats
		}
	}
	rep := FleetReport{Time: now.UnixMilli(), Hosts: out}
	st.cached, st.at = &rep, now
	return rep, nil
}

func (s *Server) collectFleetHost(in FleetHost, t target) (fh FleetHost) {
	start := time.Now()
	fh = in
	fh.Finds = []Finding{}
	defer func() {
		fh.Took = time.Since(start).Milliseconds()
		fh.Time = time.Now().UnixMilli()
	}()
	if t.host != nil {
		info, err := t.host.Connect()
		if err != nil {
			fh.State, fh.Error = "error", err.Error()
			fh.Finds = append(fh.Finds, Finding{"crit", "连不上：" + err.Error()})
			return fh
		}
		fh.Hostname, fh.Kernel = info.Hostname, info.Kernel
		switch info.Root {
		case remote.RootLogin:
			fh.Priv = "root"
		case remote.RootSudo, remote.RootSudoPass:
			fh.Priv = "sudo"
		default:
			fh.Priv = "none"
		}
	} else {
		fh.Hostname = localHostname()
		fh.Priv = s.Priv.Status()
	}
	fh.State = "ok"

	// 网络
	n := &FleetNet{Addrs: []string{}, Exposed: []ExposedPort{}, TopPeers: []PeerCount{}}
	if links, err := netinfo.LinksOn(t.sys); err != nil {
		fh.Finds = append(fh.Finds, Finding{"warn", "网卡采集失败：" + err.Error()})
	} else {
		for _, l := range links {
			if l.Class == "loopback" {
				continue
			}
			n.Ifaces++
			if l.Up {
				n.UpIfaces++
			}
			for _, a := range l.Addrs {
				if a.Scope == "link" {
					continue
				}
				n.Addrs = append(n.Addrs, a.Local)
			}
		}
	}
	if smp, err := netinfo.StatsOn(t.sys); err == nil {
		var rx, tx uint64
		for name, c := range smp.Stats {
			if name == "lo" {
				continue
			}
			rx += c.RxBytes
			tx += c.TxBytes
		}
		fh.stats = &statSample{at: time.UnixMilli(smp.Time), rx: rx, tx: tx}
	}
	if socks, err := s.sockets(t); err != nil {
		fh.Finds = append(fh.Finds, Finding{"warn", "连接采集失败：" + err.Error()})
	} else {
		summarizeSockets(n, socks)
	}
	fh.Net = n

	// 防火墙
	fw := netinfo.CollectFirewallOn(t.sys, t.runPriv)
	fh.Fw = summarizeFirewall(fw)
	fh.Finds = append(fh.Finds, findings(fh.Priv, fh.Fw, n)...)
	return fh
}

func localHostname() string {
	h, _ := osHostname()
	return h
}

func isWildcard(a string) bool {
	a = strings.Trim(a, "[]")
	return a == "*" || a == "0.0.0.0" || a == "::" || a == ""
}

func isLoopback(a string) bool {
	a = strings.Trim(a, "[]")
	if i := strings.IndexByte(a, '%'); i >= 0 {
		a = a[:i]
	}
	ip, err := netip.ParseAddr(a)
	return err == nil && ip.Unmap().IsLoopback()
}

func summarizeSockets(n *FleetNet, socks []netinfo.Socket) {
	peers := map[string]int{}
	seen := map[string]bool{}
	for _, so := range socks {
		switch {
		case so.Proto == "tcp" && so.State == "ESTAB":
			n.Estab++
			if !isLoopback(so.Peer) {
				peers[strings.Trim(so.Peer, "[]")]++
			}
		case (so.Proto == "tcp" && so.State == "LISTEN") || (so.Proto == "udp" && (so.State == "UNCONN" || so.State == "LISTEN") && (so.Peer == "*" || isWildcard(so.Peer))):
			n.Listens++
			if isLoopback(so.Local) {
				continue
			}
			port, _ := strconv.Atoi(so.LocalPort)
			if port == 0 {
				continue
			}
			addr := strings.Trim(so.Local, "[]")
			if isWildcard(addr) {
				addr = "*"
			}
			proc := so.App
			if proc == "" {
				proc = so.Process
			}
			key := so.Proto + "/" + addr + "/" + so.LocalPort
			if seen[key] {
				continue
			}
			seen[key] = true
			n.Exposed = append(n.Exposed, ExposedPort{Proto: so.Proto, Addr: addr, Port: port, Process: proc})
		}
	}
	// 同一端口在 v4 / v6 通配地址上各监听一次时只算一个
	sort.Slice(n.Exposed, func(i, j int) bool {
		a, b := n.Exposed[i], n.Exposed[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Proto < b.Proto
	})
	dedup := n.Exposed[:0]
	for _, e := range n.Exposed {
		if k := len(dedup); k > 0 && dedup[k-1].Port == e.Port && dedup[k-1].Proto == e.Proto && dedup[k-1].Addr == "*" && e.Addr == "*" {
			continue
		}
		dedup = append(dedup, e)
	}
	n.Exposed = dedup
	for p, c := range peers {
		n.TopPeers = append(n.TopPeers, PeerCount{p, c})
	}
	sort.Slice(n.TopPeers, func(i, j int) bool {
		if n.TopPeers[i].Conns != n.TopPeers[j].Conns {
			return n.TopPeers[i].Conns > n.TopPeers[j].Conns
		}
		return n.TopPeers[i].Peer < n.TopPeers[j].Peer
	})
	if len(n.TopPeers) > 5 {
		n.TopPeers = n.TopPeers[:5]
	}
}

func summarizeFirewall(fw netinfo.Firewall) *FleetFw {
	f := &FleetFw{Privileged: fw.Privileged, Ufw: fw.UfwStatus}
	if fw.Ufw != nil {
		if fw.Ufw.Status != "" {
			f.Ufw = fw.Ufw.Status
		}
		f.UfwIncoming = fw.Ufw.Defaults["incoming"]
		f.UfwRules = len(fw.Ufw.Rules)
	}
	if fw.Firewalld != nil {
		f.Firewalld, f.FirewalldZone = fw.Firewalld.State, fw.Firewalld.DefaultZone
	}
	policies := map[string]bool{}
	for _, t := range fw.Tables {
		f.Tables++
		if f.Backend == "" || t.Backend == "iptables-legacy" {
			f.Backend = t.Backend
		}
		for _, c := range t.Chains {
			f.Rules += len(c.Rules)
			if !c.Base || c.Hook != "input" || (c.Type != "" && c.Type != "filter") {
				continue
			}
			if c.Policy != "" {
				policies[strings.ToLower(c.Policy)] = true
				if p := strings.ToLower(c.Policy); p == "drop" || p == "reject" {
					f.InputFiltering = true
				}
			}
			for _, r := range c.Rules {
				if v := strings.ToLower(r.Verdict); v == "drop" || v == "reject" || r.Target != "" {
					// 跳到 ufw / firewalld 的链也算有过滤：具体放行什么由那些链决定
					f.InputFiltering = true
				}
			}
		}
	}
	switch {
	case len(policies) == 1:
		for p := range policies {
			f.InputPolicy = p
		}
	case len(policies) > 1:
		f.InputPolicy = "mixed"
	}
	return f
}

// 对外暴露时风险较高的端口：数据库、缓存、远程桌面、明文协议、容器 / 编排的管理接口。
var riskyPorts = map[int]string{
	21: "FTP", 23: "Telnet", 111: "rpcbind", 135: "MS RPC", 139: "NetBIOS", 445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh",
	1433: "SQL Server", 1521: "Oracle", 2375: "Docker API（无 TLS）", 2379: "etcd", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
	5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 10250: "kubelet", 11211: "Memcached", 27017: "MongoDB",
}

func findings(priv string, fw *FleetFw, n *FleetNet) []Finding {
	var out []Finding
	if priv == "none" {
		out = append(out, Finding{"info", "没有 root 权限：防火墙规则和其他用户进程的连接看不全"})
	}
	if fw != nil && fw.Privileged {
		ufwOn := fw.Ufw == "active"
		fwdOn := fw.Firewalld == "running"
		switch {
		case !ufwOn && !fwdOn && !fw.InputFiltering:
			out = append(out, Finding{"crit", "没有启用防火墙：ufw / firewalld 都未运行，入站方向也没有丢弃或拒绝的规则"})
		case ufwOn && fw.UfwIncoming == "allow":
			out = append(out, Finding{"warn", "ufw 默认入站策略是「允许」，相当于不设防"})
		case !ufwOn && !fwdOn:
			out = append(out, Finding{"info", "ufw / firewalld 都未运行，过滤靠直接写的 nftables / iptables 规则"})
		}
		if ufwOn && fwdOn {
			out = append(out, Finding{"warn", "ufw 和 firewalld 同时在运行，规则可能互相冲突"})
		}
	}
	if n != nil {
		var risky []string
		for _, e := range n.Exposed {
			if name, ok := riskyPorts[e.Port]; ok && e.Proto == "tcp" {
				risky = append(risky, fmt.Sprintf("%d（%s）", e.Port, name))
			}
		}
		if len(risky) > 0 {
			out = append(out, Finding{"warn", "高风险端口对外监听：" + strings.Join(risky, "、") + "，请确认防火墙只放行可信来源"})
		}
		if len(n.Exposed) > 30 {
			out = append(out, Finding{"info", fmt.Sprintf("对外监听的端口较多（%d 个）", len(n.Exposed))})
		}
	}
	if out == nil {
		out = []Finding{}
	}
	return out
}
