package netinfo

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type Addr struct {
	Family string `json:"family"` // inet | inet6
	Local  string `json:"local"`
	Prefix int    `json:"prefix"`
	Scope  string `json:"scope"`
}

type Counters struct {
	RxBytes   uint64 `json:"rxBytes"`
	TxBytes   uint64 `json:"txBytes"`
	RxPackets uint64 `json:"rxPackets"`
	TxPackets uint64 `json:"txPackets"`
	RxErrors  uint64 `json:"rxErrors"`
	TxErrors  uint64 `json:"txErrors"`
	RxDropped uint64 `json:"rxDropped"`
	TxDropped uint64 `json:"txDropped"`
}

type Link struct {
	Index  int      `json:"index"`
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`  // ethernet wifi loopback tun tap wireguard bridge veth vlan ...
	Class  string   `json:"class"` // physical | tunnel | virtual | loopback
	Flags  []string `json:"flags"`
	State  string   `json:"state"` // UP DOWN UNKNOWN
	Up     bool     `json:"up"`    // 管理状态 UP 且有载波
	MTU    int      `json:"mtu"`
	MAC    string   `json:"mac"`
	Master string   `json:"master"`
	Speed  int      `json:"speed"` // Mb/s，未知为 0
	Driver string   `json:"driver"`
	Addrs  []Addr   `json:"addrs"`
	Stats  Counters `json:"stats"`
}

type ipAddrJSON struct {
	Ifindex   int      `json:"ifindex"`
	Ifname    string   `json:"ifname"`
	Flags     []string `json:"flags"`
	MTU       int      `json:"mtu"`
	Operstate string   `json:"operstate"`
	Master    string   `json:"master"`
	LinkType  string   `json:"link_type"`
	Address   string   `json:"address"`
	Linkinfo  struct {
		InfoKind string `json:"info_kind"`
		InfoData struct {
			Type string `json:"type"`
		} `json:"info_data"`
	} `json:"linkinfo"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
	} `json:"addr_info"`
	Stats64 struct {
		Rx ipStats `json:"rx"`
		Tx ipStats `json:"tx"`
	} `json:"stats64"`
}

type ipStats struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Errors  uint64 `json:"errors"`
	Dropped uint64 `json:"dropped"`
}

// Links 返回本机全部网络接口。
func Links() ([]Link, error) { return LinksOn(Local) }

// LinksOn 返回 sys 上的全部网络接口。
func LinksOn(sys Sys) ([]Link, error) {
	sys = orLocal(sys)
	out, err := sys.Run(8*time.Second, "ip", "-j", "-s", "-d", "addr", "show")
	if err != nil {
		return nil, err
	}
	var raw []ipAddrJSON
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, err
	}
	links := make([]Link, 0, len(raw))
	sysInfo := readIfaceSys(sys)
	for _, r := range raw {
		l := Link{
			Index: r.Ifindex, Name: r.Ifname, Flags: r.Flags, State: r.Operstate,
			MTU: r.MTU, MAC: r.Address, Master: r.Master, Addrs: []Addr{},
			Stats: Counters{
				RxBytes: r.Stats64.Rx.Bytes, TxBytes: r.Stats64.Tx.Bytes,
				RxPackets: r.Stats64.Rx.Packets, TxPackets: r.Stats64.Tx.Packets,
				RxErrors: r.Stats64.Rx.Errors, TxErrors: r.Stats64.Tx.Errors,
				RxDropped: r.Stats64.Rx.Dropped, TxDropped: r.Stats64.Tx.Dropped,
			},
		}
		for _, a := range r.AddrInfo {
			l.Addrs = append(l.Addrs, Addr{Family: a.Family, Local: a.Local, Prefix: a.Prefixlen, Scope: a.Scope})
		}
		si := sysInfo[r.Ifname]
		l.Kind, l.Class = classify(r, si)
		l.Up = hasFlag(r.Flags, "UP") && hasFlag(r.Flags, "LOWER_UP")
		if l.Class == "physical" && si.speed > 0 {
			l.Speed = si.speed
		}
		l.Driver = si.driver
		links = append(links, l)
	}
	return links, nil
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

func classify(r ipAddrJSON, si ifaceSys) (kind, class string) {
	if r.LinkType == "loopback" {
		return "loopback", "loopback"
	}
	if k := r.Linkinfo.InfoKind; k != "" {
		if k == "tun" && r.Linkinfo.InfoData.Type == "tap" {
			k = "tap"
		}
		switch k {
		case "tun", "tap", "wireguard", "ipip", "gre", "gretap", "sit", "vti", "xfrm", "ip6tnl", "vxlan", "geneve", "ppp":
			return k, "tunnel"
		}
		return k, "virtual"
	}
	if si.wireless {
		return "wifi", "physical"
	}
	if si.device {
		return "ethernet", "physical"
	}
	if r.LinkType == "none" || r.LinkType == "ppp" {
		return "tunnel", "tunnel"
	}
	return "virtual", "virtual"
}

// StatSample 是一次 /proc/net/dev 采样，前端用相邻两次采样算速率。
type StatSample struct {
	Time  int64               `json:"time"` // unix 毫秒
	Stats map[string]Counters `json:"stats"`
}

// Stats 读取本机 /proc/net/dev，开销很小，适合每秒轮询。
func Stats() (StatSample, error) { return StatsOn(Local) }

// StatsOn 读取 sys 上的 /proc/net/dev。
func StatsOn(sys Sys) (StatSample, error) {
	s := StatSample{Time: time.Now().UnixMilli(), Stats: map[string]Counters{}}
	b, err := orLocal(sys).ReadFile("/proc/net/dev")
	if err != nil {
		return s, err
	}
	s.Time = time.Now().UnixMilli() // 远程读取有往返延迟，以拿到数据的时刻为准
	parseNetDev(string(b), s.Stats)
	return s, nil
}

func parseNetDev(text string, stats map[string]Counters) {
	for _, line := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fs := strings.Fields(rest)
		if len(fs) < 16 {
			continue
		}
		u := func(i int) uint64 { n, _ := strconv.ParseUint(fs[i], 10, 64); return n }
		stats[strings.TrimSpace(name)] = Counters{
			RxBytes: u(0), RxPackets: u(1), RxErrors: u(2), RxDropped: u(3),
			TxBytes: u(8), TxPackets: u(9), TxErrors: u(10), TxDropped: u(11),
		}
	}
}
