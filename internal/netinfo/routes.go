package netinfo

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Route struct {
	Family   string   `json:"family"` // inet | inet6
	Dst      string   `json:"dst"`
	Gateway  string   `json:"gateway"`
	Dev      string   `json:"dev"`
	Protocol string   `json:"protocol"`
	Scope    string   `json:"scope"`
	PrefSrc  string   `json:"prefsrc"`
	Metric   int      `json:"metric"`
	Type     string   `json:"type"` // 空=unicast；local broadcast unreachable blackhole ...
	Flags    []string `json:"flags"`
}

type Table struct {
	ID     string   `json:"id"`   // ip 命令给出的名字或编号
	Name   string   `json:"name"` // rt_tables 里的名字（若有）
	Routes []Route  `json:"routes"`
	Devs   []string `json:"devs"` // 该表路由涉及的出口设备
}

type Rule struct {
	Family   string `json:"family"`
	Priority int    `json:"priority"`
	Text     string `json:"text"`   // ip rule 原文（去掉优先级）
	Action   string `json:"action"` // lookup | goto | unreachable | nop | blackhole | prohibit
	Table    string `json:"table"`  // action=lookup 时的目标表
	Goto     int    `json:"goto"`
}

type Routing struct {
	Rules  []Rule  `json:"rules"`
	Tables []Table `json:"tables"`
}

type ipRouteJSON struct {
	Type     string   `json:"type"`
	Dst      string   `json:"dst"`
	Gateway  string   `json:"gateway"`
	Dev      string   `json:"dev"`
	Table    string   `json:"table"`
	Protocol string   `json:"protocol"`
	Scope    string   `json:"scope"`
	PrefSrc  string   `json:"prefsrc"`
	Metric   int      `json:"metric"`
	Flags    []string `json:"flags"`
}

var reHostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$`)

var (
	ruleLine   = regexp.MustCompile(`^(\d+):\s+(.*)$`)
	ruleLookup = regexp.MustCompile(`\blookup (\S+)`)
	ruleGoto   = regexp.MustCompile(`\bgoto (\d+)`)
)

// RoutingInfo 返回本机的策略路由规则和所有路由表。
func RoutingInfo() (Routing, error) { return RoutingOn(Local) }

// RoutingOn 返回 sys 上的策略路由规则和所有路由表。
func RoutingOn(sys Sys) (Routing, error) {
	sys = orLocal(sys)
	run := func(name string, args ...string) (string, error) { return sys.Run(8*time.Second, name, args...) }
	r := Routing{Rules: []Rule{}, Tables: []Table{}}
	names := tableNames(sys)
	byID := map[string]*Table{}
	var order []string
	var firstErr error
	for _, fam := range []string{"inet", "inet6"} {
		flag := "-4"
		if fam == "inet6" {
			flag = "-6"
		}
		if out, err := run("ip", flag, "rule", "show"); err == nil {
			r.Rules = append(r.Rules, parseRules(out, fam)...)
		} else if firstErr == nil {
			firstErr = err
		}
		out, err := run("ip", "-j", flag, "route", "show", "table", "all")
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		var raw []ipRouteJSON
		if err := json.Unmarshal([]byte(out), &raw); err != nil {
			continue
		}
		for _, x := range raw {
			id := x.Table
			if id == "" {
				id = "main"
			}
			t := byID[id]
			if t == nil {
				t = &Table{ID: id, Name: names[id], Routes: []Route{}, Devs: []string{}}
				byID[id] = t
				order = append(order, id)
			}
			if x.Flags == nil {
				x.Flags = []string{}
			}
			t.Routes = append(t.Routes, Route{Family: fam, Dst: x.Dst, Gateway: x.Gateway, Dev: x.Dev,
				Protocol: x.Protocol, Scope: x.Scope, PrefSrc: x.PrefSrc, Metric: x.Metric, Type: x.Type, Flags: x.Flags})
			if x.Dev != "" && !contains(t.Devs, x.Dev) {
				t.Devs = append(t.Devs, x.Dev)
			}
		}
	}
	rank := func(id string) int {
		switch id {
		case "main":
			return 0
		case "default":
			return 2
		case "local":
			return 3
		}
		return 1
	}
	sort.SliceStable(order, func(i, j int) bool { return rank(order[i]) < rank(order[j]) })
	for _, id := range order {
		r.Tables = append(r.Tables, *byID[id])
	}
	if len(r.Rules) == 0 && len(r.Tables) == 0 {
		return r, firstErr
	}
	return r, nil
}

func parseRules(out, fam string) []Rule {
	var rules []Rule
	for _, ln := range strings.Split(out, "\n") {
		m := ruleLine.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		prio, _ := strconv.Atoi(m[1])
		ru := Rule{Family: fam, Priority: prio, Text: strings.TrimSpace(m[2])}
		switch {
		case ruleLookup.MatchString(ru.Text):
			ru.Action, ru.Table = "lookup", ruleLookup.FindStringSubmatch(ru.Text)[1]
		case ruleGoto.MatchString(ru.Text):
			ru.Action = "goto"
			ru.Goto, _ = strconv.Atoi(ruleGoto.FindStringSubmatch(ru.Text)[1])
		default:
			for _, a := range []string{"unreachable", "blackhole", "prohibit", "nop"} {
				if strings.HasSuffix(ru.Text, a) {
					ru.Action = a
				}
			}
		}
		rules = append(rules, ru)
	}
	return rules
}

func tableNames(sys Sys) map[string]string {
	names := map[string]string{}
	for _, p := range []string{"/usr/share/iproute2/rt_tables", "/etc/iproute2/rt_tables"} {
		b, err := sys.ReadFile(p)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			fs := strings.Fields(ln)
			if len(fs) >= 2 && !strings.HasPrefix(fs[0], "#") {
				names[fs[0]] = fs[1]
				names[fs[1]] = fs[1]
			}
		}
	}
	return names
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// RouteGet 询问内核：发往 dst 的包会怎么走（ip route get）。
type RouteGetResult struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	PrefSrc string `json:"prefsrc"`
	Table   string `json:"table"`
	Type    string `json:"type"`
	Raw     string `json:"raw"`
}

func RouteGet(dst string) (RouteGetResult, error) { return RouteGetOn(Local, dst) }

// RouteGetOn 在 sys 上执行 ip route get。远程主机上的域名用它自己的 DNS（getent）解析。
func RouteGetOn(sys Sys, dst string) (RouteGetResult, error) {
	sys = orLocal(sys)
	run := func(name string, args ...string) (string, error) { return sys.Run(8*time.Second, name, args...) }
	var res RouteGetResult
	dst = strings.TrimSpace(dst)
	ip := net.ParseIP(dst)
	if ip == nil && sys.Remote() {
		if !reHostname.MatchString(dst) {
			return res, fmt.Errorf("无法解析 %q", dst)
		}
		if out, err := run("getent", "ahosts", dst); err == nil {
			if fs := strings.Fields(out); len(fs) > 0 {
				ip = net.ParseIP(fs[0])
			}
		}
		if ip == nil {
			return res, fmt.Errorf("无法解析 %q", dst)
		}
	} else if ip == nil {
		addrs, err := net.LookupIP(dst)
		if err != nil || len(addrs) == 0 {
			return res, fmt.Errorf("无法解析 %q", dst)
		}
		ip = addrs[0]
	}
	out, err := run("ip", "-j", "route", "get", ip.String())
	if err != nil {
		return res, err
	}
	var raw []struct {
		ipRouteJSON
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil || len(raw) == 0 {
		return res, fmt.Errorf("无法解析 ip route get 输出")
	}
	x := raw[0]
	res = RouteGetResult{Dst: x.Dst, Gateway: x.Gateway, Dev: x.Dev, PrefSrc: x.PrefSrc, Table: x.Table, Type: x.Type}
	if res.Table == "" {
		res.Table = "main"
	}
	if txt, err := run("ip", "route", "get", ip.String()); err == nil {
		res.Raw = strings.TrimSpace(txt)
	}
	return res, nil
}
