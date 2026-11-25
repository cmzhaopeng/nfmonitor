package netinfo

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PrivCommands 是需要 root 的只读命令白名单。提权 helper 只接受这里的名字，
// 不接受任何调用方传入的参数。
var PrivCommands = map[string][]string{
	"nft":                   {"nft", "-a", "list", "ruleset"},
	"iptables-save":         {"iptables-save", "-c"},
	"ip6tables-save":        {"ip6tables-save", "-c"},
	"iptables-legacy-save":  {"iptables-legacy-save", "-c"},
	"ip6tables-legacy-save": {"ip6tables-legacy-save", "-c"},
	"ufw":                   {"ufw", "status", "verbose"},
	"ufw-numbered":          {"ufw", "status", "numbered"},
	// 读 /etc/ufw/user.rules、user6.rules 里 ufw 自己写的 tuple 行（路径固定，见 ufw.go）。
	"ufw-tuples": {"ufw"},
	"ss":         append([]string{"ss"}, SsArgs...),
	// firewalld 的只读查询（修改走结构化的 FirewalldOp，见 firewalld.go）。
	"firewalld-state":    {"firewall-cmd", "--state"},
	"firewalld-default":  {"firewall-cmd", "--get-default-zone"},
	"firewalld-zones":    {"firewall-cmd", "--list-all-zones"},
	"firewalld-services": {"firewall-cmd", "--get-services"},
	// 常驻的 bpftrace 探针（脚本固定，见 udp.go）；每次调用取走上次以来的 UDP 流量增量。
	"udpstat": {"bpftrace", "-q", "-e", udpScript},
}

// RunPrivCommand 直接执行白名单命令（调用方自己保证已有权限）。
func RunPrivCommand(name string) (string, error) {
	argv, ok := PrivCommands[name]
	if !ok {
		return "", fmt.Errorf("不允许的命令: %s", name)
	}
	switch name {
	case "udpstat":
		return udpMon.drain()
	case "ufw-tuples":
		return readUfwTuples()
	}
	return Run(15*time.Second, argv[0], argv[1:]...)
}

// RunPrivCommandOn 在远程主机上以 root（root 登录或 sudo）执行白名单命令。
// UDP 探针只在本机提供。
func RunPrivCommandOn(r RootSys, name string) (string, error) {
	argv, ok := PrivCommands[name]
	if !ok {
		return "", fmt.Errorf("不允许的命令: %s", name)
	}
	switch name {
	case "udpstat":
		return "", errors.New("远程主机不统计 UDP 流量")
	case "ufw-tuples":
		return readUfwTuplesWith(r.ReadFileRoot)
	}
	return r.RunRoot(15*time.Second, argv[0], argv[1:]...)
}

type FwRule struct {
	Handle     int    `json:"handle"`
	Text       string `json:"text"`
	HasCounter bool   `json:"hasCounter"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	Verdict    string `json:"verdict"` // accept drop reject jump goto return masquerade dnat snat redirect queue tproxy mark log ...
	Target     string `json:"target"`  // jump/goto 的目标链
	Comment    string `json:"comment"`
}

type FwChain struct {
	Name     string   `json:"name"`
	Base     bool     `json:"base"` // 挂在 netfilter hook 上的基链
	Type     string   `json:"type"` // filter nat route
	Hook     string   `json:"hook"` // prerouting input forward output postrouting ingress egress
	Device   string   `json:"device"`
	Priority string   `json:"priority"` // 原文，如 "filter" "dstnat - 5" "-150"
	Prio     int      `json:"prio"`     // 数值，用于排序
	Policy   string   `json:"policy"`
	Owner    string   `json:"owner"`
	Rules    []FwRule `json:"rules"`
}

type FwObject struct {
	Kind string `json:"kind"` // set map flowtable counter ...
	Name string `json:"name"`
	Raw  string `json:"raw"`
}

type FwTable struct {
	Family  string     `json:"family"` // ip ip6 inet arp bridge netdev
	Name    string     `json:"name"`
	Backend string     `json:"backend"` // nft | iptables-nft | iptables-legacy
	Owner   string     `json:"owner"`
	Chains  []FwChain  `json:"chains"`
	Objects []FwObject `json:"objects"`
}

type Firewall struct {
	Privileged bool              `json:"privileged"` // 本次采集是否拿到了 root 数据
	Tables     []FwTable         `json:"tables"`
	Raw        map[string]string `json:"raw"`       // 各命令原始输出
	Errors     map[string]string `json:"errors"`    // 各命令的失败原因
	UfwStatus  string            `json:"ufwStatus"` // active | inactive | ""(未安装/未知)
	Ufw        *UfwInfo          `json:"ufw"`       // 未安装 ufw 时为 null
	Firewalld  *FirewalldInfo    `json:"firewalld"` // 未安装 firewalld 时为 null
	Tools      map[string]string `json:"tools"`     // 已安装的工具及版本
}

// CollectFirewall 采集本机：用 runPriv 执行需要 root 的命令并解析。
func CollectFirewall(runPriv func(string) (string, error)) Firewall {
	return CollectFirewallOn(Local, runPriv)
}

// CollectFirewallOn 采集 sys 上的防火墙；runPriv 以 root 执行 PrivCommands 里的命令。
func CollectFirewallOn(sys Sys, runPriv func(string) (string, error)) Firewall {
	sys = orLocal(sys)
	fw := Firewall{Tables: []FwTable{}, Raw: map[string]string{}, Errors: map[string]string{}, Tools: map[string]string{}}
	if v, err := sys.Run(8*time.Second, "iptables", "--version"); err == nil {
		fw.Tools["iptables"] = strings.TrimSpace(v)
	}
	if v, err := sys.Run(8*time.Second, "nft", "--version"); err == nil {
		fw.Tools["nft"] = strings.TrimSpace(v)
	}
	hasUfw := sys.HasTool("ufw")
	if hasUfw {
		fw.Tools["ufw"] = "installed"
	}
	if sys.HasTool("firewall-cmd") {
		fw.Tools["firewalld"] = "installed"
	}
	get := func(name string) (string, bool) {
		if !sys.HasTool(PrivCommands[name][0]) {
			return "", false
		}
		out, err := runPriv(name)
		if err != nil {
			fw.Errors[name] = err.Error()
			return "", false
		}
		fw.Raw[name] = out
		return out, true
	}
	if out, ok := get("nft"); ok {
		fw.Privileged = true
		fw.Tables = append(fw.Tables, ParseNft(out)...)
	}
	get("iptables-save")
	get("ip6tables-save")
	// legacy 后端的规则不在 nft ruleset 里，要单独并入。
	for name, fam := range map[string]string{"iptables-legacy-save": "ip", "ip6tables-legacy-save": "ip6"} {
		if out, ok := get(name); ok {
			if ts := ParseIptablesSave(out, fam); len(ts) > 0 {
				fw.Privileged = true
				fw.Tables = append(fw.Tables, ts...)
			} else {
				delete(fw.Raw, name)
			}
		}
	}
	if out, ok := get("ufw"); ok {
		fw.UfwStatus = ParseUfwStatus(out)
		if fw.UfwStatus == "active" {
			get("ufw-numbered") // 未启用时 numbered 只有一行状态，没必要取
		}
	}
	if hasUfw {
		u := &UfwInfo{Status: fw.UfwStatus, Rules: []UfwRule{}}
		var enabled string
		u.Defaults, u.Logging, u.IPv6, enabled = ReadUfwConfigOn(sys)
		if u.Status == "" {
			u.Status = enabled // 没授权时按 ufw.conf 的 ENABLED 推断
		}
		if out, err := runPriv("ufw-tuples"); err != nil {
			u.RulesError = err.Error()
		} else {
			u.Rules = ParseUfwTuples(out, u.IPv6)
		}
		fw.Ufw = u
	}
	if fw.Tools["firewalld"] != "" {
		fd := CollectFirewalld(sys, runPriv)
		fw.Firewalld = &fd
		for k, v := range fd.Raw {
			fw.Raw[k] = v
		}
	}
	return fw
}

// ParseUfwStatus 从 `ufw status` 输出里取状态：active | inactive | ""(认不出)。
// 正常情况下输出是英文（见 cEnv）；中文是兜底，防止 helper 环境里语言变量没清干净。
func ParseUfwStatus(out string) string {
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			k, v, ok = strings.Cut(l, "：")
		}
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k != "Status" && k != "状态" {
			continue
		}
		switch v {
		case "active", "激活":
			return "active"
		case "inactive", "不活动":
			return "inactive"
		}
	}
	return ""
}

var (
	reHandle  = regexp.MustCompile(`\s*# handle (\d+)$`)
	reBase    = regexp.MustCompile(`^type (\S+) hook (\S+)(?: devices? (?:= )?(\{[^}]*\}|"[^"]*"|\S+))? priority ([^;]+);(?:\s*policy (\w+);)?`)
	rePolicy  = regexp.MustCompile(`^policy (\w+);?$`)
	reCounter = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)
	reComment = regexp.MustCompile(`comment "([^"]*)"`)
	reJump    = regexp.MustCompile(`\b(jump|goto) (\S+)`)
	reXtTgt   = regexp.MustCompile(`xt target "?([\w-]+)"?`)
)

// ParseNft 解析 `nft -a list ruleset` 的文本输出。
func ParseNft(out string) []FwTable {
	var tables []FwTable
	var tb *FwTable
	var ch *FwChain
	var obj *FwObject
	depth := 0 // obj 内部的花括号深度
	compat := false
	flushChain := func() {
		if ch != nil {
			ch.Owner = ownerOf(tb.Name, ch.Name)
			tb.Chains = append(tb.Chains, *ch)
			ch = nil
		}
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if strings.Contains(line, "iptables-nft") {
				compat = true
			}
			continue
		}
		handle := 0
		if m := reHandle.FindStringSubmatch(line); m != nil {
			handle, _ = strconv.Atoi(m[1])
			line = strings.TrimSpace(reHandle.ReplaceAllString(line, ""))
		}
		switch {
		case obj != nil:
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= 0 {
				tb.Objects = append(tb.Objects, *obj)
				obj = nil
				continue
			}
			obj.Raw += line + "\n"
		case ch != nil:
			if line == "}" {
				flushChain()
				continue
			}
			if m := reBase.FindStringSubmatch(line); m != nil {
				ch.Base, ch.Type, ch.Hook = true, m[1], m[2]
				ch.Device = strings.Trim(m[3], `"{} `)
				ch.Priority = strings.TrimSpace(m[4])
				ch.Prio = prioValue(ch.Priority, tb.Family)
				ch.Policy = m[5]
				if ch.Policy == "" {
					ch.Policy = "accept"
				}
				continue
			}
			if m := rePolicy.FindStringSubmatch(line); m != nil {
				ch.Policy = m[1]
				continue
			}
			if strings.HasPrefix(line, "comment ") && handle == 0 {
				continue
			}
			ch.Rules = append(ch.Rules, parseRule(line, handle))
		case tb != nil:
			if line == "}" {
				tb.Owner = ownerOf(tb.Name, "")
				if tb.Backend == "" {
					tb.Backend = "nft"
				}
				tables = append(tables, *tb)
				tb = nil
				continue
			}
			if !strings.HasSuffix(line, "{") {
				continue // 表级的 flags / comment
			}
			fs := strings.Fields(strings.TrimSuffix(line, "{"))
			if len(fs) < 2 {
				continue
			}
			if fs[0] == "chain" {
				ch = &FwChain{Name: fs[1], Rules: []FwRule{}}
			} else {
				obj = &FwObject{Kind: fs[0], Name: fs[len(fs)-1]}
				if len(fs) > 2 {
					obj.Kind = strings.Join(fs[:len(fs)-1], " ")
				}
				depth = 1
			}
		default:
			fs := strings.Fields(strings.TrimSuffix(line, "{"))
			if len(fs) == 3 && fs[0] == "table" {
				tb = &FwTable{Family: fs[1], Name: fs[2], Chains: []FwChain{}, Objects: []FwObject{}}
				if compat {
					tb.Backend = "iptables-nft"
				}
			}
			compat = false
		}
	}
	// iptables-nft 的表即使没有警告注释，也能靠内建链名认出来。
	for i := range tables {
		t := &tables[i]
		if t.Backend == "nft" && (t.Family == "ip" || t.Family == "ip6") && isXtTable(t) {
			t.Backend = "iptables-nft"
		}
	}
	return tables
}

func isXtTable(t *FwTable) bool {
	switch t.Name {
	case "filter", "nat", "mangle", "raw", "security":
	default:
		return false
	}
	for _, c := range t.Chains {
		if c.Base && c.Name != strings.ToUpper(c.Name) {
			return false
		}
	}
	return len(t.Chains) > 0
}

func parseRule(line string, handle int) FwRule {
	r := FwRule{Handle: handle, Text: line}
	if m := reCounter.FindStringSubmatch(line); m != nil {
		r.HasCounter = true
		r.Packets, _ = strconv.ParseUint(m[1], 10, 64)
		r.Bytes, _ = strconv.ParseUint(m[2], 10, 64)
		r.Text = strings.Join(strings.Fields(reCounter.ReplaceAllString(r.Text, "")), " ")
	}
	body := r.Text
	if m := reComment.FindStringSubmatch(body); m != nil {
		r.Comment = m[1]
		body = reComment.ReplaceAllString(body, "")
		r.Text = strings.TrimSpace(body)
	}
	if m := reJump.FindStringSubmatch(body); m != nil {
		r.Verdict, r.Target = m[1], m[2]
		return r
	}
	if m := reXtTgt.FindStringSubmatch(body); m != nil {
		r.Verdict = strings.ToLower(m[1])
		return r
	}
	// 判决一般在规则末尾，从后往前找第一个认识的词。
	fs := strings.Fields(body)
	for i := len(fs) - 1; i >= 0; i-- {
		switch w := fs[i]; w {
		case "accept", "drop", "reject", "return", "masquerade", "dnat", "snat", "redirect", "queue", "tproxy", "continue", "notrack":
			r.Verdict = w
			return r
		}
	}
	switch {
	case strings.Contains(body, "mark set"):
		r.Verdict = "mark"
	case strings.Contains(body, "log"):
		r.Verdict = "log"
	}
	return r
}

func prioValue(p, family string) int {
	names := map[string]int{"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}
	if family == "bridge" {
		names = map[string]int{"dstnat": -300, "filter": -200, "out": 100, "srcnat": 300}
	}
	fs := strings.Fields(p)
	if len(fs) == 0 {
		return 0
	}
	base, ok := names[fs[0]]
	if !ok {
		n, _ := strconv.Atoi(fs[0])
		base = n
	}
	if len(fs) == 3 {
		off, _ := strconv.Atoi(fs[2])
		if fs[1] == "-" {
			off = -off
		}
		base += off
	}
	return base
}

// ownerOf 根据表名 / 链名猜规则是谁装的。
func ownerOf(table, chain string) string {
	for _, s := range []string{chain, table} {
		l := strings.ToLower(s)
		switch {
		case l == "":
			continue
		case strings.HasPrefix(l, "ufw"):
			return "ufw"
		case strings.HasPrefix(l, "docker"):
			return "docker"
		case strings.HasPrefix(l, "ts-") || strings.Contains(l, "tailscale"):
			return "tailscale"
		case strings.Contains(l, "sing-box"):
			return "sing-box"
		case strings.HasPrefix(l, "libvirt"):
			return "libvirt"
		case strings.HasPrefix(l, "kube-") || strings.HasPrefix(l, "cni-"):
			return "kubernetes"
		case strings.HasPrefix(l, "f2b-"):
			return "fail2ban"
		case strings.HasPrefix(l, "lxc") || strings.HasPrefix(l, "lxd") || strings.HasPrefix(l, "incus"):
			return "lxc"
		case strings.Contains(l, "firewalld"):
			return "firewalld"
		case strings.Contains(l, "clash") || strings.Contains(l, "mihomo"):
			return "clash"
		case strings.HasPrefix(l, "wg-quick") || strings.Contains(l, "wireguard"):
			return "wireguard"
		}
	}
	return ""
}

var xtHooks = map[string]string{"PREROUTING": "prerouting", "INPUT": "input", "FORWARD": "forward", "OUTPUT": "output", "POSTROUTING": "postrouting"}

var (
	reXtChain = regexp.MustCompile(`^:(\S+) (\S+) \[(\d+):(\d+)\]`)
	reXtRule  = regexp.MustCompile(`^(?:\[(\d+):(\d+)\] )?-A (\S+) ?(.*)$`)
	reXtJump  = regexp.MustCompile(`(?:^| )-([jg]) (\S+)`)
	reXtCmt   = regexp.MustCompile(`-m comment --comment (?:"([^"]*)"|(\S+))`)
)

// ParseIptablesSave 把 iptables-save -c 的输出转成和 nft 相同的模型（用于 legacy 后端）。
// 只有默认策略、没有任何规则和自定义链时返回空。
func ParseIptablesSave(out, family string) []FwTable {
	var tables []FwTable
	var tb *FwTable
	idx := map[string]int{}
	interesting := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "*"):
			tb = &FwTable{Family: family, Name: line[1:], Backend: "iptables-legacy", Chains: []FwChain{}, Objects: []FwObject{}}
			idx = map[string]int{}
		case line == "COMMIT" && tb != nil:
			tables = append(tables, *tb)
			tb = nil
		case tb == nil:
		case strings.HasPrefix(line, ":"):
			m := reXtChain.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			c := FwChain{Name: m[1], Rules: []FwRule{}, Owner: ownerOf(tb.Name, m[1])}
			if hook, ok := xtHooks[m[1]]; ok && m[2] != "-" {
				c.Base, c.Hook, c.Policy = true, hook, strings.ToLower(m[2])
				c.Type, c.Priority, c.Prio = xtPrio(tb.Name, hook)
				if c.Policy != "accept" {
					interesting = true
				}
			} else {
				interesting = true
			}
			idx[c.Name] = len(tb.Chains)
			tb.Chains = append(tb.Chains, c)
		case strings.Contains(line, "-A "):
			m := reXtRule.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			i, ok := idx[m[3]]
			if !ok {
				continue
			}
			interesting = true
			r := FwRule{Text: m[4]}
			if m[1] != "" {
				r.HasCounter = true
				r.Packets, _ = strconv.ParseUint(m[1], 10, 64)
				r.Bytes, _ = strconv.ParseUint(m[2], 10, 64)
			}
			if c := reXtCmt.FindStringSubmatch(r.Text); c != nil {
				r.Comment = c[1] + c[2]
			}
			if j := reXtJump.FindStringSubmatch(r.Text); j != nil {
				switch t := j[2]; t {
				case "ACCEPT", "DROP", "REJECT", "RETURN", "MASQUERADE", "DNAT", "SNAT", "REDIRECT", "LOG", "MARK", "TPROXY", "NFQUEUE", "CONNMARK", "TCPMSS", "CT", "NOTRACK":
					r.Verdict = strings.ToLower(t)
				default:
					r.Verdict, r.Target = "jump", t
					if j[1] == "g" {
						r.Verdict = "goto"
					}
				}
			}
			tb.Chains[i].Rules = append(tb.Chains[i].Rules, r)
		}
	}
	if !interesting {
		return nil
	}
	return tables
}

func xtPrio(table, hook string) (typ, name string, prio int) {
	switch table {
	case "raw":
		return "filter", "raw", -300
	case "mangle":
		if hook == "output" {
			return "route", "mangle", -150
		}
		return "filter", "mangle", -150
	case "nat":
		if hook == "prerouting" || hook == "output" {
			return "nat", "dstnat", -100
		}
		return "nat", "srcnat", 100
	case "security":
		return "filter", "security", 50
	}
	return "filter", "filter", 0
}
