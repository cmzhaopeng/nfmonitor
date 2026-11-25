package netinfo

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// 远程修改防火墙最怕把自己关在门外：规则一生效，管理用的 SSH 连接就断了，再也连不回去。
// 这里按「当前这条 SSH 连接」（客户端地址 → 服务器地址:端口）模拟修改前后的规则，
// 修改前放行、修改后不放行，就给出警告；执行前必须由用户确认。
// 模拟只看 ufw / firewalld 自己的规则，不考虑 docker 等其他链，所以是尽力而为的保护。

// SSHPath 是管理连接在服务器一侧看到的样子（取自远程的 $SSH_CONNECTION）。
type SSHPath struct {
	Client string `json:"client"` // 客户端地址（服务器看到的）
	Server string `json:"server"` // 服务器上接受连接的地址
	Port   int    `json:"port"`   // 服务器上 sshd 的端口
	Iface  string `json:"iface"`  // Server 地址所在的网卡（可能为空）
}

// ParseSSHConnection 解析 "client_ip client_port server_ip server_port"。
func ParseSSHConnection(s string) (SSHPath, bool) {
	fs := strings.Fields(s)
	if len(fs) != 4 {
		return SSHPath{}, false
	}
	port, err := strconv.Atoi(fs[3])
	if err != nil {
		return SSHPath{}, false
	}
	c, err1 := netip.ParseAddr(fs[0])
	sv, err2 := netip.ParseAddr(fs[2])
	if err1 != nil || err2 != nil {
		return SSHPath{}, false
	}
	return SSHPath{Client: c.Unmap().String(), Server: sv.Unmap().String(), Port: port}, true
}

func (p SSHPath) v6() bool {
	a, err := netip.ParseAddr(p.Client)
	return err == nil && a.Is6()
}

// local：管理连接来自主机自己（回环或本机地址），这类包走 lo，ufw / firewalld 总是放行。
func (p SSHPath) local() bool {
	a, err := netip.ParseAddr(p.Client)
	return err == nil && (a.IsLoopback() || p.Client == p.Server || p.Iface == "lo")
}

func (p SSHPath) describe() string {
	return fmt.Sprintf("当前连接 %s → %s:%d", p.Client, p.Server, p.Port)
}

// addrCovers：spec 是 any、单个地址或网段，判断它是否包含 ip。
func addrCovers(spec, ip string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "any" || spec == "0.0.0.0/0" || spec == "::/0" {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if p, err := netip.ParsePrefix(spec); err == nil {
		return p.Contains(a)
	}
	if b, err := netip.ParseAddr(spec); err == nil {
		return b.Unmap() == a.Unmap()
	}
	return false
}

// portCovers：spec 是 ufw 的端口写法（any、22、80,443、1000:2000），判断是否包含 port。
func portCovers(spec string, port int) bool {
	if spec == "" || spec == "any" {
		return true
	}
	for _, p := range strings.Split(spec, ",") {
		lo, hi, rng := strings.Cut(p, ":")
		if !rng {
			lo, hi, rng = strings.Cut(p, "-")
		}
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if rng {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		if port >= a && port <= b {
			return true
		}
	}
	return false
}

// ---- ufw ----

// ufwAllowsSSH 判断 SSH 连接的入站包在这组规则下会不会被放行（ufw 按顺序首条命中）。
func ufwAllowsSSH(rules []UfwRule, defIn string, active bool, p SSHPath) bool {
	if !active {
		return true
	}
	v6 := p.v6()
	for _, r := range rules {
		if r.Route || r.Dir != "in" || r.V6 != v6 {
			continue
		}
		if r.Proto != "" && r.Proto != "any" && r.Proto != "tcp" {
			continue
		}
		if !addrCovers(r.Src, p.Client) || !addrCovers(r.Dst, p.Server) {
			continue
		}
		if r.SPort != "" && r.SPort != "any" {
			continue // 客户端端口是随机的，指定了源端口的规则一般匹配不上
		}
		if r.SApp != "" {
			continue
		}
		if r.DApp != "" {
			// 常见的 OpenSSH 应用配置就是 22/tcp；其他应用配置看不到定义，不算命中。
			if !(strings.Contains(strings.ToLower(r.DApp), "ssh") && p.Port == 22) {
				continue
			}
		} else if !portCovers(r.DPort, p.Port) {
			continue
		}
		if r.IfaceIn != "" && p.Iface != "" && strings.TrimSuffix(r.IfaceIn, "+") != p.Iface &&
			!(strings.HasSuffix(r.IfaceIn, "+") && strings.HasPrefix(p.Iface, strings.TrimSuffix(r.IfaceIn, "+"))) {
			continue
		}
		return r.Action == "allow" || r.Action == "limit"
	}
	return defIn == "allow" || defIn == ""
}

// simulateUfw 在内存里套用一次修改，返回修改后的规则、默认入站策略和启用状态。
func simulateUfw(op UfwOp, cur []UfwRule, defIn string, active bool) ([]UfwRule, string, bool) {
	rules := slices.Clone(cur)
	same := func(a, b UfwRule) bool { return a.Route == b.Route && slices.Equal(a.Spec, b.Spec) }
	remove := func(old UfwRule) (pos map[bool]int) {
		pos = map[bool]int{}
		out := rules[:0:0]
		for _, r := range rules {
			if same(r, old) {
				if _, ok := pos[r.V6]; !ok {
					pos[r.V6] = len(out)
				}
				continue
			}
			out = append(out, r)
		}
		rules = out
		return
	}
	// 把新规则插到 idx（同族规则的第 idx 条之前；-1 = 末尾）。地址为 any 时 v4、v6 各一条。
	insert := func(nr UfwRule, before func(v6 bool) int) {
		for _, v6 := range []bool{false, true} {
			if !ruleFitsFamily(nr, v6) {
				continue
			}
			x := nr
			x.V6 = v6
			i := before(v6)
			if i < 0 || i > len(rules) {
				rules = append(rules, x)
			} else {
				rules = slices.Insert(rules, i, x)
			}
		}
	}
	byNum := func(n int) func(bool) int {
		return func(v6 bool) int {
			if n <= 0 {
				return -1
			}
			for i, r := range rules {
				if r.V6 == v6 && r.Num >= n {
					return i
				}
			}
			return -1
		}
	}
	switch op.Op {
	case "enable":
		active = true
	case "disable":
		active = false
	case "default":
		if op.Direction == "incoming" {
			defIn = op.Policy
		}
	case "delete":
		if op.Old != nil {
			remove(*op.Old)
		}
	case "add":
		if op.Rule != nil {
			if nr, err := NormalizeUfwRule(*op.Rule); err == nil {
				insert(nr, byNum(op.Position))
			}
		}
	case "replace":
		if op.Rule != nil && op.Old != nil {
			if nr, err := NormalizeUfwRule(*op.Rule); err == nil {
				pos := remove(*op.Old)
				insert(nr, func(v6 bool) int {
					if i, ok := pos[v6]; ok {
						return i
					}
					return -1
				})
			}
		}
	case "move":
		if op.Old != nil {
			var moved []UfwRule
			for _, r := range rules {
				if same(r, *op.Old) {
					moved = append(moved, r)
				}
			}
			remove(*op.Old)
			for _, m := range moved {
				i := -1
				if op.Before != nil {
					for j, r := range rules {
						if r.V6 == m.V6 && same(r, *op.Before) {
							i = j
							break
						}
					}
				}
				if i < 0 {
					rules = append(rules, m)
				} else {
					rules = slices.Insert(rules, i, m)
				}
			}
		}
	}
	return rules, defIn, active
}

func ruleFitsFamily(r UfwRule, v6 bool) bool {
	for _, a := range []string{r.Src, r.Dst} {
		if a == "" || a == "any" {
			continue
		}
		p, err := netip.ParsePrefix(a)
		if err != nil {
			if ad, err := netip.ParseAddr(a); err == nil {
				return ad.Is6() == v6
			}
			continue
		}
		return p.Addr().Is6() == v6
	}
	return true
}

// UfwLockout 返回这次修改会不会切断 SSH 连接的说明；空串表示没发现风险。
func UfwLockout(op UfwOp, cur []UfwRule, defaults map[string]string, status string, p SSHPath) string {
	if p.Port == 0 || p.local() {
		return ""
	}
	active := status == "active"
	defIn := defaults["incoming"]
	if !ufwAllowsSSH(cur, defIn, active, p) {
		return "" // 模型认为现在就不放行，说明还有别的规则在起作用，判断不了
	}
	rules, defIn2, active2 := simulateUfw(op, cur, defIn, active)
	if ufwAllowsSSH(rules, defIn2, active2, p) {
		return ""
	}
	return fmt.Sprintf("%s：修改后 ufw 不再放行 %d/tcp，执行后很可能连不上这台主机。建议先添加一条允许 %d/tcp 的规则。", p.describe(), p.Port, p.Port)
}
