package netinfo

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// firewalld（RHEL / Fedora / openSUSE 系常用）。
//
// 读：firewall-cmd 的 --state、--get-default-zone、--list-all-zones、--get-services，
// 优先经 root（helper 或远程 sudo）执行，没有权限时退回普通权限（firewalld 的 polkit 策略
// 通常允许普通用户查看）。
// 写：结构化的 FirewalldOp，校验后生成 firewall-cmd 参数，运行时与永久配置各执行一遍，
// 改动立即生效、重启后也还在。

// FirewalldZone 是一个区域在运行时的配置。
type FirewalldZone struct {
	Name         string   `json:"name"`
	Default      bool     `json:"default"`
	Active       bool     `json:"active"`
	Target       string   `json:"target"` // default ACCEPT DROP %%REJECT%%
	Interfaces   []string `json:"interfaces"`
	Sources      []string `json:"sources"`
	Services     []string `json:"services"`
	Ports        []string `json:"ports"`
	Protocols    []string `json:"protocols"`
	Masquerade   bool     `json:"masquerade"`
	ForwardPorts []string `json:"forwardPorts"`
	SourcePorts  []string `json:"sourcePorts"`
	IcmpBlocks   []string `json:"icmpBlocks"`
	RichRules    []string `json:"richRules"`
}

type FirewalldInfo struct {
	State       string            `json:"state"` // running | not running | ""(未知)
	DefaultZone string            `json:"defaultZone"`
	Zones       []FirewalldZone   `json:"zones"`
	Services    []string          `json:"services"` // 可用的服务名
	Error       string            `json:"error,omitempty"`
	Raw         map[string]string `json:"-"`
}

// CollectFirewalld 读取 firewalld 状态与各区域配置。runPriv 可为 nil。
func CollectFirewalld(sys Sys, runPriv func(string) (string, error)) FirewalldInfo {
	sys = orLocal(sys)
	info := FirewalldInfo{Zones: []FirewalldZone{}, Services: []string{}, Raw: map[string]string{}}
	get := func(name string) (string, error) {
		if runPriv != nil {
			if out, err := runPriv(name); err == nil {
				return out, nil
			}
		}
		argv := PrivCommands[name]
		return sys.Run(15*time.Second, argv[0], argv[1:]...)
	}
	st, err := get("firewalld-state")
	info.State = strings.TrimSpace(st)
	if err != nil && info.State == "" {
		info.Error = err.Error()
		return info
	}
	if info.State != "running" {
		return info
	}
	if out, err := get("firewalld-default"); err == nil {
		info.DefaultZone = strings.TrimSpace(out)
	}
	out, err := get("firewalld-zones")
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Raw["firewalld"] = out
	info.Zones = ParseFirewalldZones(out, info.DefaultZone)
	if out, err := get("firewalld-services"); err == nil {
		info.Services = strings.Fields(out)
		slices.Sort(info.Services)
	}
	return info
}

var reZoneHead = regexp.MustCompile(`^([A-Za-z0-9_+-]+)(?:\s+\(([^)]*)\))?\s*$`)

// ParseFirewalldZones 解析 `firewall-cmd --list-all-zones` 的输出。
func ParseFirewalldZones(out, defaultZone string) []FirewalldZone {
	zones := []FirewalldZone{}
	var z *FirewalldZone
	lastKey := ""
	add := func(key, val string) {
		if z == nil {
			return
		}
		val = strings.TrimSpace(val)
		if val == "" {
			return
		}
		list := func(p *[]string) { *p = append(*p, strings.Fields(val)...) }
		switch key {
		case "target":
			z.Target = val
		case "interfaces":
			list(&z.Interfaces)
		case "sources":
			list(&z.Sources)
		case "services":
			list(&z.Services)
		case "ports":
			list(&z.Ports)
		case "protocols":
			list(&z.Protocols)
		case "masquerade":
			z.Masquerade = val == "yes"
		case "forward-ports":
			list(&z.ForwardPorts)
		case "source-ports":
			list(&z.SourcePorts)
		case "icmp-blocks":
			list(&z.IcmpBlocks)
		case "rich rules":
			z.RichRules = append(z.RichRules, val)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			m := reZoneHead.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			zones = append(zones, FirewalldZone{Name: m[1], Interfaces: []string{}, Sources: []string{}, Services: []string{},
				Ports: []string{}, Protocols: []string{}, ForwardPorts: []string{}, SourcePorts: []string{}, IcmpBlocks: []string{}, RichRules: []string{}})
			z = &zones[len(zones)-1]
			for _, f := range strings.Split(m[2], ",") {
				switch strings.TrimSpace(f) {
				case "active":
					z.Active = true
				case "default":
					z.Default = true
				}
			}
			if z.Name == defaultZone {
				z.Default = true
			}
			lastKey = ""
			continue
		}
		if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "        ") {
			add(lastKey, line) // 上一项的续行（rich rules、新版本的 forward-ports）
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		lastKey = strings.TrimSpace(k)
		add(lastKey, v)
	}
	// 没有接口也没有来源的区域，firewalld 不会标 active。
	for i := range zones {
		if len(zones[i].Interfaces) > 0 || len(zones[i].Sources) > 0 {
			zones[i].Active = true
		}
	}
	return zones
}

// ---- 写操作 ----

// FirewalldOp 是一次 firewalld 修改。
type FirewalldOp struct {
	Op      string `json:"op"`              // add | remove | default-zone
	Zone    string `json:"zone"`            // 区域名
	Kind    string `json:"kind,omitempty"`  // service port source interface rich-rule masquerade
	Value   string `json:"value,omitempty"` // 服务名、端口（22/tcp、1000-2000/udp）、地址、网卡名、rich rule 原文
	Confirm bool   `json:"confirm,omitempty"`
}

type FirewalldResult struct {
	Commands [][]string `json:"commands"`
	Output   string     `json:"output"`
	Executed bool       `json:"executed"`
	Warning  string     `json:"warning,omitempty"`
}

var (
	reFwdName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$`)
	reFwdPort    = regexp.MustCompile(`^(\d{1,5})(?:-(\d{1,5}))?/(tcp|udp|sctp|dccp)$`)
	reMAC        = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)
	reIpsetSrc   = regexp.MustCompile(`^ipset:[A-Za-z0-9_.-]{1,64}$`)
	reRichAction = regexp.MustCompile(`\b(accept|reject|drop|mark)\b`)
)

func normFwdPort(v string) (string, error) {
	m := reFwdPort.FindStringSubmatch(strings.ToLower(strings.TrimSpace(v)))
	if m == nil {
		return "", errors.New("端口写法应为 22/tcp 或 8000-8100/udp")
	}
	lo, _ := strconv.Atoi(m[1])
	hi := lo
	if m[2] != "" {
		hi, _ = strconv.Atoi(m[2])
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return "", errors.New("端口范围无效（1–65535）")
	}
	return strings.ToLower(strings.TrimSpace(v)), nil
}

func normFwdSource(v string) (string, error) {
	v = strings.TrimSpace(v)
	switch {
	case reMAC.MatchString(v), reIpsetSrc.MatchString(v):
		return v, nil
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked().String(), nil
	}
	if a, err := netip.ParseAddr(v); err == nil && a.Zone() == "" {
		return a.String(), nil
	}
	return "", errors.New("来源应为 IP 地址、网段（10.0.0.0/8）、MAC 地址或 ipset:名称")
}

func normRichRule(v string) (string, error) {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "rule ") && v != "rule" {
		return "", errors.New(`rich rule 要以 rule 开头，例如 rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept`)
	}
	if len(v) > 1000 {
		return "", errors.New("rich rule 太长")
	}
	for _, c := range v {
		if unicode.IsControl(c) {
			return "", errors.New("rich rule 里不能有换行等控制字符")
		}
	}
	return v, nil
}

func (info FirewalldInfo) zone(name string) (FirewalldZone, bool) {
	for _, z := range info.Zones {
		if z.Name == name {
			return z, true
		}
	}
	return FirewalldZone{}, false
}

// BuildFirewalld 校验一次修改并翻译成 firewall-cmd 命令。info 是当前配置（执行前在 root 侧重新读取）。
func BuildFirewalld(op FirewalldOp, info FirewalldInfo) ([][]string, error) {
	if info.State != "running" {
		return nil, errors.New("firewalld 没有运行")
	}
	z, ok := info.zone(op.Zone)
	if !ok {
		return nil, fmt.Errorf("区域不存在: %q", op.Zone)
	}
	zoneArg := "--zone=" + z.Name
	if op.Op == "default-zone" {
		if z.Name == info.DefaultZone {
			return nil, errors.New("已经是默认区域")
		}
		return [][]string{{"firewall-cmd", "--set-default-zone=" + z.Name}}, nil
	}
	if op.Op != "add" && op.Op != "remove" {
		return nil, fmt.Errorf("未知操作: %q", op.Op)
	}
	adding := op.Op == "add"
	var flag, val string
	var cur []string
	switch op.Kind {
	case "service":
		val = strings.TrimSpace(op.Value)
		if !reFwdName.MatchString(val) {
			return nil, fmt.Errorf("服务名无效: %q", op.Value)
		}
		if adding && len(info.Services) > 0 && !slices.Contains(info.Services, val) {
			return nil, fmt.Errorf("firewalld 没有名为 %q 的服务定义", val)
		}
		flag, cur = "service", z.Services
	case "port":
		v, err := normFwdPort(op.Value)
		if err != nil {
			return nil, err
		}
		flag, val, cur = "port", v, z.Ports
	case "source":
		v, err := normFwdSource(op.Value)
		if err != nil {
			return nil, err
		}
		flag, val, cur = "source", v, z.Sources
		if adding {
			for _, o := range info.Zones {
				if o.Name != z.Name && slices.Contains(o.Sources, v) {
					return nil, fmt.Errorf("来源 %s 已绑定在区域 %s，请先从那里移除", v, o.Name)
				}
			}
		}
	case "interface":
		val = strings.TrimSpace(op.Value)
		if !reIface.MatchString(val) || strings.HasSuffix(val, "+") {
			return nil, fmt.Errorf("网卡名无效: %q", op.Value)
		}
		flag, cur = "interface", z.Interfaces
	case "rich-rule":
		v, err := normRichRule(op.Value)
		if err != nil {
			return nil, err
		}
		flag, val, cur = "rich-rule", v, z.RichRules
	case "masquerade":
		if adding == z.Masquerade {
			if adding {
				return nil, errors.New("已经开启了地址伪装")
			}
			return nil, errors.New("地址伪装没有开启")
		}
		return [][]string{
			{"firewall-cmd", zoneArg, "--" + op.Op + "-masquerade"},
			{"firewall-cmd", "--permanent", zoneArg, "--" + op.Op + "-masquerade"},
		}, nil
	default:
		return nil, fmt.Errorf("不支持的类型: %q", op.Kind)
	}
	has := slices.Contains(cur, val)
	if adding && has {
		return nil, errors.New("区域里已经有这一项")
	}
	if !adding && !has {
		return nil, errors.New("区域里没有这一项，请刷新后重试")
	}
	verb := op.Op
	if flag == "interface" && adding {
		verb = "change" // 网卡可能已绑在别的区域，change 会把它移过来
	}
	arg := "--" + verb + "-" + flag + "=" + val
	return [][]string{
		{"firewall-cmd", zoneArg, arg},
		{"firewall-cmd", "--permanent", zoneArg, arg},
	}, nil
}

// ApplyFirewalldOn 以 root 在 r 上执行一次修改：重新读取当前配置、校验、检查会不会切断
// SSH（path 非空时），然后逐条执行，遇错即停。
func ApplyFirewalldOn(r RootSys, op FirewalldOp, path *SSHPath) (FirewalldResult, error) {
	res := FirewalldResult{Commands: [][]string{}}
	if !r.HasTool("firewall-cmd") {
		return res, errors.New("firewalld 未安装")
	}
	info := CollectFirewalld(r, func(name string) (string, error) {
		argv := PrivCommands[name]
		return r.RunRoot(15*time.Second, argv[0], argv[1:]...)
	})
	if info.Error != "" {
		return res, fmt.Errorf("读取 firewalld 配置失败: %s", info.Error)
	}
	cmds, err := BuildFirewalld(op, info)
	if err != nil {
		return res, err
	}
	res.Commands = cmds
	if path != nil {
		if w := FirewalldLockout(op, info, *path); w != "" {
			res.Warning = w
			if !op.Confirm {
				return res, fmt.Errorf("%w：%s", ErrLockout, w)
			}
		}
	}
	var out strings.Builder
	for _, c := range cmds {
		o, err := r.RunRoot(60*time.Second, c[0], c[1:]...)
		out.WriteString("$ " + strings.Join(c, " ") + "\n" + o)
		if err != nil {
			res.Output = out.String()
			return res, err
		}
	}
	res.Output, res.Executed = out.String(), true
	return res, nil
}

// ---- 防失联检查 ----

var (
	reRichSource  = regexp.MustCompile(`\bsource\s+(not\s+)?address="([^"]+)"`)
	reRichFamily  = regexp.MustCompile(`\bfamily="(ipv4|ipv6)"`)
	reRichPort    = regexp.MustCompile(`\bport\s+port="([0-9-]+)"\s+protocol="(\w+)"`)
	reRichService = regexp.MustCompile(`\bservice\s+name="([^"]+)"`)
)

// richMatch 粗略判断一条 rich rule 是否作用于 SSH 连接，返回其动作（accept / reject / drop）。
func richMatch(rule string, p SSHPath) (action string, ok bool) {
	if m := reRichFamily.FindStringSubmatch(rule); m != nil && (m[1] == "ipv6") != p.v6() {
		return "", false
	}
	if m := reRichSource.FindStringSubmatch(rule); m != nil {
		if m[1] != "" || !addrCovers(m[2], p.Client) {
			return "", false
		}
	}
	if strings.Contains(rule, "destination") || strings.Contains(rule, "source-port") {
		return "", false
	}
	if m := reRichPort.FindStringSubmatch(rule); m != nil {
		if m[2] != "tcp" || !portCovers(m[1], p.Port) {
			return "", false
		}
	} else if m := reRichService.FindStringSubmatch(rule); m != nil {
		if m[1] != "ssh" || p.Port != 22 {
			return "", false
		}
	} else if strings.Contains(rule, " protocol ") || strings.Contains(rule, "icmp-") || strings.Contains(rule, "forward-port") || strings.Contains(rule, "masquerade") {
		return "", false
	}
	a := reRichAction.FindAllString(rule, -1)
	if len(a) == 0 {
		return "", false
	}
	return a[len(a)-1], true
}

// connZone 是管理连接落在的区域：先按来源地址，再按网卡，最后是默认区域。
func connZone(zones []FirewalldZone, def string, p SSHPath) (FirewalldZone, bool) {
	for _, z := range zones {
		for _, s := range z.Sources {
			if addrCovers(s, p.Client) {
				return z, true
			}
		}
	}
	if p.Iface != "" {
		for _, z := range zones {
			if slices.Contains(z.Interfaces, p.Iface) {
				return z, true
			}
		}
	}
	for _, z := range zones {
		if z.Name == def {
			return z, true
		}
	}
	return FirewalldZone{}, false
}

func firewalldAllowsSSH(info FirewalldInfo, p SSHPath) bool {
	if info.State != "running" {
		return true
	}
	z, ok := connZone(info.Zones, info.DefaultZone, p)
	if !ok {
		return true // 判断不了
	}
	allowed := false
	for _, r := range z.RichRules {
		if a, ok := richMatch(r, p); ok {
			if a == "reject" || a == "drop" {
				return false // firewalld 先处理拒绝类的 rich rule
			}
			if a == "accept" {
				allowed = true
			}
		}
	}
	if allowed || z.Target == "ACCEPT" {
		return true
	}
	if slices.Contains(z.Services, "ssh") && p.Port == 22 {
		return true
	}
	for _, port := range z.Ports {
		if pp, proto, ok := strings.Cut(port, "/"); ok && proto == "tcp" && portCovers(pp, p.Port) {
			return true
		}
	}
	return false
}

func cloneZones(zs []FirewalldZone) []FirewalldZone {
	out := make([]FirewalldZone, len(zs))
	for i, z := range zs {
		c := z
		c.Interfaces, c.Sources, c.Services = slices.Clone(z.Interfaces), slices.Clone(z.Sources), slices.Clone(z.Services)
		c.Ports, c.RichRules = slices.Clone(z.Ports), slices.Clone(z.RichRules)
		out[i] = c
	}
	return out
}

// simulateFirewalld 在内存里套用一次修改。
func simulateFirewalld(op FirewalldOp, info FirewalldInfo) FirewalldInfo {
	n := info
	n.Zones = cloneZones(info.Zones)
	if op.Op == "default-zone" {
		n.DefaultZone = op.Zone
		return n
	}
	val := strings.TrimSpace(op.Value)
	switch op.Kind {
	case "port":
		val, _ = normFwdPort(val)
	case "source":
		val, _ = normFwdSource(val)
	}
	for i := range n.Zones {
		z := &n.Zones[i]
		var list *[]string
		switch op.Kind {
		case "service":
			list = &z.Services
		case "port":
			list = &z.Ports
		case "source":
			list = &z.Sources
		case "interface":
			list = &z.Interfaces
		case "rich-rule":
			list = &z.RichRules
		default:
			continue
		}
		if z.Name == op.Zone {
			if op.Op == "add" && !slices.Contains(*list, val) {
				*list = append(*list, val)
			} else if op.Op == "remove" {
				*list = slices.DeleteFunc(*list, func(s string) bool { return s == val })
			}
		} else if op.Op == "add" && op.Kind == "interface" {
			// change-interface 会把网卡从原区域移走
			*list = slices.DeleteFunc(*list, func(s string) bool { return s == val })
		}
	}
	return n
}

// FirewalldLockout 返回这次修改会不会切断 SSH 连接的说明；空串表示没发现风险。
func FirewalldLockout(op FirewalldOp, info FirewalldInfo, p SSHPath) string {
	if p.Port == 0 || p.local() || !firewalldAllowsSSH(info, p) {
		return ""
	}
	after := simulateFirewalld(op, info)
	if firewalldAllowsSSH(after, p) {
		return ""
	}
	z, _ := connZone(after.Zones, after.DefaultZone, p)
	return fmt.Sprintf("%s（区域 %s）：修改后该区域不再放行 %d/tcp，执行后很可能连不上这台主机。", p.describe(), z.Name, p.Port)
}

// ApplyFirewalld 在本机 root 进程（helper）里执行一次 firewalld 修改。
func ApplyFirewalld(op FirewalldOp) (FirewalldResult, error) {
	if os.Geteuid() != 0 {
		return FirewalldResult{Commands: [][]string{}}, errors.New("需要 root 权限")
	}
	return ApplyFirewalldOn(localRoot{}, op, nil)
}
