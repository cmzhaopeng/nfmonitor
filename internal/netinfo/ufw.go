package netinfo

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ufw 策略管理。
//
// 读：规则来自 ufw 自己写在 /etc/ufw/user.rules、user6.rules 里的 "### tuple ###" 行
// （需要 root，由只读 helper 的 ufw-tuples 命令取回），默认策略与日志级别来自全员可读的
// /etc/default/ufw、/etc/ufw/ufw.conf。tuple 是结构化的，ufw 停用时也在，比解析 status 输出可靠。
//
// 写：前端提交结构化的 UfwOp，由 `pkexec nfmonitor ufw-apply` 起的一次性 root 进程
// 重新校验、生成 ufw 参数并执行（见 ApplyUfw）。只读 helper 不接受任何写命令。

const (
	ufwRulesV4  = "/etc/ufw/user.rules"
	ufwRulesV6  = "/etc/ufw/user6.rules"
	ufwDefaults = "/etc/default/ufw"
	ufwConf     = "/etc/ufw/ufw.conf"
)

// UfwRule 是一条 ufw 用户规则（对应 tuple 的一行；v4 / v6 各一条）。
type UfwRule struct {
	Num      int      `json:"num"` // 在 `ufw status numbered` 里的序号；0 表示 ufw 显示时合并掉的应用规则
	V6       bool     `json:"v6"`
	Route    bool     `json:"route"`  // 转发规则（ufw route ...）
	Action   string   `json:"action"` // allow deny reject limit
	Log      string   `json:"log"`    // "" log log-all
	Dir      string   `json:"dir"`    // in out
	IfaceIn  string   `json:"ifaceIn"`
	IfaceOut string   `json:"ifaceOut"`
	Proto    string   `json:"proto"` // any tcp udp ...
	Src      string   `json:"src"`   // any 或地址 / 网段
	SPort    string   `json:"sport"` // any 或 22、80,443、1000:2000
	SApp     string   `json:"sapp"`
	Dst      string   `json:"dst"`
	DPort    string   `json:"dport"`
	DApp     string   `json:"dapp"`
	Comment  string   `json:"comment"`
	Spec     []string `json:"spec"` // 重建这条规则的 ufw 参数（不含 route 前缀和 comment），用来定位、删除
}

type UfwInfo struct {
	Status     string            `json:"status"`   // active | inactive | ""
	Logging    string            `json:"logging"`  // off low medium high full
	Defaults   map[string]string `json:"defaults"` // incoming outgoing routed → allow deny reject
	IPv6       bool              `json:"ipv6"`
	Rules      []UfwRule         `json:"rules"`
	RulesError string            `json:"rulesError,omitempty"`
}

// readUfwTuples 在 root 侧读两份规则文件里的 tuple 行，每行前缀 v4 / v6。路径固定。
func readUfwTuples() (string, error) {
	var b strings.Builder
	for _, f := range []struct{ path, fam string }{{ufwRulesV4, "v4"}, {ufwRulesV6, "v6"}} {
		data, err := os.ReadFile(f.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", err
		}
		for _, l := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(l, "### tuple ###") {
				b.WriteString(f.fam + " " + strings.TrimSpace(l) + "\n")
			}
		}
	}
	return b.String(), nil
}

// ParseUfwTuples 解析 readUfwTuples 的输出，按 `ufw status numbered` 的规则编号。
func ParseUfwTuples(out string, ipv6 bool) []UfwRule {
	var v4, v6 []UfwRule
	for _, l := range strings.Split(out, "\n") {
		fam, rest, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok || (fam != "v4" && fam != "v6") {
			continue
		}
		r, ok := parseUfwTuple(strings.TrimPrefix(rest, "### tuple ###"))
		if !ok {
			continue
		}
		r.V6 = fam == "v6"
		if r.V6 {
			v6 = append(v6, r)
		} else {
			v4 = append(v4, r)
		}
	}
	rules := v4
	if ipv6 {
		rules = append(rules, v6...)
	}
	numberRules(rules)
	if rules == nil {
		rules = []UfwRule{}
	}
	return rules
}

// numberRules 按 `ufw status numbered` 编号（rules 须是 v4 在前、v6 在后）。
// 与 ufw 的 get_rule_by_number 一致：应用规则按 app tuple 去重后才计数。
func numberRules(rules []UfwRule) {
	seen := map[string]bool{}
	n := 0
	for i := range rules {
		r := &rules[i]
		r.Num = 0
		if r.DApp != "" || r.SApp != "" {
			k := r.appKey()
			if seen[k] {
				continue
			}
			seen[k] = true
		}
		n++
		r.Num = n
	}
}

func parseUfwTuple(s string) (UfwRule, bool) {
	var r UfwRule
	s = strings.TrimSpace(s)
	if body, hx, ok := strings.Cut(s, " comment="); ok {
		s = body
		if b, err := hex.DecodeString(strings.TrimSpace(hx)); err == nil {
			r.Comment = string(b)
		}
	}
	f := strings.Fields(s)
	if len(f) < 6 || len(f) > 9 {
		return r, false
	}
	action := f[0]
	if a, ok := strings.CutPrefix(action, "route:"); ok {
		r.Route, action = true, a
	}
	if a, lg, ok := strings.Cut(action, "_"); ok {
		action, r.Log = a, lg
	}
	r.Action = action
	r.Proto, r.DPort, r.Dst, r.SPort, r.Src = f[1], f[2], f[3], f[4], f[5]
	r.Dir = "in"
	if len(f) >= 8 {
		if f[6] != "-" {
			r.DApp = strings.ReplaceAll(f[6], "%20", " ")
		}
		if f[7] != "-" {
			r.SApp = strings.ReplaceAll(f[7], "%20", " ")
		}
	}
	if len(f) == 7 || len(f) == 9 {
		last := f[len(f)-1]
		r.Dir, _, _ = strings.Cut(last, "_")
		switch {
		case strings.Contains(last, "!"):
			a, b, _ := strings.Cut(last, "!")
			_, r.IfaceIn, _ = strings.Cut(a, "_")
			_, r.IfaceOut, _ = strings.Cut(b, "_")
		case strings.HasPrefix(last, "in_"):
			r.IfaceIn = last[3:]
		case strings.HasPrefix(last, "out_"):
			r.IfaceOut = last[4:]
		}
	}
	for _, p := range []*string{&r.Src, &r.Dst} {
		if *p == "0.0.0.0/0" || *p == "::/0" {
			*p = "any"
		} else {
			*p = strings.TrimSuffix(strings.TrimSuffix(*p, "/32"), "/128")
		}
	}
	r.Spec = r.specArgs(true)
	return r, true
}

func (r UfwRule) appKey() string {
	d, s := r.DApp, r.SApp
	if d == "" {
		d = r.DPort
	}
	if s == "" {
		s = r.SPort
	}
	return strings.Join([]string{d, r.Dst, s, r.Src, r.Dir, r.IfaceIn, r.IfaceOut, strconv.FormatBool(r.V6)}, " ")
}

// specArgs 生成 ufw 规则参数（不含 route 前缀和 comment）。withAction=false 时去掉动作与日志，
// 得到 ufw 判定"同一条规则"用的匹配键（ufw 对只差动作 / 日志 / 备注的规则做原地更新）。
func (r UfwRule) specArgs(withAction bool) []string {
	var a []string
	if withAction {
		a = append(a, r.Action)
	}
	if r.Route {
		if r.IfaceIn != "" {
			a = append(a, "in", "on", r.IfaceIn)
		}
		if r.IfaceOut != "" {
			a = append(a, "out", "on", r.IfaceOut)
		}
	} else {
		a = append(a, r.Dir)
		if r.Dir == "in" && r.IfaceIn != "" {
			a = append(a, "on", r.IfaceIn)
		} else if r.Dir == "out" && r.IfaceOut != "" {
			a = append(a, "on", r.IfaceOut)
		}
	}
	if withAction && r.Log != "" {
		a = append(a, r.Log)
	}
	if r.Proto != "" && r.Proto != "any" && r.DApp == "" && r.SApp == "" {
		a = append(a, "proto", r.Proto)
	}
	end := func(kw, addr, port, app string) {
		a = append(a, kw, orAny(addr))
		if app != "" {
			a = append(a, "app", app)
		} else if port != "" && port != "any" {
			a = append(a, "port", port)
		}
	}
	end("from", r.Src, r.SPort, r.SApp)
	end("to", r.Dst, r.DPort, r.DApp)
	return a
}

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

// ---- 默认策略、日志级别（全员可读的配置文件） ----

// ReadUfwConfig 读默认策略、日志级别、是否启用 IPv6、开机是否启用。
func ReadUfwConfig() (defaults map[string]string, logging string, ipv6 bool, enabled string) {
	defaults = map[string]string{}
	ipv6 = true
	pol := map[string]string{"DROP": "deny", "ACCEPT": "allow", "REJECT": "reject"}
	for k, v := range readShellVars(ufwDefaults) {
		v = strings.ToUpper(v)
		switch k {
		case "DEFAULT_INPUT_POLICY":
			defaults["incoming"] = pol[v]
		case "DEFAULT_OUTPUT_POLICY":
			defaults["outgoing"] = pol[v]
		case "DEFAULT_FORWARD_POLICY":
			defaults["routed"] = pol[v]
		case "IPV6":
			ipv6 = v == "YES"
		}
	}
	conf := readShellVars(ufwConf)
	logging = strings.ToLower(conf["LOGLEVEL"])
	if logging == "" {
		logging = "low"
	}
	switch strings.ToLower(conf["ENABLED"]) {
	case "yes":
		enabled = "active"
	case "no":
		enabled = "inactive"
	}
	return
}

func readShellVars(path string) map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			m[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return m
}

// ---- 写操作 ----

// UfwOp 是前端提交的一次修改。
type UfwOp struct {
	Op        string   `json:"op"`                  // add | delete | replace | move | enable | disable | default | logging
	Rule      *UfwRule `json:"rule,omitempty"`      // add / replace：新规则（只用其中的可编辑字段）
	Position  int      `json:"position,omitempty"`  // add：插到第 N 条之前；0 = 追加到末尾
	Old       *UfwRule `json:"old,omitempty"`       // delete / replace / move：现有规则，按 Route + Spec 定位
	Before    *UfwRule `json:"before,omitempty"`    // move：移到这条规则之前；nil = 移到末尾
	Direction string   `json:"direction,omitempty"` // default：incoming outgoing routed
	Policy    string   `json:"policy,omitempty"`    // default：allow deny reject
	Level     string   `json:"level,omitempty"`     // logging：off low medium high full
}

type UfwResult struct {
	Commands [][]string `json:"commands"`
	Output   string     `json:"output"`
	Executed bool       `json:"executed"`
}

var (
	reIface = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}\+?$`)
	rePorts = regexp.MustCompile(`^\d{1,5}([:-]\d{1,5})?(,\d{1,5}([:-]\d{1,5})?)*$`)
)

// NormalizeUfwRule 校验前端填的规则并转成规范形式；所有写操作都只经过它生成参数。
func NormalizeUfwRule(in UfwRule) (UfwRule, error) {
	r := UfwRule{Route: in.Route, Log: in.Log, Comment: strings.TrimSpace(in.Comment)}
	switch in.Action {
	case "allow", "deny", "reject", "limit":
		r.Action = in.Action
	default:
		return r, fmt.Errorf("动作无效: %q", in.Action)
	}
	if r.Log != "" && r.Log != "log" && r.Log != "log-all" {
		return r, fmt.Errorf("日志选项无效: %q", in.Log)
	}
	if r.Route {
		r.Dir = "in"
		if in.IfaceOut != "" && in.IfaceIn == "" {
			r.Dir = "out" // ufw 只有出网卡的转发规则记为 out
		}
	} else {
		switch in.Dir {
		case "in", "out":
			r.Dir = in.Dir
		default:
			return r, fmt.Errorf("方向无效: %q", in.Dir)
		}
	}
	for _, p := range []struct {
		dst  *string
		v    string
		want bool
	}{{&r.IfaceIn, in.IfaceIn, r.Route || r.Dir == "in"}, {&r.IfaceOut, in.IfaceOut, r.Route || r.Dir == "out"}} {
		v := strings.TrimSpace(p.v)
		if v == "" || v == "any" || !p.want {
			continue
		}
		if !reIface.MatchString(v) {
			return r, fmt.Errorf("网卡名无效: %q", v)
		}
		*p.dst = v
	}
	switch in.Proto {
	case "", "any":
		r.Proto = "any"
	case "tcp", "udp", "esp", "ah", "gre", "igmp", "ipv6":
		r.Proto = in.Proto
	default:
		return r, fmt.Errorf("协议无效: %q", in.Proto)
	}
	var fam [2]string
	for i, p := range []struct {
		dst *string
		v   string
		nm  string
	}{{&r.Src, in.Src, "源地址"}, {&r.Dst, in.Dst, "目的地址"}} {
		a, f, err := normAddr(p.v)
		if err != nil {
			return r, fmt.Errorf("%s无效: %w", p.nm, err)
		}
		*p.dst, fam[i] = a, f
	}
	if fam[0] != "" && fam[1] != "" && fam[0] != fam[1] {
		return r, errors.New("源地址与目的地址一个是 IPv4、一个是 IPv6，不能写在同一条规则里")
	}
	for _, p := range []struct {
		dst *string
		v   string
		nm  string
	}{{&r.SPort, in.SPort, "源端口"}, {&r.DPort, in.DPort, "目的端口"}} {
		v, err := normPorts(p.v)
		if err != nil {
			return r, fmt.Errorf("%s无效: %w", p.nm, err)
		}
		if v == "any" {
			*p.dst = v
			continue
		}
		if r.Proto != "any" && r.Proto != "tcp" && r.Proto != "udp" {
			return r, fmt.Errorf("协议 %s 没有端口，%s请留空", r.Proto, p.nm)
		}
		if strings.ContainsAny(v, ",:") && r.Proto == "any" {
			return r, fmt.Errorf("%s是多个端口或端口范围时，协议必须选 TCP 或 UDP", p.nm)
		}
		*p.dst = v
	}
	if n := len([]rune(r.Comment)); n > 120 {
		return r, errors.New("备注太长（最多 120 个字）")
	}
	for _, c := range r.Comment {
		if unicode.IsControl(c) {
			return r, errors.New("备注里不能有换行等控制字符")
		}
	}
	if in.SApp != "" || in.DApp != "" {
		return r, errors.New("暂不支持编辑应用配置（app）规则")
	}
	r.Spec = r.specArgs(true)
	return r, nil
}

func normAddr(s string) (addr, fam string, err error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "any") || strings.EqualFold(s, "anywhere") {
		return "any", "", nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", "", fmt.Errorf("%q 不是合法的地址或网段", s)
		}
		p = p.Masked()
		if p.IsSingleIP() {
			return p.Addr().String(), family(p.Addr()), nil
		}
		return p.String(), family(p.Addr()), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", "", fmt.Errorf("%q 不是合法的地址或网段", s)
	}
	return a.String(), family(a), nil
}

func family(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "v4"
	}
	return "v6"
}

func normPorts(s string) (string, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	if s == "" || strings.EqualFold(s, "any") {
		return "any", nil
	}
	if !rePorts.MatchString(s) {
		return "", fmt.Errorf("%q：写成 22、80,443 或 1000:2000", s)
	}
	s = strings.ReplaceAll(s, "-", ":")
	items := strings.Split(s, ",")
	if len(items) > 15 {
		return "", errors.New("最多 15 个端口")
	}
	for _, it := range items {
		lo, hi, rng := strings.Cut(it, ":")
		a, _ := strconv.Atoi(lo)
		b := a
		if rng {
			b, _ = strconv.Atoi(hi)
		}
		if a < 1 || b > 65535 || a > b {
			return "", fmt.Errorf("端口 %q 超出 1-65535 或范围颠倒", it)
		}
	}
	return s, nil
}

// ufwCmd 拼一条规则命令。--force 只能放在最前面，而且放了之后 ufw 不再把裸的
// allow/deny/reject 识别成规则命令，所以只给 delete 加（删除时不弹确认）。
func ufwCmd(route bool, pre []string, body []string) []string {
	c := []string{"ufw"}
	if len(pre) > 0 && pre[0] == "delete" {
		c = append(c, "--force")
	}
	if route {
		c = append(c, "route")
	}
	return append(append(c, pre...), body...)
}

func withComment(r UfwRule) []string {
	b := append([]string{}, r.Spec...)
	if r.Comment != "" {
		b = append(b, "comment", r.Comment)
	}
	return b
}

func findRule(cur []UfwRule, old *UfwRule) (UfwRule, bool) {
	if old == nil {
		return UfwRule{}, false
	}
	want := strings.Join(old.Spec, "\x00")
	var best UfwRule
	found := false
	for _, r := range cur {
		if r.Route == old.Route && strings.Join(r.Spec, "\x00") == want && (!found || (r.Num > 0 && (best.Num == 0 || r.Num < best.Num))) {
			best, found = r, true
		}
	}
	return best, found
}

// BuildUfw 把一次修改翻译成要执行的 ufw 命令。cur 是当前规则；verify 为真时
// delete / replace 的目标必须在 cur 里（root 侧执行前一定校验）。
func BuildUfw(op UfwOp, cur []UfwRule, verify bool) ([][]string, error) {
	maxNum := 0
	for _, r := range cur {
		maxNum = max(maxNum, r.Num)
	}
	locate := func() (UfwRule, error) {
		if op.Old == nil || len(op.Old.Spec) == 0 {
			return UfwRule{}, errors.New("缺少要修改的规则")
		}
		if r, ok := findRule(cur, op.Old); ok {
			return r, nil
		}
		if verify {
			return UfwRule{}, errors.New("规则已经变化，找不到要修改的那一条，请刷新后重试")
		}
		return *op.Old, nil
	}
	switch op.Op {
	case "enable":
		return [][]string{{"ufw", "--force", "enable"}}, nil
	case "disable":
		return [][]string{{"ufw", "disable"}}, nil
	case "default":
		if op.Direction != "incoming" && op.Direction != "outgoing" && op.Direction != "routed" {
			return nil, fmt.Errorf("方向无效: %q", op.Direction)
		}
		if op.Policy != "allow" && op.Policy != "deny" && op.Policy != "reject" {
			return nil, fmt.Errorf("策略无效: %q", op.Policy)
		}
		return [][]string{{"ufw", "default", op.Policy, op.Direction}}, nil
	case "logging":
		switch op.Level {
		case "off", "low", "medium", "high", "full":
			return [][]string{{"ufw", "logging", op.Level}}, nil
		}
		return nil, fmt.Errorf("日志级别无效: %q", op.Level)
	case "delete":
		old, err := locate()
		if err != nil {
			return nil, err
		}
		return [][]string{ufwCmd(old.Route, []string{"delete"}, old.Spec)}, nil
	case "move":
		return planMove(cur, op.Old, op.Before)
	case "add", "replace":
		if op.Rule == nil {
			return nil, errors.New("缺少规则")
		}
		nr, err := NormalizeUfwRule(*op.Rule)
		if err != nil {
			return nil, err
		}
		if op.Op == "add" {
			var pre []string
			if op.Position > 0 && (cur == nil || op.Position <= maxNum) {
				pre = []string{"insert", strconv.Itoa(op.Position)}
			}
			return [][]string{ufwCmd(nr.Route, pre, withComment(nr))}, nil
		}
		old, err := locate()
		if err != nil {
			return nil, err
		}
		// 只差动作 / 日志 / 备注：ufw 会原地更新，位置不变。
		if old.Route == nr.Route && strings.Join(old.specArgs(false), " ") == strings.Join(nr.specArgs(false), " ") {
			if old.Action == nr.Action && old.Log == nr.Log && old.Comment == nr.Comment {
				return nil, errors.New("规则没有变化")
			}
			return [][]string{ufwCmd(nr.Route, nil, withComment(nr))}, nil
		}
		// 否则先在原位置插入新规则，再删旧规则；插入失败就什么都没改。
		var pre []string
		if old.Num > 0 {
			pre = []string{"insert", strconv.Itoa(old.Num)}
		}
		return [][]string{
			ufwCmd(nr.Route, pre, withComment(nr)),
			ufwCmd(old.Route, []string{"delete"}, old.Spec),
		}, nil
	}
	return nil, fmt.Errorf("未知操作: %q", op.Op)
}

// ApplyUfw 在 root 进程里执行一次修改：重新读取当前规则、校验、逐条执行，遇错即停。
func ApplyUfw(op UfwOp) (UfwResult, error) {
	res := UfwResult{Commands: [][]string{}}
	if os.Geteuid() != 0 {
		return res, errors.New("需要 root 权限")
	}
	if ToolPath("ufw") == "" {
		return res, errors.New("ufw 未安装")
	}
	raw, err := readUfwTuples()
	if err != nil {
		return res, fmt.Errorf("读取 ufw 规则失败: %w", err)
	}
	_, _, ipv6, _ := ReadUfwConfig()
	cur := ParseUfwTuples(raw, ipv6)
	cmds, err := BuildUfw(op, cur, true)
	if err != nil {
		return res, err
	}
	res.Commands = cmds
	var out strings.Builder
	run := func(c []string) error {
		o, err := Run(30*time.Second, c[0], c[1:]...)
		out.WriteString("$ " + strings.Join(c, " ") + "\n" + o)
		if err == nil && strings.HasPrefix(strings.TrimSpace(o), "ERROR") {
			err = errors.New(strings.TrimSpace(o))
		}
		return err
	}
	for i, c := range cmds {
		if err := run(c); err != nil {
			// 移动是先删后插：删掉之后插入失败，就把原规则追加回末尾，至少不丢规则。
			if op.Op == "move" && i > 0 {
				if old, ok := findRule(cur, op.Old); ok {
					if rerr := run(ufwCmd(old.Route, nil, withComment(old))); rerr == nil {
						err = fmt.Errorf("%w（原规则已追加回末尾，请检查顺序）", err)
					} else {
						err = fmt.Errorf("%w；恢复原规则也失败了: %v", err, rerr)
					}
				}
			}
			res.Output = out.String()
			return res, err
		}
	}
	res.Output, res.Executed = out.String(), true
	return res, nil
}

// ---- 调整顺序 ----

func groupKey(r UfwRule) string {
	k := strings.Join(r.Spec, " ")
	if r.Route {
		k = "route " + k
	}
	return k
}

// ufwGroups 把 v4 / v6 各一条、spec 相同的规则归为一组（与界面上的一行对应），按首个序号排序。
func ufwGroups(rules []UfwRule) (order []string, byKey map[string][]UfwRule) {
	byKey = map[string][]UfwRule{}
	first := map[string]int{}
	for _, r := range rules {
		k := groupKey(r)
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
			first[k] = 1 << 30
		}
		byKey[k] = append(byKey[k], r)
		if r.Num > 0 && r.Num < first[k] {
			first[k] = r.Num
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return first[order[i]] < first[order[j]] })
	return
}

// planMove 把一组规则（含 v4、v6 两份）移到另一组之前。ufw 没有"移动"命令，只能先删再插；
// v4、v6 是两张独立的表，序号也分开算，所以把两份分别用显式的 0.0.0.0/0、::/0 插回各自表里
// 合适的位置。整个过程在内存里模拟一遍算出每一步的序号，预览与执行用的是同一份命令。
// 规则的优先级只在同一方向（入站 / 出站 / 转发）、同一 IP 版本内有意义，其余相对顺序不影响匹配。
func planMove(cur []UfwRule, old, before *UfwRule) ([][]string, error) {
	if old == nil || len(old.Spec) == 0 {
		return nil, errors.New("缺少要移动的规则")
	}
	order, groups := ufwGroups(cur)
	gk := groupKey(*old)
	g, ok := groups[gk]
	if !ok {
		return nil, errors.New("规则已经变化，找不到要移动的那一条，请刷新后重试")
	}
	if g[0].DApp != "" || g[0].SApp != "" {
		return nil, errors.New("应用配置（app）规则请用命令行调整顺序")
	}
	bk := ""
	if before != nil {
		bk = groupKey(*before)
		if _, ok := groups[bk]; !ok {
			return nil, errors.New("目标位置的规则已经变化，请刷新后重试")
		}
		if bk == gk {
			return nil, errors.New("位置没有变化")
		}
	}
	// 目标之后（含目标）的各组，按顺序；移动的组本身除外。
	var after []string
	if bk != "" {
		for i, k := range order {
			if k == bk {
				for _, k2 := range order[i:] {
					if k2 != gk {
						after = append(after, k2)
					}
				}
				break
			}
		}
	}
	if pos := slices.Index(order, gk); pos >= 0 {
		next := ""
		if pos+1 < len(order) {
			next = order[pos+1]
		}
		if next == bk {
			return nil, errors.New("位置没有变化")
		}
	}

	var v4, v6 []UfwRule
	var mv4, mv6 *UfwRule
	for _, r := range cur {
		r := r
		switch {
		case groupKey(r) == gk && r.V6:
			mv6 = &r
		case groupKey(r) == gk:
			mv4 = &r
		case r.V6:
			v6 = append(v6, r)
		default:
			v4 = append(v4, r)
		}
	}
	renumber := func() []UfwRule {
		all := append(append([]UfwRule{}, v4...), v6...)
		numberRules(all)
		copy(v4, all[:len(v4)])
		copy(v6, all[len(v4):])
		return all
	}
	renumber()
	cmds := [][]string{ufwCmd(g[0].Route, []string{"delete"}, g[0].Spec)}
	place := func(list *[]UfwRule, m UfwRule, isV6 bool) {
		// 目标在这张表里的位置：目标组（或其后第一个在这张表里有规则的组）的那一条之前。
		idx := -1
		for _, k := range after {
			for i, r := range *list {
				if groupKey(r) == k {
					idx = i
					break
				}
			}
			if idx >= 0 {
				break
			}
		}
		fam := m
		if fam.Src == "any" && fam.Dst == "any" {
			fam.Src = map[bool]string{false: "0.0.0.0/0", true: "::/0"}[isV6]
		}
		body := fam.specArgs(true)
		if m.Comment != "" {
			body = append(body, "comment", m.Comment)
		}
		var pre []string
		if idx >= 0 {
			pre = []string{"insert", strconv.Itoa((*list)[idx].Num)}
			*list = slices.Insert(*list, idx, m)
		} else {
			*list = append(*list, m)
		}
		cmds = append(cmds, ufwCmd(m.Route, pre, body))
		renumber()
	}
	if mv4 != nil {
		place(&v4, *mv4, false)
	}
	if mv6 != nil {
		place(&v6, *mv6, true)
	}
	return cmds, nil
}
