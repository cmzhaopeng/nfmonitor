package netinfo

import (
	"os"
	"strings"
	"testing"
)

func fixtureRules(t *testing.T) []UfwRule {
	b, err := os.ReadFile("../../testdata/fixture/ufw-tuples.txt")
	if err != nil {
		t.Fatal(err)
	}
	return ParseUfwTuples(string(b), true)
}

func TestParseUfwTuples(t *testing.T) {
	rs := fixtureRules(t)
	if len(rs) != 14 {
		t.Fatalf("got %d rules", len(rs))
	}
	r := rs[0]
	if r.Num != 1 || r.Action != "allow" || r.Proto != "tcp" || r.DPort != "22" || r.Src != "192.168.1.0/24" || r.Dst != "any" || r.Comment != "SSH from office" || r.V6 {
		t.Errorf("rule 1 = %+v", r)
	}
	if got := strings.Join(r.Spec, " "); got != "allow in proto tcp from 192.168.1.0/24 to any port 22" {
		t.Errorf("spec 1 = %q", got)
	}
	if rs[1].Action != "limit" || rs[1].Comment != "SSH 来自 VPN" {
		t.Errorf("rule 2 = %+v", rs[1])
	}
	if r := rs[3]; r.IfaceIn != "br0" || strings.Join(r.Spec, " ") != "allow in on br0 from any to any" {
		t.Errorf("iface rule = %+v", r)
	}
	if r := rs[5]; !r.Route || r.Dir != "out" || r.IfaceOut != "br0" || strings.Join(r.Spec, " ") != "allow out on br0 from any to any" {
		t.Errorf("route out rule = %+v", r)
	}
	if r := rs[6]; r.Log != "log" || r.Dir != "out" || strings.Join(r.Spec, " ") != "deny out on eth0 log proto udp from any to any port 53" {
		t.Errorf("log rule = %+v %q", r, r.Spec)
	}
	if r := rs[7]; r.Src != "203.0.113.7" || r.Action != "reject" {
		t.Errorf("host rule = %+v", r)
	}
	if r := rs[8]; r.DApp != "OpenSSH" || strings.Join(r.Spec, " ") != "allow in from any to any app OpenSSH" {
		t.Errorf("app rule = %+v %q", r, r.Spec)
	}
	// v4 / v6 的同一条规则 spec 相同，序号接着 v4 往下排。
	if r := rs[9]; !r.V6 || r.Num != 10 || strings.Join(r.Spec, " ") != strings.Join(rs[2].Spec, " ") {
		t.Errorf("v6 twin = %+v", r)
	}
	if r := rs[13]; r.Src != "2001:db8:a::/48" || r.Num != 14 {
		t.Errorf("v6 rule = %+v", r)
	}
	if n := len(ParseUfwTuples("v4 ### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\nv6 ### tuple ### allow tcp 22 ::/0 any ::/0 in\n", false)); n != 1 {
		t.Errorf("IPV6=no should drop v6 rules, got %d", n)
	}
}

func TestNormalizeUfwRule(t *testing.T) {
	ok := []struct {
		in   UfwRule
		spec string
	}{
		{UfwRule{Action: "allow", Dir: "in", Proto: "tcp", DPort: "22", Src: "10.0.0.5/24"}, "allow in proto tcp from 10.0.0.0/24 to any port 22"},
		{UfwRule{Action: "deny", Dir: "out", IfaceOut: "wlan0", Proto: "udp", DPort: "1000-2000", Log: "log"}, "deny out on wlan0 log proto udp from any to any port 1000:2000"},
		{UfwRule{Action: "allow", Route: true, IfaceIn: "br0", IfaceOut: "eth0"}, "allow in on br0 out on eth0 from any to any"},
		{UfwRule{Action: "reject", Dir: "in", Src: "2001:db8::1/128", DPort: "443"}, "reject in from 2001:db8::1 to any port 443"},
		{UfwRule{Action: "allow", Dir: "in", IfaceOut: "ignored0"}, "allow in from any to any"},
	}
	for _, c := range ok {
		r, err := NormalizeUfwRule(c.in)
		if err != nil {
			t.Errorf("%+v: %v", c.in, err)
			continue
		}
		if got := strings.Join(r.Spec, " "); got != c.spec {
			t.Errorf("%+v: spec %q, want %q", c.in, got, c.spec)
		}
	}
	bad := []UfwRule{
		{Action: "accept", Dir: "in"},
		{Action: "allow", Dir: "up"},
		{Action: "allow", Dir: "in", Src: "10.0.0.300"},
		{Action: "allow", Dir: "in", Src: "10.0.0.1", Dst: "::1"},
		{Action: "allow", Dir: "in", DPort: "80,443"},              // 多端口要指定协议
		{Action: "allow", Dir: "in", Proto: "tcp", DPort: "70000"}, // 超范围
		{Action: "allow", Dir: "in", Proto: "tcp", DPort: "22; rm -rf /"},
		{Action: "allow", Dir: "in", Proto: "esp", DPort: "22"},
		{Action: "allow", Dir: "in", IfaceIn: "eth0 out"},
		{Action: "allow", Dir: "in", Comment: "a\nb"},
		{Action: "allow", Dir: "in", Log: "verbose"},
	}
	for _, in := range bad {
		if _, err := NormalizeUfwRule(in); err == nil {
			t.Errorf("%+v: expected error", in)
		}
	}
}

func TestBuildUfw(t *testing.T) {
	cur := fixtureRules(t)
	join := func(cs [][]string) string {
		var s []string
		for _, c := range cs {
			s = append(s, strings.Join(c, " "))
		}
		return strings.Join(s, " ; ")
	}
	cases := []struct {
		op   UfwOp
		want string
	}{
		{UfwOp{Op: "add", Rule: &UfwRule{Action: "allow", Dir: "in", Proto: "tcp", DPort: "8080", Comment: "web dev"}},
			"ufw allow in proto tcp from any to any port 8080 comment web dev"},
		{UfwOp{Op: "add", Position: 2, Rule: &UfwRule{Action: "deny", Dir: "in", Src: "198.51.100.0/24"}},
			"ufw insert 2 deny in from 198.51.100.0/24 to any"},
		{UfwOp{Op: "add", Position: 99, Rule: &UfwRule{Action: "deny", Dir: "in", Src: "198.51.100.0/24"}}, // 超过末尾 → 追加
			"ufw deny in from 198.51.100.0/24 to any"},
		{UfwOp{Op: "add", Position: 1, Rule: &UfwRule{Action: "allow", Route: true, IfaceIn: "docker0"}},
			"ufw route insert 1 allow in on docker0 from any to any"},
		{UfwOp{Op: "delete", Old: &cur[4]}, "ufw --force route delete allow in on br0 from any to any"},
		// 只改动作 / 备注 → 原地更新
		{UfwOp{Op: "replace", Old: &cur[0], Rule: &UfwRule{Action: "limit", Dir: "in", Proto: "tcp", DPort: "22", Src: "192.168.1.0/24", Comment: "SSH from office"}},
			"ufw limit in proto tcp from 192.168.1.0/24 to any port 22 comment SSH from office"},
		// 改了匹配条件 → 原位置插入新的，再删旧的
		{UfwOp{Op: "replace", Old: &cur[2], Rule: &UfwRule{Action: "allow", Dir: "in", Proto: "tcp", DPort: "80,443,8443"}},
			"ufw insert 3 allow in proto tcp from any to any port 80,443,8443 ; ufw --force delete allow in proto tcp from any to any port 80,443"},
		{UfwOp{Op: "default", Direction: "incoming", Policy: "deny"}, "ufw default deny incoming"},
		{UfwOp{Op: "logging", Level: "medium"}, "ufw logging medium"},
		{UfwOp{Op: "enable"}, "ufw --force enable"},
	}
	for _, c := range cases {
		got, err := BuildUfw(c.op, cur, true)
		if err != nil {
			t.Errorf("%s: %v", c.op.Op, err)
			continue
		}
		if join(got) != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.op.Op, join(got), c.want)
		}
	}
	// 当前规则里找不到的目标一律拒绝（root 侧不信任前端传来的 spec）。
	forged := UfwRule{Spec: []string{"allow", "in", "from", "any", "to", "any", "port", "1"}}
	if _, err := BuildUfw(UfwOp{Op: "delete", Old: &forged}, cur, true); err == nil {
		t.Error("forged delete accepted")
	}
	same := cur[0]
	if _, err := BuildUfw(UfwOp{Op: "replace", Old: &same, Rule: &UfwRule{Action: "allow", Dir: "in", Proto: "tcp", DPort: "22", Src: "192.168.1.0/24", Comment: "SSH from office"}}, cur, true); err == nil {
		t.Error("no-op replace should error")
	}
	for _, op := range []UfwOp{{Op: "default", Direction: "incoming", Policy: "drop"}, {Op: "logging", Level: "debug"}, {Op: "reset"}} {
		if _, err := BuildUfw(op, cur, true); err == nil {
			t.Errorf("%+v accepted", op)
		}
	}
}

func TestPlanMove(t *testing.T) {
	cur := fixtureRules(t)
	byNum := func(n int) *UfwRule {
		for i := range cur {
			if cur[i].Num == n {
				return &cur[i]
			}
		}
		t.Fatalf("no rule %d", n)
		return nil
	}
	join := func(cs [][]string) string {
		var s []string
		for _, c := range cs {
			s = append(s, strings.Join(c, " "))
		}
		return strings.Join(s, " ; ")
	}
	cases := []struct {
		name        string
		old, before int // before=0 → 末尾
		want        string
	}{
		// v4+v6 的组移到最前：v4 插到 #1，v6 插到 v6 表里原来排在它后面的第一条（br0 的 v6）之前。
		{"twin to top", 3, 1,
			"ufw --force delete allow in proto tcp from any to any port 80,443 ; " +
				"ufw insert 1 allow in proto tcp from 0.0.0.0/0 to any port 80,443 ; " +
				"ufw insert 10 allow in proto tcp from ::/0 to any port 80,443"},
		{"twin to end", 4, 0,
			"ufw --force delete allow in on br0 from any to any ; " +
				"ufw allow in on br0 from 0.0.0.0/0 to any ; ufw allow in on br0 from ::/0 to any"},
		{"v4 down one, keeps comment", 1, 3,
			"ufw --force delete allow in proto tcp from 192.168.1.0/24 to any port 22 ; " +
				"ufw insert 2 allow in proto tcp from 192.168.1.0/24 to any port 22 comment SSH from office"},
		{"v6 only up", 14, 3,
			"ufw --force delete allow in proto tcp from 2001:db8:a::/48 to any port 3389 ; " +
				"ufw insert 10 allow in proto tcp from 2001:db8:a::/48 to any port 3389 comment RDP-test"},
		{"route rule", 6, 5,
			"ufw --force route delete allow out on br0 from any to any ; " +
				"ufw route insert 5 allow out on br0 from 0.0.0.0/0 to any"},
	}
	for _, c := range cases {
		op := UfwOp{Op: "move", Old: byNum(c.old)}
		if c.before > 0 {
			op.Before = byNum(c.before)
		}
		got, err := BuildUfw(op, cur, true)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if join(got) != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, join(got), c.want)
		}
	}
	for _, c := range []struct{ old, before int }{{14, 0}, {1, 2}, {3, 3}, {9, 1}} { // 已在末尾 / 已在目标前 / 自己 / app 规则
		op := UfwOp{Op: "move", Old: byNum(c.old)}
		if c.before > 0 {
			op.Before = byNum(c.before)
		}
		if _, err := BuildUfw(op, cur, true); err == nil {
			t.Errorf("move %d before %d: expected error", c.old, c.before)
		}
	}
}
