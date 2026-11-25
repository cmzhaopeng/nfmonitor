package netinfo

import (
	"strings"
	"testing"
)

func TestParseSSHConnection(t *testing.T) {
	p, ok := ParseSSHConnection("10.0.0.5 51234 10.0.0.1 22")
	if !ok || p.Client != "10.0.0.5" || p.Server != "10.0.0.1" || p.Port != 22 {
		t.Fatalf("got %+v %v", p, ok)
	}
	p, ok = ParseSSHConnection("::ffff:192.168.1.2 1 ::ffff:192.168.1.1 2222")
	if !ok || p.Client != "192.168.1.2" || p.Port != 2222 || p.v6() {
		t.Fatalf("v4-mapped: %+v %v", p, ok)
	}
	for _, bad := range []string{"", "1.2.3.4 1 2", "x 1 1.2.3.4 22", "1.2.3.4 1 1.2.3.5 ssh"} {
		if _, ok := ParseSSHConnection(bad); ok {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestCovers(t *testing.T) {
	for _, c := range []struct {
		spec, ip string
		want     bool
	}{{"any", "1.2.3.4", true}, {"10.0.0.0/8", "10.1.2.3", true}, {"10.0.0.0/8", "11.0.0.1", false}, {"1.2.3.4", "1.2.3.4", true}, {"2001:db8::/32", "2001:db8::1", true}} {
		if got := addrCovers(c.spec, c.ip); got != c.want {
			t.Errorf("addrCovers(%q,%q)=%v", c.spec, c.ip, got)
		}
	}
	for _, c := range []struct {
		spec string
		port int
		want bool
	}{{"any", 22, true}, {"22", 22, true}, {"80,443", 22, false}, {"1000:2000", 1500, true}, {"20-30", 22, true}, {"23", 22, false}} {
		if got := portCovers(c.spec, c.port); got != c.want {
			t.Errorf("portCovers(%q,%d)=%v", c.spec, c.port, got)
		}
	}
}

var sshPath = SSHPath{Client: "10.0.0.5", Server: "10.0.0.1", Port: 22}

func allow22(v6 bool) UfwRule {
	return UfwRule{Num: 1, V6: v6, Action: "allow", Dir: "in", Proto: "tcp", Src: "any", Dst: "any", DPort: "22", Spec: []string{"allow", "22/tcp"}}
}

func TestUfwLockout(t *testing.T) {
	cur := []UfwRule{allow22(false), allow22(true)}
	defs := map[string]string{"incoming": "deny"}

	// 删除唯一放行 22 的规则：会失联
	op := UfwOp{Op: "delete", Old: &cur[0]}
	if w := UfwLockout(op, cur, defs, "active", sshPath); w == "" {
		t.Error("deleting the ssh rule should warn")
	}
	// ufw 未启用时删除：不影响
	if w := UfwLockout(op, cur, defs, "inactive", sshPath); w != "" {
		t.Errorf("inactive ufw should not warn: %s", w)
	}
	// 没有规则、默认拒绝时启用 ufw：会失联
	if w := UfwLockout(UfwOp{Op: "enable"}, nil, defs, "inactive", sshPath); w == "" {
		t.Error("enabling with no ssh rule should warn")
	}
	// 有放行规则时启用：没问题
	if w := UfwLockout(UfwOp{Op: "enable"}, cur, defs, "inactive", sshPath); w != "" {
		t.Errorf("enable with ssh rule: %s", w)
	}
	// 在放行规则之前插入一条拒绝本客户端网段的规则：会失联
	deny := UfwRule{Action: "deny", Dir: "in", Proto: "any", Src: "10.0.0.0/24", Dst: "any", DPort: "any"}
	if w := UfwLockout(UfwOp{Op: "add", Rule: &deny, Position: 1}, cur, defs, "active", sshPath); w == "" {
		t.Error("inserting deny before allow should warn")
	}
	// 追加到末尾：前面的放行规则先命中，没问题
	if w := UfwLockout(UfwOp{Op: "add", Rule: &deny}, cur, defs, "active", sshPath); w != "" {
		t.Errorf("appending deny after allow: %s", w)
	}
	// 默认入站允许、没有规则时改成拒绝：会失联
	if w := UfwLockout(UfwOp{Op: "default", Direction: "incoming", Policy: "deny"}, nil, map[string]string{"incoming": "allow"}, "active", sshPath); w == "" {
		t.Error("default deny without ssh rule should warn")
	}
	// 从主机自己连过来（走 lo）：ufw 总是放行回环，不警告
	if w := UfwLockout(op, cur, defs, "active", SSHPath{Client: "127.0.0.1", Server: "127.0.0.1", Port: 22}); w != "" {
		t.Error("loopback should not warn")
	}
	// 不知道 SSH 连接（本机）时不检查
	if w := UfwLockout(op, cur, defs, "active", SSHPath{}); w != "" {
		t.Error("no ssh path should not warn")
	}
}

const firewalldListAll = `public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources: 
  services: dhcpv6-client ssh
  ports: 8080/tcp
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
	rule family="ipv4" source address="192.168.9.0/24" reject

trusted
  target: ACCEPT
  icmp-block-inversion: no
  interfaces: 
  sources: 10.9.0.0/16
  services: 
  ports: 
  protocols: 
  masquerade: yes
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
`

func TestParseFirewalldZones(t *testing.T) {
	zs := ParseFirewalldZones(firewalldListAll, "public")
	if len(zs) != 2 {
		t.Fatalf("zones: %+v", zs)
	}
	p := zs[0]
	if p.Name != "public" || !p.Active || !p.Default || p.Target != "default" {
		t.Errorf("public: %+v", p)
	}
	if strings.Join(p.Services, ",") != "dhcpv6-client,ssh" || strings.Join(p.Ports, ",") != "8080/tcp" || strings.Join(p.Interfaces, ",") != "eth0" {
		t.Errorf("public lists: %+v", p)
	}
	if len(p.RichRules) != 1 || !strings.HasPrefix(p.RichRules[0], `rule family="ipv4"`) {
		t.Errorf("rich rules: %q", p.RichRules)
	}
	tr := zs[1]
	if tr.Name != "trusted" || !tr.Active || tr.Default || tr.Target != "ACCEPT" || !tr.Masquerade || tr.Sources[0] != "10.9.0.0/16" {
		t.Errorf("trusted: %+v", tr)
	}
}

func fwInfo() FirewalldInfo {
	return FirewalldInfo{State: "running", DefaultZone: "public", Services: []string{"ssh", "http", "https"},
		Zones: ParseFirewalldZones(firewalldListAll, "public")}
}

func TestBuildFirewalld(t *testing.T) {
	info := fwInfo()
	cmds, err := BuildFirewalld(FirewalldOp{Op: "add", Zone: "public", Kind: "service", Value: "http"}, info)
	if err != nil || len(cmds) != 2 || strings.Join(cmds[0], " ") != "firewall-cmd --zone=public --add-service=http" ||
		strings.Join(cmds[1], " ") != "firewall-cmd --permanent --zone=public --add-service=http" {
		t.Fatalf("add service: %q %v", cmds, err)
	}
	cmds, err = BuildFirewalld(FirewalldOp{Op: "add", Zone: "public", Kind: "port", Value: "8000-8100/UDP"}, info)
	if err != nil || cmds[0][2] != "--add-port=8000-8100/udp" {
		t.Errorf("add port: %q %v", cmds, err)
	}
	cmds, err = BuildFirewalld(FirewalldOp{Op: "add", Zone: "public", Kind: "interface", Value: "eth1"}, info)
	if err != nil || cmds[0][2] != "--change-interface=eth1" {
		t.Errorf("add interface: %q %v", cmds, err)
	}
	cmds, err = BuildFirewalld(FirewalldOp{Op: "default-zone", Zone: "trusted"}, info)
	if err != nil || len(cmds) != 1 || cmds[0][1] != "--set-default-zone=trusted" {
		t.Errorf("default zone: %q %v", cmds, err)
	}
	for _, bad := range []FirewalldOp{
		{Op: "add", Zone: "public", Kind: "service", Value: "ssh"},          // 已有
		{Op: "add", Zone: "public", Kind: "service", Value: "nosuch"},       // 没有这个服务定义
		{Op: "add", Zone: "public", Kind: "service", Value: "a;rm -rf /"},   // 非法字符
		{Op: "add", Zone: "public", Kind: "port", Value: "70000/tcp"},       // 端口越界
		{Op: "remove", Zone: "public", Kind: "port", Value: "9999/tcp"},     // 不存在
		{Op: "add", Zone: "nosuch", Kind: "port", Value: "22/tcp"},          // 区域不存在
		{Op: "add", Zone: "public", Kind: "source", Value: "10.9.0.0/16"},   // 已绑在 trusted
		{Op: "add", Zone: "public", Kind: "rich-rule", Value: "accept all"}, // 不以 rule 开头
		{Op: "add", Zone: "trusted", Kind: "masquerade"},                    // 已开启
		{Op: "default-zone", Zone: "public"},                                // 已是默认
	} {
		if _, err := BuildFirewalld(bad, info); err == nil {
			t.Errorf("%+v should fail", bad)
		}
	}
	stopped := info
	stopped.State = "not running"
	if _, err := BuildFirewalld(FirewalldOp{Op: "add", Zone: "public", Kind: "service", Value: "http"}, stopped); err == nil {
		t.Error("not running should fail")
	}
}

func TestFirewalldLockout(t *testing.T) {
	info := fwInfo()
	p := SSHPath{Client: "10.0.0.5", Server: "10.0.0.1", Port: 22, Iface: "eth0"}
	if w := FirewalldLockout(FirewalldOp{Op: "remove", Zone: "public", Kind: "service", Value: "ssh"}, info, p); w == "" {
		t.Error("removing ssh service should warn")
	}
	if w := FirewalldLockout(FirewalldOp{Op: "remove", Zone: "public", Kind: "port", Value: "8080/tcp"}, info, p); w != "" {
		t.Errorf("removing unrelated port: %s", w)
	}
	// 管理连接来自 trusted 的来源网段：public 删掉 ssh 不影响
	p2 := SSHPath{Client: "10.9.1.1", Server: "10.0.0.1", Port: 22, Iface: "eth0"}
	if w := FirewalldLockout(FirewalldOp{Op: "remove", Zone: "public", Kind: "service", Value: "ssh"}, info, p2); w != "" {
		t.Errorf("trusted source: %s", w)
	}
	// 给 public 加一条拒绝本客户端的 rich rule：会失联
	op := FirewalldOp{Op: "add", Zone: "public", Kind: "rich-rule", Value: `rule family="ipv4" source address="10.0.0.0/24" drop`}
	if w := FirewalldLockout(op, info, p); w == "" {
		t.Error("drop rich rule should warn")
	}
	// 已经被现有 rich rule 拒绝的客户端：判断不了，不警告
	p3 := SSHPath{Client: "192.168.9.3", Server: "10.0.0.1", Port: 22, Iface: "eth0"}
	if w := FirewalldLockout(FirewalldOp{Op: "remove", Zone: "public", Kind: "service", Value: "ssh"}, info, p3); w != "" {
		t.Errorf("already blocked: %s", w)
	}
}
