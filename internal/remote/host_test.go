package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io/fs"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"nfmonitor/internal/netinfo"
)

// testServer 是一个最小的 SSH 服务器：口令认证，exec 请求交给本机 sh -c 执行。
type testServer struct {
	addr    string
	port    int
	hostKey ssh.PublicKey
	cmds    chan string
}

func startServer(t *testing.T, password string) *testServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	conf := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) == password {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	conf.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &testServer{addr: "127.0.0.1", port: ln.Addr().(*net.TCPAddr).Port, hostKey: signer.PublicKey(), cmds: make(chan string, 1000)}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, conf)
		}
	}()
	return s
}

func (s *testServer) serve(nc net.Conn, conf *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(nc, conf)
	if err != nil {
		nc.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	la, ra := nc.LocalAddr().(*net.TCPAddr), nc.RemoteAddr().(*net.TCPAddr)
	sshConn := ra.IP.String() + " " + strconv.Itoa(ra.Port) + " " + la.IP.String() + " " + strconv.Itoa(la.Port)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				n := binary.BigEndian.Uint32(req.Payload[:4])
				cmd := string(req.Payload[4 : 4+n])
				req.Reply(true, nil)
				select {
				case s.cmds <- cmd:
				default:
				}
				c := exec.Command("sh", "-c", cmd)
				c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "SSH_CONNECTION=" + sshConn}
				c.Stdin, c.Stdout, c.Stderr = ch, ch, ch.Stderr()
				status := 0
				if err := c.Run(); err != nil {
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						status = ee.ExitCode()
					} else {
						status = 127
					}
				}
				ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, uint32(status)))
				return
			}
		}()
	}
}

func (s *testServer) config(pw string) HostConfig {
	return HostConfig{Addr: s.addr, Port: s.port, User: "tester", Auth: AuthPassword, Password: pw,
		HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.hostKey)))}
}

func TestProbeHostKey(t *testing.T) {
	s := startServer(t, "pw")
	p, err := ProbeHostKey(s.addr, s.port)
	if err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint != ssh.FingerprintSHA256(s.hostKey) || p.Type != ssh.KeyAlgoED25519 {
		t.Errorf("probe: %+v", p)
	}
}

func TestHostAuthAndHostKey(t *testing.T) {
	s := startServer(t, "pw")
	m := NewManager(mustStore(t))

	if _, err := m.Test(s.config("wrong"), Secrets{}); err == nil || !strings.Contains(err.Error(), "认证失败") {
		t.Errorf("wrong password: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ssh.NewPublicKey(other)
	cfg := s.config("pw")
	cfg.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	if _, err := m.Test(cfg, Secrets{}); err == nil || !strings.Contains(err.Error(), "主机密钥与已信任的不一致") {
		t.Errorf("host key mismatch: %v", err)
	}
	cfg.HostKey = ""
	if _, err := m.Test(cfg, Secrets{}); err == nil {
		t.Error("untrusted host key should be refused")
	}
	info, err := m.Test(s.config("pw"), Secrets{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Hostname == "" || info.Kernel == "" || info.Path == nil || info.Path.Port != s.port {
		t.Errorf("info: %+v", info)
	}
}

func mustStore(t *testing.T) *Store {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestHostRun(t *testing.T) {
	s := startServer(t, "pw")
	m := NewManager(mustStore(t))
	v, err := m.Save(s.config("pw"), Secrets{})
	if err != nil {
		t.Fatal(err)
	}
	h, err := m.Get(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	out, err := h.Run(5*time.Second, "printf", "%s|", "a b", "it's", "$(id)")
	if err != nil || out != "a b|it's|$(id)|" {
		t.Errorf("quoting: %q %v", out, err)
	}
	out, err = h.Run(5*time.Second, "sh", "-c", `echo "$LC_ALL"`)
	if err != nil || strings.TrimSpace(out) != "C" {
		t.Errorf("locale: %q %v", out, err)
	}
	if _, err := h.ReadFile("/nonexistent/x"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile missing: %v", err)
	}
	if b, err := h.ReadFile("/proc/net/dev"); err != nil || !strings.Contains(string(b), "Inter-") {
		t.Errorf("ReadFile: %v", err)
	}
	if !h.HasTool("sh") || h.HasTool("no-such-tool-xyz") {
		t.Error("HasTool")
	}
	if _, err := h.Run(5*time.Second, "no-such-tool-xyz"); err == nil {
		t.Error("missing tool should fail")
	}
	if _, err := h.Run(5*time.Second, "sh", "-c", "exit 3"); err == nil || !strings.Contains(err.Error(), "退出码 3") {
		t.Errorf("exit code: %v", err)
	}
	// 测试环境以 root 运行，探测应得到 root 登录
	if mode := h.RootMode(); mode != RootLogin {
		t.Logf("root mode %q (test not running as root?)", mode)
	}
	view := m.List()
	if len(view) != 1 || !view[0].Connected || !view[0].HasPassword || view[0].Fingerprint == "" {
		t.Errorf("list: %+v", view)
	}

	// 删除后句柄不可再用
	if err := m.Delete(v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Run(time.Second, "true"); err == nil {
		t.Error("deleted host should not run")
	}
}

// 远程采集走一遍：结果应与本机直接读取一致（测试里「远程主机」就是本机）。
func TestRemoteCollectors(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip not installed")
	}
	s := startServer(t, "pw")
	m := NewManager(mustStore(t))
	defer m.Close()
	v, err := m.Save(s.config("pw"), Secrets{})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := m.Get(v.ID)

	links, err := netinfo.LinksOn(h)
	if err != nil {
		t.Fatal(err)
	}
	local, _ := netinfo.Links()
	if len(links) == 0 || len(links) != len(local) {
		t.Errorf("links: remote %d local %d", len(links), len(local))
	}
	st, err := netinfo.StatsOn(h)
	if err != nil || len(st.Stats) == 0 {
		t.Errorf("stats: %+v %v", st, err)
	}
	if _, err := netinfo.RoutingOn(h); err != nil {
		t.Errorf("routing: %v", err)
	}
	if _, err := exec.LookPath("ss"); err == nil {
		socks, err := netinfo.SocketsOn(h)
		if err != nil {
			t.Errorf("sockets: %v", err)
		}
		// 测试服务器自己在监听，必须能看到
		found := false
		for _, so := range socks {
			if so.LocalPort == strconv.Itoa(s.port) && so.State == "LISTEN" {
				found = true
			}
		}
		if !found {
			t.Errorf("own listener %d not in sockets (%d total)", s.port, len(socks))
		}
		netinfo.EnrichSocketsOn(h, socks)
		for _, so := range socks {
			if so.LocalPort == strconv.Itoa(s.port) && so.State == "LISTEN" && so.App == "" {
				t.Errorf("listener not attributed to a process: %+v", so)
			}
		}
	}
	fw := netinfo.CollectFirewallOn(h, h.RunPriv)
	// 以 root 登录：应拿到 root 数据；iptables / nft 已安装时工具版本应被识别
	if !fw.Privileged {
		t.Errorf("firewall not privileged: errors %v", fw.Errors)
	}
	t.Logf("firewall tools %v, %d tables, errors %v", fw.Tools, len(fw.Tables), fw.Errors)
}
