package remote

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"nfmonitor/internal/netinfo"
)

// Root 权限的来源。
const (
	RootLogin    = "root"    // 以 root 登录
	RootSudo     = "sudo"    // sudo 免密
	RootSudoPass = "sudo-pw" // sudo 需要口令（用 sudo 口令或登录口令）
	RootNone     = "none"    // 没有 root 权限：只能看普通用户能看的
)

// HostInfo 是连上之后探测到的信息。
type HostInfo struct {
	Hostname string           `json:"hostname"`
	Kernel   string           `json:"kernel"`
	Root     string           `json:"root"` // root | sudo | sudo-pw | none
	RootErr  string           `json:"rootErr,omitempty"`
	Path     *netinfo.SSHPath `json:"path,omitempty"` // 管理连接在服务器一侧的样子
}

// ErrNoRoot 表示远程用户拿不到 root。
var ErrNoRoot = errors.New("远程用户没有 root 权限：请用 root 登录，或为该用户配置 sudo（免密，或在主机设置里填 sudo 口令）")

const (
	dialTimeout = 10 * time.Second
	maxSessions = 4 // sshd 默认 MaxSessions 是 10，留些余量
	idleClose   = 10 * time.Minute
	retryAfter  = 5 * time.Second
)

// Host 是一台远程主机的 SSH 连接，实现 netinfo.Sys 和 netinfo.RootSys。
// 连接按需建立、出错后自动重连、空闲一段时间后关闭。
type Host struct {
	cfg HostConfig
	sem chan struct{}

	mu       sync.Mutex
	client   *ssh.Client
	info     HostInfo
	lastErr  error
	lastFail time.Time
	lastUse  time.Time
	tools    map[string]bool
	closed   bool
	// manual 表示用户在界面上点了「断开」：之后的采集请求不会自动重连，直到再点「连接」。
	manual bool
}

// ErrDisconnected 是用户手动断开后，采集请求得到的错误。
var ErrDisconnected = errors.New("已断开连接：点「连接」重新连接")

func newHost(cfg HostConfig) *Host {
	return &Host{cfg: cfg, sem: make(chan struct{}, maxSessions), tools: map[string]bool{}}
}

func (h *Host) Config() HostConfig { return h.cfg }
func (h *Host) Remote() bool       { return true }

// Status 返回是否已连接、最近的错误和探测到的信息（不会主动发起连接）。
func (h *Host) Status() (connected bool, errMsg string, info HostInfo) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastErr != nil {
		errMsg = h.lastErr.Error()
	}
	return h.client != nil, errMsg, h.info
}

// Connect 确保连接已建立，返回探测到的信息。
func (h *Host) Connect() (HostInfo, error) {
	if _, err := h.conn(); err != nil {
		return HostInfo{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.info, nil
}

// Close 断开连接；之后的调用会重新连接（Manager 删除主机时不再使用它）。
func (h *Host) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	if h.client != nil {
		h.client.Close()
		h.client = nil
	}
}

// Disconnect 是用户手动断开：关闭连接，并且在 Reconnect 之前不再自动重连。
func (h *Host) Disconnect() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.manual, h.lastErr = true, nil
	if h.client != nil {
		h.client.Close()
		h.client = nil
	}
}

// Manual 报告用户是否手动断开了这台主机（之后不自动重连）。
func (h *Host) Manual() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.manual
}

// Reconnect 是用户主动连接：清掉手动断开标记和重试间隔，立即连接。
func (h *Host) Reconnect() (HostInfo, error) {
	h.mu.Lock()
	h.manual, h.lastErr = false, nil
	h.tools = map[string]bool{} // 「重连」后重新检测装了哪些工具（例如刚装了 ufw）
	h.mu.Unlock()
	return h.Connect()
}

func (h *Host) conn() (*ssh.Client, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastUse = time.Now()
	if h.client != nil {
		return h.client, nil
	}
	if h.closed {
		return nil, errors.New("主机已删除")
	}
	if h.manual {
		return nil, ErrDisconnected
	}
	if h.lastErr != nil && time.Since(h.lastFail) < retryAfter {
		return nil, h.lastErr
	}
	c, err := dial(h.cfg)
	if err != nil {
		h.lastErr, h.lastFail = err, time.Now()
		return nil, err
	}
	h.client, h.lastErr = c, nil
	h.tools = map[string]bool{}
	h.info = probe(c, h.cfg)
	go h.keepalive(c)
	return c, nil
}

// drop 在连接出错时丢弃它，下次调用重新连接。
func (h *Host) drop(c *ssh.Client, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.client == c {
		h.client.Close()
		h.client = nil
		h.lastErr, h.lastFail = fmt.Errorf("连接已断开: %w", err), time.Now()
	}
}

func (h *Host) keepalive(c *ssh.Client) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		h.mu.Lock()
		cur, idle := h.client, time.Since(h.lastUse) > idleClose
		h.mu.Unlock()
		if cur != c {
			return
		}
		if idle {
			h.mu.Lock()
			if h.client == c {
				h.client.Close()
				h.client = nil
			}
			h.mu.Unlock()
			return
		}
		done := make(chan error, 1)
		go func() { _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); done <- err }()
		select {
		case err := <-done:
			if err != nil {
				h.drop(c, err)
				return
			}
		case <-time.After(15 * time.Second):
			h.drop(c, errors.New("心跳超时"))
			return
		}
	}
}

// ---- 拨号与认证 ----

func authMethods(cfg HostConfig) ([]ssh.AuthMethod, error) {
	switch cfg.Auth {
	case AuthPassword:
		pw := cfg.Password
		return []ssh.AuthMethod{
			ssh.Password(pw),
			// 不少服务器只开了 keyboard-interactive：每个问题都用口令回答。
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				ans := make([]string, len(qs))
				for i := range qs {
					ans[i] = pw
				}
				return ans, nil
			}),
		}, nil
	case AuthKey:
		pem := []byte(cfg.KeyPEM)
		if len(pem) == 0 {
			b, err := os.ReadFile(cfg.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("读取私钥失败: %w", err)
			}
			pem = b
		}
		signer, err := parseKey(pem, cfg.Passphrase)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	case AuthAgent:
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("没有 ssh-agent（SSH_AUTH_SOCK 未设置）")
		}
		ac, err := net.Dial("unix", sock)
		if err != nil {
			return nil, fmt.Errorf("连接 ssh-agent 失败: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeysCallback(agent.NewClient(ac).Signers)}, nil
	}
	return nil, fmt.Errorf("认证方式无效: %q", cfg.Auth)
}

func parseKey(pem []byte, passphrase string) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pem)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == "" {
			return nil, errors.New("私钥有口令保护，请填写私钥口令")
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(passphrase))
	}
	if err != nil {
		return nil, fmt.Errorf("私钥无法解析: %w", err)
	}
	return signer, nil
}

func addrPort(cfg HostConfig) string { return net.JoinHostPort(cfg.Addr, strconv.Itoa(cfg.Port)) }

func dial(cfg HostConfig) (*ssh.Client, error) {
	if cfg.HostKey == "" {
		return nil, errors.New("还没有确认这台主机的密钥指纹，请在主机设置里重新连接并确认")
	}
	trusted, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.HostKey))
	if err != nil {
		return nil, fmt.Errorf("保存的主机公钥无效: %w", err)
	}
	auth, err := authMethods(cfg)
	if err != nil {
		return nil, err
	}
	conf := &ssh.ClientConfig{
		User: cfg.User,
		Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if bytes.Equal(key.Marshal(), trusted.Marshal()) {
				return nil
			}
			return fmt.Errorf("主机密钥与已信任的不一致（现在是 %s，保存的是 %s）。可能遭遇中间人攻击；如果确认是主机重装了系统，请在主机设置里重新确认指纹",
				ssh.FingerprintSHA256(key), ssh.FingerprintSHA256(trusted))
		},
		HostKeyAlgorithms: []string{trusted.Type()},
		Timeout:           dialTimeout,
	}
	if trusted.Type() == ssh.KeyAlgoRSA {
		conf.HostKeyAlgorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	c, err := ssh.Dial("tcp", addrPort(cfg), conf)
	if err != nil {
		return nil, friendlyDialErr(err)
	}
	return c, nil
}

func friendlyDialErr(err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "unable to authenticate"):
		return fmt.Errorf("认证失败（用户名、口令或私钥不对，或服务器不允许这种认证方式）: %w", err)
	case strings.Contains(s, "connection refused"):
		return fmt.Errorf("连接被拒绝（端口不对，或 sshd 没有运行）: %w", err)
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "no route to host"):
		return fmt.Errorf("连不上主机（地址不对，或被防火墙挡住）: %w", err)
	}
	return err
}

// HostKeyProbe 是首次连接时看到的主机公钥。
type HostKeyProbe struct {
	HostKey     string `json:"hostKey"`     // authorized_keys 格式
	Type        string `json:"type"`        // ssh-ed25519 ...
	Fingerprint string `json:"fingerprint"` // SHA256:...
	KnownHosts  string `json:"knownHosts"`  // match | mismatch | unknown：与 ~/.ssh/known_hosts 的比对
}

var errProbeDone = errors.New("probe done")

// ProbeHostKey 连上主机拿到它的公钥就断开（不做认证），给用户确认指纹。
func ProbeHostKey(addr string, port int) (HostKeyProbe, error) {
	cfg := HostConfig{Addr: addr, Port: port, User: "probe", Auth: AuthAgent}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	var res HostKeyProbe
	var got ssh.PublicKey
	conf := &ssh.ClientConfig{
		User: "nfmonitor-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errProbeDone
		},
		Timeout: dialTimeout,
	}
	_, err := ssh.Dial("tcp", addrPort(cfg), conf)
	if got == nil {
		if err == nil {
			err = errors.New("没有拿到主机公钥")
		}
		return res, friendlyDialErr(err)
	}
	res.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(got)))
	res.Type = got.Type()
	res.Fingerprint = ssh.FingerprintSHA256(got)
	res.KnownHosts = checkKnownHosts(cfg, got)
	return res, nil
}

func checkKnownHosts(cfg HostConfig, key ssh.PublicKey) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unknown"
	}
	cb, err := knownhosts.New(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		return "unknown"
	}
	remote := &net.TCPAddr{Port: cfg.Port}
	if ip := net.ParseIP(cfg.Addr); ip != nil {
		remote.IP = ip
	}
	err = cb(knownhosts.Normalize(addrPort(cfg)), remote, key)
	var ke *knownhosts.KeyError
	switch {
	case err == nil:
		return "match"
	case errors.As(err, &ke) && len(ke.Want) > 0:
		// known_hosts 里有这台主机，但同类型的密钥不一样（或只记了别的类型）
		for _, w := range ke.Want {
			if w.Key.Type() == key.Type() {
				return "mismatch"
			}
		}
		return "unknown"
	}
	return "unknown"
}

// ---- 执行命令 ----

// 连上后探测一次：身份、主机名、管理连接的地址、root 权限来源。
const probeScript = `printf '%s\n' "$SSH_CONNECTION"; id -u; uname -n; uname -sr`

func probe(c *ssh.Client, cfg HostConfig) HostInfo {
	info := HostInfo{Root: RootNone}
	out, _, err := runSession(c, "sh -c "+netinfo.ShellQuote(probeScript), "", 15*time.Second)
	if err != nil {
		info.RootErr = err.Error()
		return info
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for len(lines) < 4 {
		lines = append(lines, "")
	}
	if p, ok := netinfo.ParseSSHConnection(lines[0]); ok {
		if o, _, err := runSession(c, cmdline("", "ip", []string{"-o", "addr", "show", "to", p.Server}), "", 8*time.Second); err == nil {
			if fs := strings.Fields(o); len(fs) > 1 {
				p.Iface = strings.TrimSuffix(fs[1], ":")
			}
		}
		info.Path = &p
	}
	info.Hostname, info.Kernel = strings.TrimSpace(lines[2]), strings.TrimSpace(lines[3])
	if strings.TrimSpace(lines[1]) == "0" {
		info.Root = RootLogin
		return info
	}
	if _, _, err := runSession(c, "sudo -n true", "", 10*time.Second); err == nil {
		info.Root = RootSudo
		return info
	}
	if pw := sudoPassword(cfg); pw != "" {
		if _, _, err := runSession(c, "sudo -S -p '' true", pw+"\n", 10*time.Second); err == nil {
			info.Root = RootSudoPass
			return info
		}
		info.RootErr = "sudo 口令不对，或该用户不在 sudoers 里"
		return info
	}
	info.RootErr = "该用户不能免密 sudo；如需 root 才能看的数据（防火墙规则、其他用户的进程），请用 root 登录或在主机设置里填 sudo 口令"
	return info
}

func sudoPassword(cfg HostConfig) string {
	if cfg.SudoPassword != "" {
		return cfg.SudoPassword
	}
	if cfg.Auth == AuthPassword {
		return cfg.Password
	}
	return ""
}

// cmdline 拼远程命令行：固定 C 语言环境和 PATH，每个参数都按 shell 单引号转义；
// sudo 为 "-n" / "-S" 时以 root 执行。用 env 而不是 shell 赋值，登录 shell 是 fish、csh 也能用。
func cmdline(sudo, name string, args []string) string {
	var b strings.Builder
	switch sudo {
	case "-n":
		b.WriteString("sudo -n -- ")
	case "-S":
		b.WriteString("sudo -S -p '' -- ")
	}
	b.WriteString("env LC_ALL=C LANG=C LANGUAGE=C PATH=" + strings.Join(netinfo.ToolDirs(), ":") + " ")
	b.WriteString(netinfo.ShellQuote(name))
	for _, a := range args {
		b.WriteString(" " + netinfo.ShellQuote(a))
	}
	return b.String()
}

type exitErr struct {
	status int
	stderr string
}

func (e *exitErr) Error() string { return e.stderr }

// runSession 在一个新会话里执行命令；ssh.ExitError 转成带 stderr 的 exitErr，其余错误原样返回（通常是连接问题）。
func runSession(c *ssh.Client, cmd, stdin string, timeout time.Duration) (string, string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", "", err
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout, sess.Stderr = &out, &errb
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err = <-done:
	case <-time.After(timeout):
		sess.Signal(ssh.SIGKILL)
		sess.Close()
		return out.String(), errb.String(), errTimeout
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		return out.String(), errb.String(), &exitErr{status: ee.ExitStatus(), stderr: strings.TrimSpace(errb.String())}
	}
	var em *ssh.ExitMissingError
	if errors.As(err, &em) {
		return out.String(), errb.String(), &exitErr{status: -1, stderr: strings.TrimSpace(errb.String())}
	}
	return out.String(), errb.String(), err
}

var errTimeout = errors.New("执行超时")

func (h *Host) exec(timeout time.Duration, sudo, name string, args []string, stdin string) (string, error) {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	cmd := cmdline(sudo, name, args)
	for attempt := 0; ; attempt++ {
		c, err := h.conn()
		if err != nil {
			return "", err
		}
		out, _, err := runSession(c, cmd, stdin, timeout)
		var ee *exitErr
		switch {
		case err == nil:
			return out, nil
		case errors.As(err, &ee):
			msg := ee.stderr
			if msg == "" {
				msg = fmt.Sprintf("退出码 %d", ee.status)
			}
			if ee.status == 127 && strings.Contains(msg, "No such file") {
				msg = "未安装"
			}
			return out, fmt.Errorf("%s: %s", name, msg)
		case errors.Is(err, errTimeout):
			return out, fmt.Errorf("%s: %w", name, err)
		}
		// 会话都开不了：连接多半已经坏了，重连再试一次。
		h.drop(c, err)
		if attempt > 0 {
			return "", err
		}
	}
}

// Run 以登录用户执行一个工具。
func (h *Host) Run(timeout time.Duration, name string, args ...string) (string, error) {
	return h.exec(timeout, "", name, args, "")
}

// ReadFile 以登录用户读文件；文件不存在时返回 fs.ErrNotExist。
func (h *Host) ReadFile(path string) ([]byte, error) {
	out, err := h.Run(10*time.Second, "cat", "--", path)
	return []byte(out), notExist(err)
}

func notExist(err error) error {
	if err != nil && strings.Contains(err.Error(), "No such file or directory") {
		return fmt.Errorf("%w: %v", fs.ErrNotExist, err)
	}
	return err
}

// HasTool 报告远程主机上是否装了某个工具（结果按连接缓存）。
func (h *Host) HasTool(name string) bool {
	h.mu.Lock()
	v, ok := h.tools[name]
	h.mu.Unlock()
	if ok {
		return v
	}
	_, err := h.Run(8*time.Second, "sh", "-c", `command -v "$1" >/dev/null 2>&1`, "sh", name)
	v = err == nil
	if err != nil && !strings.Contains(err.Error(), "退出码") {
		return false // 连接问题，不缓存
	}
	h.mu.Lock()
	h.tools[name] = v
	h.mu.Unlock()
	return v
}

// RootMode 返回 root 权限的来源（未连接时先连接）。
func (h *Host) RootMode() string {
	if _, err := h.conn(); err != nil {
		return RootNone
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.info.Root
}

// SSHPath 返回管理连接在服务器一侧的地址与端口。
func (h *Host) SSHPath() *netinfo.SSHPath {
	if _, err := h.conn(); err != nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.info.Path == nil {
		return &netinfo.SSHPath{Server: h.cfg.Addr, Port: h.cfg.Port}
	}
	p := *h.info.Path
	return &p
}

// RunRoot 以 root 执行：root 登录直接执行，否则经 sudo。
func (h *Host) RunRoot(timeout time.Duration, name string, args ...string) (string, error) {
	switch h.RootMode() {
	case RootLogin:
		return h.exec(timeout, "", name, args, "")
	case RootSudo:
		return h.exec(timeout, "-n", name, args, "")
	case RootSudoPass:
		return h.exec(timeout, "-S", name, args, sudoPassword(h.cfg)+"\n")
	}
	return "", ErrNoRoot
}

func (h *Host) ReadFileRoot(path string) ([]byte, error) {
	out, err := h.RunRoot(10*time.Second, "cat", "--", path)
	return []byte(out), notExist(err)
}

// RunPriv 执行 netinfo.PrivCommands 白名单里的命令（防火墙页、套接字等需要 root 的数据）。
func (h *Host) RunPriv(name string) (string, error) {
	return netinfo.RunPrivCommandOn(h, name)
}

var (
	_ netinfo.Sys     = (*Host)(nil)
	_ netinfo.RootSys = (*Host)(nil)
)
