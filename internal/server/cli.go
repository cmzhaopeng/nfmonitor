package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"nfmonitor/internal/api"
	"nfmonitor/internal/priv"
	"nfmonitor/internal/remote"
)

const usage = `nfmonitor server —— 服务器版：登录后集中监控、管理多台主机

用法:
  nfmonitor server [参数]                 启动服务
  nfmonitor server genkey                 生成主密钥（打印到标准输出）
  nfmonitor server user add <名字> [-role admin|viewer]
  nfmonitor server user passwd <名字>
  nfmonitor server user role <名字> admin|viewer
  nfmonitor server user disable|enable <名字>
  nfmonitor server user del <名字>
  nfmonitor server user list

账号命令也要带 -data（或环境变量 NFMONITOR_DATA），口令从终端读取（不回显）；
非交互时加 -password-stdin 从标准输入读一行。

启动参数:
`

// Main 是 `nfmonitor server ...` 的入口。
func Main(args []string, static fs.FS, version string) {
	if len(args) > 0 {
		switch args[0] {
		case "genkey":
			b := make([]byte, remote.KeySize)
			if _, err := rand.Read(b); err != nil {
				log.Fatal(err)
			}
			fmt.Println(base64.StdEncoding.EncodeToString(b))
			return
		case "user", "users":
			if err := userCmd(args[1:]); err != nil {
				fmt.Fprintln(os.Stderr, "错误:", err)
				os.Exit(1)
			}
			return
		}
	}
	fl := flag.NewFlagSet("server", flag.ExitOnError)
	fl.Usage = func() { fmt.Fprint(os.Stderr, usage); fl.PrintDefaults() }
	addr := fl.String("addr", "127.0.0.1:8787", "监听地址；监听非回环地址时必须用 -tls-cert/-tls-key 或 -behind-proxy")
	dataDir := fl.String("data", defaultDataDir(), "数据目录（主机配置、账号、审计日志），环境变量 NFMONITOR_DATA")
	keyFile := fl.String("key-file", "", "主密钥文件（也可用环境变量 NFMONITOR_MASTER_KEY_FILE / NFMONITOR_MASTER_KEY），不能放在数据目录里")
	certFile := fl.String("tls-cert", "", "TLS 证书（PEM，含中间证书）")
	keyPEM := fl.String("tls-key", "", "TLS 私钥（PEM）")
	behindProxy := fl.Bool("behind-proxy", false, "前面有做 HTTPS 终结的反向代理（nginx / Caddy 等）：cookie 标记 Secure，客户端 IP 取 X-Forwarded-For")
	trusted := fl.String("trusted-proxies", "127.0.0.1/32,::1/128", "-behind-proxy 时信任其 X-Forwarded-For 的代理地址（逗号分隔的 CIDR）")
	origins := fl.String("allowed-origins", os.Getenv("NFMONITOR_ALLOWED_ORIGINS"), "额外接受的 Origin（逗号分隔，如 https://nfm.example.com），反向代理改写了 Host 时需要；环境变量 NFMONITOR_ALLOWED_ORIGINS")
	idle := fl.Duration("session-idle", 30*time.Minute, "会话空闲多久后失效")
	maxAge := fl.Duration("session-max", 12*time.Hour, "会话最长有效期")
	fl.Parse(args)

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	if st, err := os.Stat(*dataDir); err == nil && runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		log.Printf("警告：数据目录 %s 权限是 %v，建议 chmod 700", *dataDir, st.Mode().Perm())
	}

	tlsOn := *certFile != "" || *keyPEM != ""
	if tlsOn && (*certFile == "" || *keyPEM == "") {
		log.Fatal("-tls-cert 和 -tls-key 要一起给")
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal(err)
	}
	loopback := host == "localhost"
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		loopback = true
	}
	if !loopback && !tlsOn && !*behindProxy {
		log.Fatal("监听非回环地址时必须启用 HTTPS：用 -tls-cert/-tls-key，或放在反向代理后面并加 -behind-proxy（见 README「服务器版」）")
	}
	if !tlsOn && !*behindProxy {
		log.Printf("提示：未启用 HTTPS，只适合本机访问或经 ssh -L 转发；对外提供请用 -tls-cert/-tls-key 或反向代理")
	}

	key, keySrc, err := LoadKey(*keyFile, *dataDir)
	if err != nil {
		log.Fatal(err)
	}
	users, err := OpenUsers(*dataDir)
	if err != nil {
		log.Fatal(err)
	}
	if users.Count() == 0 {
		log.Fatalf("还没有任何账号。先创建管理员：\n  nfmonitor server user add admin -role admin -data %s", *dataDir)
	}
	store, err := remote.OpenStoreWithKey(*dataDir, key)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(*dataDir, "secret.key")); err == nil {
		log.Printf("警告：数据目录里有 secret.key（桌面版的密钥文件），服务器版不使用它，建议删除")
	}
	hosts := remote.NewManager(store)
	hosts.ServerMode = true
	defer hosts.Close()
	audit, err := OpenAudit(*dataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer audit.Close()

	pc := priv.NewClient()
	srv := &api.Server{Priv: pc, Version: version, Hosts: hosts, NoLocal: true, Mode: "server"}
	var proxies []netip.Prefix
	if *behindProxy {
		for _, p := range splitList(*trusted) {
			pf, err := netip.ParsePrefix(p)
			if err != nil {
				log.Fatalf("-trusted-proxies: %v", err)
			}
			proxies = append(proxies, pf)
		}
	}
	gw := NewGateway(Options{
		API: srv.Handler(), Static: static, Users: users, Audit: audit, Version: version,
		Secure: tlsOn || *behindProxy, HSTS: tlsOn, TrustedProxies: proxies, AllowedOrigins: splitList(*origins),
		SessionIdle: *idle, SessionMaxAge: *maxAge,
		HostName: func(id string) string {
			for _, c := range hosts.Configs() {
				if c.ID == id {
					return c.Name
				}
			}
			return ""
		},
	})
	defer gw.Close()

	hs := &http.Server{
		Addr: *addr, Handler: gw,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
		ErrorLog:       log.New(io.Discard, "", 0),
	}
	if tlsOn {
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	audit.Log(AuditEntry{Action: "server/start", Result: "ok", Detail: map[string]any{"version": version, "addr": *addr, "tls": tlsOn, "behindProxy": *behindProxy}})
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	log.Printf("nfmonitor %s 服务器版: %s://%s  数据目录 %s  主密钥来自%s  账号 %d 个", version, scheme, *addr, *dataDir, keySrc, users.Count())

	errc := make(chan error, 1)
	go func() {
		if tlsOn {
			errc <- hs.ListenAndServeTLS(*certFile, *keyPEM)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
		audit.Log(AuditEntry{Action: "server/stop", Result: "ok"})
	}
}

func defaultDataDir() string {
	if d := os.Getenv("NFMONITOR_DATA"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if d := os.Getenv("ProgramData"); d != "" {
			return filepath.Join(d, "nfmonitor")
		}
	}
	return "/var/lib/nfmonitor"
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func userCmd(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("缺少子命令")
	}
	sub := args[0]
	fl := flag.NewFlagSet("user "+sub, flag.ExitOnError)
	dataDir := fl.String("data", defaultDataDir(), "数据目录")
	role := fl.String("role", "", "角色 admin | viewer（add 时缺省 viewer）")
	pwStdin := fl.Bool("password-stdin", false, "从标准输入读口令（一行）")
	// 允许参数写在名字前后：先取出位置参数
	var pos []string
	rest := args[1:]
	for len(rest) > 0 {
		fl.Parse(rest)
		rest = fl.Args()
		if len(rest) > 0 {
			pos = append(pos, rest[0])
			rest = rest[1:]
		}
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	u, err := OpenUsers(*dataDir)
	if err != nil {
		return err
	}
	need := func(n int) error {
		if len(pos) != n {
			return fmt.Errorf("参数个数不对，见 nfmonitor server -h")
		}
		return nil
	}
	switch sub {
	case "list", "ls":
		for _, x := range u.List() {
			st := ""
			if x.Disabled {
				st = "（已停用）"
			}
			fmt.Printf("%-24s %-7s 口令修改于 %s%s\n", x.Name, x.Role, x.Changed.Local().Format("2006-01-02 15:04"), st)
		}
		return nil
	case "add":
		if err := need(1); err != nil {
			return err
		}
		pw, err := readNewPassword(*pwStdin)
		if err != nil {
			return err
		}
		r := *role
		if r == "" {
			r = RoleViewer
		}
		if err := u.Put(pos[0], r, pw, true); err != nil {
			return err
		}
		fmt.Printf("已添加 %s（%s）\n", pos[0], r)
	case "passwd":
		if err := need(1); err != nil {
			return err
		}
		pw, err := readNewPassword(*pwStdin)
		if err != nil {
			return err
		}
		if err := u.Put(pos[0], "", pw, false); err != nil {
			return err
		}
		fmt.Printf("已修改 %s 的口令（已登录的会话随之失效）\n", pos[0])
	case "role":
		if err := need(2); err != nil {
			return err
		}
		if err := u.Put(pos[0], pos[1], "", false); err != nil {
			return err
		}
		fmt.Printf("%s 的角色改为 %s\n", pos[0], pos[1])
	case "disable", "enable":
		if err := need(1); err != nil {
			return err
		}
		if err := u.SetDisabled(pos[0], sub == "disable"); err != nil {
			return err
		}
		fmt.Printf("已%s %s\n", map[string]string{"disable": "停用", "enable": "启用"}[sub], pos[0])
	case "del", "delete", "rm":
		if err := need(1); err != nil {
			return err
		}
		if err := u.Delete(pos[0]); err != nil {
			return err
		}
		fmt.Printf("已删除 %s\n", pos[0])
	default:
		return fmt.Errorf("未知子命令 %q", sub)
	}
	return nil
}

func readNewPassword(fromStdin bool) (string, error) {
	fd := int(os.Stdin.Fd())
	if fromStdin || !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("读取口令: %w", err)
		}
		pw := strings.TrimRight(line, "\r\n")
		return pw, CheckPassword(pw)
	}
	fmt.Fprint(os.Stderr, "口令: ")
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if err := CheckPassword(string(a)); err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "再输一次: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("两次输入的口令不一致")
	}
	return string(a), nil
}
