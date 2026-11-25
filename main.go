package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"time"

	"nfmonitor/internal/api"
	"nfmonitor/internal/netinfo"
	"nfmonitor/internal/priv"
	"nfmonitor/internal/remote"
	"nfmonitor/internal/server"
)

//go:embed all:frontend/dist
var assets embed.FS

// version 可在构建时用 -ldflags "-X main.version=1.2.3" 覆盖。
var version = "0.5.1"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "helper":
			// 由 pkexec 以 root 启动；只读白名单命令，见 internal/priv。
			if err := priv.ServeHelper(os.Stdin, os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "ufw-apply":
			// 由 pkexec 以 root 启动：从 stdin 读一次 ufw 修改，重新校验后执行，见 internal/priv。
			if err := priv.ServeUfwApply(os.Stdin, os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "serve":
			serve(os.Args[2:])
			return
		case "server":
			// 服务器版：部署在服务器上，登录后集中监控多台主机，见 internal/server。
			dist, err := fs.Sub(assets, "frontend/dist")
			if err != nil {
				log.Fatal(err)
			}
			server.Main(os.Args[2:], dist, version)
			return
		case "dump":
			// 调试用：不起服务，直接在进程内调一次接口。例：nfmonitor dump /api/links
			if len(os.Args) < 3 {
				log.Fatal("用法: nfmonitor dump /api/<name>")
			}
			pc := priv.NewClient()
			srv := &api.Server{Priv: pc, Version: version}
			rec := httptest.NewRecorder()
			h := srv.Handler()
			if os.Args[2] == "/api/apps" { // 速率要两次采样才有，先垫一次
				h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", os.Args[2], nil))
				time.Sleep(4500 * time.Millisecond)
			}
			h.ServeHTTP(rec, httptest.NewRequest("GET", os.Args[2], nil))
			os.Stdout.Write(rec.Body.Bytes())
			return
		case "version", "--version", "-v":
			fmt.Println(version)
			return
		case "help", "--help", "-h":
			fmt.Println("用法:\n  nfmonitor                 打开桌面窗口\n  nfmonitor serve [-addr 127.0.0.1:8787]   以网页方式提供界面（仅本机，Linux）\n  nfmonitor server -h       服务器版：登录后集中监控多台主机\n  nfmonitor version")
			return
		}
	}
	runDesktop()
}

func serve(args []string) {
	fl := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fl.String("addr", "127.0.0.1:8787", "监听地址（仅支持回环地址）")
	fl.Parse(args)
	if runtime.GOOS != "linux" {
		log.Fatal("serve 只在 Linux 上提供（它靠 /proc 校验访问者是同一用户）。Windows 上直接运行 nfmonitor.exe 打开窗口，或用 nfmonitor server（带登录）")
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal(err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Fatal("serve 只允许监听回环地址：接口没有鉴权，远程访问请用 ssh -L 转发")
	}
	pc := priv.NewClient()
	defer pc.Close()
	srv := &api.Server{Priv: pc, Version: version, CheckHost: true, Mode: "serve", NoLocal: !netinfo.LocalSupported}
	srv.Hosts, srv.HostsErr = openHosts()
	if srv.Hosts != nil {
		defer srv.Hosts.Close()
	}
	dist, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", srv.Handler())
	mux.Handle("/", http.FileServerFS(dist))
	log.Printf("nfmonitor %s: http://%s", version, *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// openHosts 打开远程主机配置（~/.config/nfmonitor/hosts.json）。失败时只能看本机，原因显示在界面上。
func openHosts() (*remote.Manager, error) {
	dir, err := remote.DefaultDir()
	if err != nil {
		log.Printf("远程主机配置不可用: %v", err)
		return nil, err
	}
	st, err := remote.OpenStore(dir)
	if err != nil {
		log.Printf("远程主机配置不可用: %v", err)
		return nil, err
	}
	return remote.NewManager(st), nil
}
