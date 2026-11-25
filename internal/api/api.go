// Package api 把采集结果暴露成 JSON 接口。桌面版（Wails 资源服务器）和
// 浏览器版（serve 子命令）共用同一个 handler。
//
// 所有采集接口都接受可选的 ?host=<id>：不带时采集本机，带了就经 SSH 采集那台远程主机
// （主机配置见 /api/hosts*，internal/remote）。
package api

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"nfmonitor/internal/netinfo"
	"nfmonitor/internal/priv"
	"nfmonitor/internal/remote"
)

type Server struct {
	Priv    *priv.Client
	Version string
	// CheckHost 为真时只接受 Host 为本机回环的请求（防 DNS rebinding），用于 serve 模式。
	CheckHost bool
	// Hosts 是远程主机管理；为 nil 时只能看本机（配置目录不可用等情况）。
	Hosts *remote.Manager
	// HostsErr 是打开主机配置失败的原因（Hosts 为 nil 时给界面看）。
	HostsErr error
	// NoLocal 为真时不采集本机：Windows 客户端（采集层只支持 Linux）和服务器版（只看纳管主机）。
	NoLocal bool
	// Mode 是运行方式：desktop | serve | server，界面据此调整（由 /api/session 返回）。
	Mode string

	fleetMu sync.Mutex // 同一时间只有一次总览采集
	fleetSt fleetState

	apps     *netinfo.AppTracker
	trackMu  sync.Mutex
	trackers map[string]*netinfo.AppTracker // 远程主机 id → 应用流量统计
}

// target 是一次请求要采集的机器。
type target struct {
	sys     netinfo.Sys
	host    *remote.Host                 // 远程主机；本机为 nil
	runPriv func(string) (string, error) // 以 root 执行白名单命令
}

func (s *Server) target(r *http.Request) (target, error) {
	id := r.URL.Query().Get("host")
	if id == "" || id == "local" {
		if s.NoLocal {
			return target{}, netinfo.ErrNoLocal
		}
		return target{sys: netinfo.Local, runPriv: s.Priv.Run}, nil
	}
	if s.Hosts == nil {
		return target{}, s.hostsUnavailable()
	}
	h, err := s.Hosts.Get(id)
	if err != nil {
		return target{}, err
	}
	return target{sys: h, host: h, runPriv: h.RunPriv}, nil
}

func (s *Server) hostsUnavailable() error {
	if s.HostsErr != nil {
		return errors.New("远程主机配置不可用: " + s.HostsErr.Error())
	}
	return errors.New("远程主机配置不可用")
}

func (s *Server) tracker(t target) *netinfo.AppTracker {
	if t.host == nil {
		return s.apps
	}
	id := t.host.Config().ID
	s.trackMu.Lock()
	defer s.trackMu.Unlock()
	if s.trackers == nil {
		s.trackers = map[string]*netinfo.AppTracker{}
	}
	tr := s.trackers[id]
	if tr == nil {
		tt := t
		tr = &netinfo.AppTracker{Sys: t.host, Sample: func() ([]netinfo.Socket, error) { return s.sockets(tt) }}
		s.trackers[id] = tr
	}
	return tr
}

// forgetHost 在主机被删除或改了配置后清掉它的采样状态。
func (s *Server) forgetHost(id string) {
	s.trackMu.Lock()
	tr := s.trackers[id]
	delete(s.trackers, id)
	s.trackMu.Unlock()
	if tr != nil {
		tr.Stop()
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	local := target{sys: netinfo.Local, runPriv: s.Priv.Run}
	s.apps = &netinfo.AppTracker{Sample: func() ([]netinfo.Socket, error) { return s.sockets(local) }, UDP: s.udpStat}
	if s.Hosts != nil {
		s.Hosts.OnRemove = s.forgetHost
	}
	// get 注册一个采集接口：先按 ?host= 选出目标机器。
	get := func(path string, fn func(r *http.Request, t target) (any, error)) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			reply(w, func(r *http.Request) (any, error) {
				t, err := s.target(r)
				if errors.Is(err, netinfo.ErrNoLocal) && (path == "/api/meta" || path == "/api/fleet") {
					return fn(r, target{}) // 这两个接口不需要本机
				}
				if err != nil {
					return nil, err
				}
				return fn(r, t)
			}, r)
		})
	}
	// 运行方式：界面据此决定有没有「本机」、要不要登录（服务器版由 internal/server 接管这个接口）。
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		reply(w, func(*http.Request) (any, error) {
			mode := s.Mode
			if mode == "" {
				mode = "desktop"
			}
			return map[string]any{"mode": mode, "local": !s.NoLocal, "version": s.Version, "canWrite": true}, nil
		}, r)
	})
	get("/api/fleet", func(_ *http.Request, _ target) (any, error) { return s.fleet() })
	get("/api/meta", func(_ *http.Request, t target) (any, error) {
		if t.host == nil {
			host, _ := os.Hostname()
			if t.sys == nil { // 不采集本机
				return map[string]any{"version": s.Version, "hostname": host, "priv": "none", "remote": false, "local": false}, nil
			}
			return map[string]any{"version": s.Version, "hostname": host, "priv": s.Priv.Status(), "remote": false}, nil
		}
		cfg := t.host.Config()
		m := map[string]any{"version": s.Version, "remote": true, "host": cfg.ID, "name": cfg.Name}
		info, err := t.host.Connect()
		if err != nil {
			m["priv"], m["error"], m["hostname"] = "none", err.Error(), cfg.Addr
			return m, nil
		}
		m["hostname"], m["kernel"], m["rootErr"] = info.Hostname, info.Kernel, info.RootErr
		switch info.Root {
		case remote.RootLogin:
			m["priv"] = "root"
		case remote.RootSudo, remote.RootSudoPass:
			m["priv"] = "sudo"
		default:
			m["priv"] = "none"
		}
		return m, nil
	})
	get("/api/links", func(_ *http.Request, t target) (any, error) { return netinfo.LinksOn(t.sys) })
	get("/api/stats", func(_ *http.Request, t target) (any, error) { return netinfo.StatsOn(t.sys) })
	get("/api/routing", func(_ *http.Request, t target) (any, error) { return netinfo.RoutingOn(t.sys) })
	get("/api/routeget", func(r *http.Request, t target) (any, error) {
		return netinfo.RouteGetOn(t.sys, r.URL.Query().Get("dst"))
	})
	get("/api/sockets", func(_ *http.Request, t target) (any, error) { return s.sockets(t) })
	get("/api/apps", func(_ *http.Request, t target) (any, error) { return s.tracker(t).Snapshot() })
	get("/api/firewall", func(_ *http.Request, t target) (any, error) {
		return netinfo.CollectFirewallOn(t.sys, t.runPriv), nil
	})
	get("/api/proxy", func(_ *http.Request, t target) (any, error) {
		links, err := netinfo.LinksOn(t.sys)
		if err != nil {
			return nil, err
		}
		routing, _ := netinfo.RoutingOn(t.sys)
		socks, _ := s.sockets(t)
		return netinfo.CollectProxyOn(t.sys, links, routing, socks), nil
	})
	mux.HandleFunc("POST /api/elevate", func(w http.ResponseWriter, r *http.Request) {
		// 自定义请求头让跨站页面无法在不经预检的情况下触发授权弹窗；serve 模式下还要求同一用户。
		if r.Header.Get("X-Nfmonitor") == "" || (s.CheckHost && !s.sameUser(r)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		reply(w, func(r *http.Request) (any, error) {
			if id := r.URL.Query().Get("host"); id != "" && id != "local" {
				return nil, errors.New("远程主机的 root 权限取决于登录用户：请用 root 登录，或为该用户配置 sudo")
			}
			if s.NoLocal {
				return nil, netinfo.ErrNoLocal
			}
			if err := s.Priv.Elevate(); err != nil {
				return nil, err
			}
			return map[string]any{"priv": s.Priv.Status()}, nil
		}, r)
	})
	// post 注册一个修改类接口：跨站防护 + 同一用户 + JSON 请求体。
	post := func(path string, fn func(r *http.Request, dec *json.Decoder) (any, error)) {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			if !s.sameOrigin(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			reply(w, func(r *http.Request) (any, error) {
				return fn(r, json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)))
			}, r)
		})
	}
	// ufw 修改：preview 只生成命令（远程主机还会给出防失联警告）；apply 真正执行。
	ufw := func(path string, apply bool) {
		post(path, func(r *http.Request, dec *json.Decoder) (any, error) {
			var op netinfo.UfwOp
			if err := dec.Decode(&op); err != nil {
				return nil, err
			}
			t, err := s.target(r)
			if err != nil {
				return nil, err
			}
			if t.host != nil {
				return s.remoteUfw(t.host, op, apply)
			}
			if s.NoLocal {
				return nil, netinfo.ErrNoLocal
			}
			if apply {
				return s.Priv.ApplyUfw(op)
			}
			var cur []netinfo.UfwRule
			if out, err := s.Priv.Run("ufw-tuples"); err == nil {
				_, _, ipv6, _ := netinfo.ReadUfwConfig()
				cur = netinfo.ParseUfwTuples(out, ipv6)
			}
			cmds, err := netinfo.BuildUfw(op, cur, false)
			if err != nil {
				return nil, err
			}
			return netinfo.UfwResult{Commands: cmds}, nil
		})
	}
	ufw("/api/ufw/preview", false)
	ufw("/api/ufw/apply", true)
	// firewalld 修改：同上。
	fwd := func(path string, apply bool) {
		post(path, func(r *http.Request, dec *json.Decoder) (any, error) {
			var op netinfo.FirewalldOp
			if err := dec.Decode(&op); err != nil {
				return nil, err
			}
			t, err := s.target(r)
			if err != nil {
				return nil, err
			}
			if t.host != nil {
				return s.remoteFirewalld(t.host, op, apply)
			}
			if s.NoLocal {
				return nil, netinfo.ErrNoLocal
			}
			if apply {
				return s.Priv.ApplyFirewalld(op)
			}
			cmds, err := netinfo.BuildFirewalld(op, netinfo.CollectFirewalld(netinfo.Local, s.Priv.Run))
			if err != nil {
				return nil, err
			}
			return netinfo.FirewalldResult{Commands: cmds}, nil
		})
	}
	fwd("/api/firewalld/preview", false)
	fwd("/api/firewalld/apply", true)
	s.hostRoutes(mux, post)

	var h http.Handler = mux
	if os.Getenv("NFMONITOR_DEBUG") != "" { // 排查用：把每个接口请求打到 stderr（不含请求体）
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s %s", r.Method, r.URL.RequestURI())
			mux.ServeHTTP(w, r)
		})
	}
	if !s.CheckHost {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		// 远程主机的数据是用本用户保存的凭据取来的：本机其他用户不能借 serve 端口读。
		if (r.URL.Query().Get("host") != "" || strings.HasPrefix(r.URL.Path, "/api/hosts")) && !s.sameUser(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// remoteUfw 在远程主机上预览 / 执行 ufw 修改。预览时一并给出防失联警告。
func (s *Server) remoteUfw(h *remote.Host, op netinfo.UfwOp, apply bool) (any, error) {
	path := h.SSHPath()
	if apply {
		return netinfo.ApplyUfwOn(h, op, path)
	}
	raw, err := h.RunPriv("ufw-tuples")
	if err != nil {
		return nil, err
	}
	defaults, _, ipv6, enabled := netinfo.ReadUfwConfigOn(h)
	cur := netinfo.ParseUfwTuples(raw, ipv6)
	cmds, err := netinfo.BuildUfw(op, cur, false)
	if err != nil {
		return nil, err
	}
	res := netinfo.UfwResult{Commands: cmds}
	if path != nil {
		status := enabled
		if out, err := h.RunPriv("ufw"); err == nil {
			if st := netinfo.ParseUfwStatus(out); st != "" {
				status = st
			}
		}
		res.Warning = netinfo.UfwLockout(op, cur, defaults, status, *path)
	}
	return res, nil
}

// remoteFirewalld 在远程主机上预览 / 执行 firewalld 修改。
func (s *Server) remoteFirewalld(h *remote.Host, op netinfo.FirewalldOp, apply bool) (any, error) {
	path := h.SSHPath()
	if apply {
		return netinfo.ApplyFirewalldOn(h, op, path)
	}
	info := netinfo.CollectFirewalld(h, h.RunPriv)
	if info.Error != "" {
		return nil, errors.New(info.Error)
	}
	cmds, err := netinfo.BuildFirewalld(op, info)
	if err != nil {
		return nil, err
	}
	res := netinfo.FirewalldResult{Commands: cmds}
	if path != nil {
		res.Warning = netinfo.FirewalldLockout(op, info, *path)
	}
	return res, nil
}

var osHostname = os.Hostname

func (s *Server) sameUser(r *http.Request) bool {
	uid, err := peerUID(r.RemoteAddr)
	return err == nil && uid == os.Getuid()
}

// sameOrigin 挡跨站请求：必须带自定义头（跨站页面要先过 CORS 预检，而这里不响应预检）、
// 内容是 JSON；serve 模式下带了 Origin 时还必须与 Host 一致（桌面版资源服务器外部访问不到，
// 且 WebView 的 Origin 是 wails:// 之类，不做这项比对）。
func (s *Server) sameOrigin(r *http.Request) bool {
	if r.Header.Get("X-Nfmonitor") == "" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return false
	}
	// serve 模式：回环地址上本机任何用户都连得到，修改类请求只接受与本程序同一用户的连接。
	if s.CheckHost {
		if !s.sameUser(r) {
			return false
		}
	}
	if o := r.Header.Get("Origin"); o != "" && s.CheckHost {
		u, err := url.Parse(o)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	return true
}

// sockets 采集套接字：有 root（本机已授权 / 远程 root 或 sudo）时用 root 跑 ss，能看到所有进程。
func (s *Server) sockets(t target) ([]netinfo.Socket, error) {
	var socks []netinfo.Socket
	var privOK bool
	if t.host == nil {
		privOK = s.Priv.Status() != "none"
	} else {
		privOK = t.host.RootMode() != remote.RootNone
	}
	if privOK {
		if out, err := t.runPriv("ss"); err == nil {
			socks = netinfo.ParseSs(out)
		}
	}
	if socks == nil {
		var err error
		if socks, err = netinfo.SocketsOn(t.sys); err != nil {
			return nil, err
		}
	}
	netinfo.EnrichSocketsOn(t.sys, socks)
	return socks, nil
}

// udpStat 取 UDP 流量增量；探针要 root，没授权时返回 ErrNotElevated。
func (s *Server) udpStat() (netinfo.UDPStat, error) {
	out, err := s.Priv.Run("udpstat")
	if err != nil {
		return netinfo.UDPStat{}, err
	}
	return netinfo.ParseUDPStat(out), nil
}

func reply(w http.ResponseWriter, fn func(r *http.Request) (any, error), r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	v, err := fn(r)
	if err != nil {
		body := map[string]any{"error": strings.TrimSpace(err.Error())}
		status := http.StatusInternalServerError
		if errors.Is(err, netinfo.ErrLockout) {
			// 防失联拦截：界面据此弹出二次确认，带 confirm 重发。
			status, body["lockout"] = http.StatusConflict, true
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
		return
	}
	json.NewEncoder(w).Encode(v)
}
