// Package api 把采集结果暴露成 JSON 接口。桌面版（Wails 资源服务器）和
// 浏览器版（serve 子命令）共用同一个 handler。
package api

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"nfmonitor/internal/netinfo"
	"nfmonitor/internal/priv"
)

type Server struct {
	Priv    *priv.Client
	Version string
	// CheckHost 为真时只接受 Host 为本机回环的请求（防 DNS rebinding），用于 serve 模式。
	CheckHost bool

	apps *netinfo.AppTracker
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.apps = &netinfo.AppTracker{Sample: s.sockets, UDP: s.udpStat}
	get := func(path string, fn func(r *http.Request) (any, error)) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) { reply(w, fn, r) })
	}
	get("/api/meta", func(*http.Request) (any, error) {
		host, _ := os.Hostname()
		return map[string]any{"version": s.Version, "hostname": host, "priv": s.Priv.Status()}, nil
	})
	get("/api/links", func(*http.Request) (any, error) { return netinfo.Links() })
	get("/api/stats", func(*http.Request) (any, error) { return netinfo.Stats() })
	get("/api/routing", func(*http.Request) (any, error) { return netinfo.RoutingInfo() })
	get("/api/routeget", func(r *http.Request) (any, error) { return netinfo.RouteGet(r.URL.Query().Get("dst")) })
	get("/api/sockets", func(*http.Request) (any, error) { return s.sockets() })
	get("/api/apps", func(*http.Request) (any, error) { return s.apps.Snapshot() })
	get("/api/firewall", func(*http.Request) (any, error) { return netinfo.CollectFirewall(s.Priv.Run), nil })
	get("/api/proxy", func(*http.Request) (any, error) {
		links, err := netinfo.Links()
		if err != nil {
			return nil, err
		}
		routing, _ := netinfo.RoutingInfo()
		socks, _ := s.sockets()
		return netinfo.CollectProxy(links, routing, socks), nil
	})
	mux.HandleFunc("POST /api/elevate", func(w http.ResponseWriter, r *http.Request) {
		// 自定义请求头让跨站页面无法在不经预检的情况下触发授权弹窗；serve 模式下还要求同一用户。
		if r.Header.Get("X-Nfmonitor") == "" || (s.CheckHost && !s.sameUser(r)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		reply(w, func(*http.Request) (any, error) {
			if err := s.Priv.Elevate(); err != nil {
				return nil, err
			}
			return map[string]any{"priv": s.Priv.Status()}, nil
		}, r)
	})
	// ufw 修改：preview 只生成命令；apply 会弹系统授权框并真正执行。
	ufw := func(path string, apply bool) {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			if !s.sameOrigin(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			reply(w, func(r *http.Request) (any, error) {
				var op netinfo.UfwOp
				if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&op); err != nil {
					return nil, err
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
			}, r)
		})
	}
	ufw("/api/ufw/preview", false)
	ufw("/api/ufw/apply", true)
	var h http.Handler = mux
	if os.Getenv("NFMONITOR_DEBUG") != "" { // 排查用：把每个接口请求打到 stderr
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
		h.ServeHTTP(w, r)
	})
}

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

func (s *Server) sockets() ([]netinfo.Socket, error) {
	var socks []netinfo.Socket
	if s.Priv.Status() != "none" {
		if out, err := s.Priv.Run("ss"); err == nil {
			socks = netinfo.ParseSs(out)
		}
	}
	if socks == nil {
		var err error
		if socks, err = netinfo.Sockets(); err != nil {
			return nil, err
		}
	}
	netinfo.EnrichSockets(socks)
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
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": strings.TrimSpace(err.Error())})
		return
	}
	json.NewEncoder(w).Encode(v)
}
