// Package api 把采集结果暴露成 JSON 接口。桌面版（Wails 资源服务器）和
// 浏览器版（serve 子命令）共用同一个 handler。
package api

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
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
	s.apps = &netinfo.AppTracker{Sample: s.sockets}
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
		// 自定义请求头让跨站页面无法在不经预检的情况下触发授权弹窗。
		if r.Header.Get("X-Nfmonitor") == "" {
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
