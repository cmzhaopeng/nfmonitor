package api

import (
	"encoding/json"
	"net/http"

	"nfmonitor/internal/remote"
)

// hostForm 是界面提交的主机配置：普通字段 + 本次要修改的机密。
type hostForm struct {
	remote.HostConfig
	Secrets remote.Secrets `json:"secrets"`
}

// hostRoutes 注册远程主机管理接口。修改类接口都走 post（跨站防护、同一用户、JSON）。
//
//	GET  /api/hosts          主机列表与连接状态（不含任何机密）
//	POST /api/hosts/probe    {addr, port} → 主机公钥指纹，供首次连接时确认
//	POST /api/hosts/test     {主机配置, secrets} → 试连并探测 root 权限，不保存
//	POST /api/hosts/save     {主机配置, secrets} → 保存（id 为空 = 新增）
//	POST /api/hosts/connect  {id} → 立即（重新）连接
//	POST /api/hosts/disconnect {id} → 断开，之后不自动重连
//	POST /api/hosts/delete   {id}
func (s *Server) hostRoutes(mux *http.ServeMux, post func(string, func(*http.Request, *json.Decoder) (any, error))) {
	mux.HandleFunc("GET /api/hosts", func(w http.ResponseWriter, r *http.Request) {
		reply(w, func(*http.Request) (any, error) {
			if s.Hosts == nil {
				return map[string]any{"hosts": []any{}, "error": s.hostsUnavailable().Error()}, nil
			}
			return map[string]any{"hosts": s.Hosts.List()}, nil
		}, r)
	})
	withHosts := func(path string, fn func(*json.Decoder) (any, error)) {
		post(path, func(_ *http.Request, dec *json.Decoder) (any, error) {
			if s.Hosts == nil {
				return nil, s.hostsUnavailable()
			}
			return fn(dec)
		})
	}
	withHosts("/api/hosts/probe", func(dec *json.Decoder) (any, error) {
		var req struct {
			Addr string `json:"addr"`
			Port int    `json:"port"`
		}
		if err := dec.Decode(&req); err != nil {
			return nil, err
		}
		cfg := remote.HostConfig{Addr: req.Addr, Port: req.Port, User: "probe", Auth: remote.AuthPassword, Password: "x"}
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		return remote.ProbeHostKey(cfg.Addr, cfg.Port)
	})
	withHosts("/api/hosts/test", func(dec *json.Decoder) (any, error) {
		var f hostForm
		if err := dec.Decode(&f); err != nil {
			return nil, err
		}
		return s.Hosts.Test(f.HostConfig, f.Secrets)
	})
	withHosts("/api/hosts/save", func(dec *json.Decoder) (any, error) {
		var f hostForm
		if err := dec.Decode(&f); err != nil {
			return nil, err
		}
		return s.Hosts.Save(f.HostConfig, f.Secrets)
	})
	withHosts("/api/hosts/connect", func(dec *json.Decoder) (any, error) {
		var req struct {
			ID string `json:"id"`
		}
		if err := dec.Decode(&req); err != nil {
			return nil, err
		}
		return s.Hosts.Connect(req.ID)
	})
	withHosts("/api/hosts/disconnect", func(dec *json.Decoder) (any, error) {
		var req struct {
			ID string `json:"id"`
		}
		if err := dec.Decode(&req); err != nil {
			return nil, err
		}
		return s.Hosts.Disconnect(req.ID)
	})
	withHosts("/api/hosts/delete", func(dec *json.Decoder) (any, error) {
		var req struct {
			ID string `json:"id"`
		}
		if err := dec.Decode(&req); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.Hosts.Delete(req.ID)
	})
}
